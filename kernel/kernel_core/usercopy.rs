//! Fault-tolerant user-space memory copy
//!
//! This module provides safe copy operations between kernel and user space
//! that can recover from page faults (TOCTOU protection).
//!
//! # Design
//!
//! Uses a per-CPU state to track when a user copy is in progress.
//! If a page fault occurs during a user copy:
//! 1. The page_fault_handler detects the active copy via `is_in_usercopy()`
//! 2. Verifies the fault address is within the expected buffer range
//! 3. Sets the fault flag via `set_usercopy_fault()`
//! 4. The page_fault_handler terminates the process (cannot recover RIP)
//!
//! Note: Due to x86 variable-length instructions, we cannot simply advance
//! RIP to skip the faulting instruction. Instead, the process is terminated
//! gracefully with EFAULT semantics.
//!
//! # SMAP Guard Nesting (S-5 fix)
//!
//! UserAccessGuard supports nesting via a depth counter. Only the outermost
//! guard executes STAC/CLAC, preventing premature SMAP re-enablement when
//! guards are nested (e.g., copy_user_str_array calling copy_user_cstring).
//!
//! # PID Binding (H-36 fix)
//!
//! Usercopy state is bound to the owning process PID to prevent cross-process
//! false positive fault detection in future SMP scenarios.
//!
//! # Per-CPU State (V-5 fix)
//!
//! Both usercopy state and SMAP guard depth are now per-CPU via CpuLocal<T>.
//! This ensures correct behavior in SMP environments where multiple CPUs may
//! be performing user copies concurrently.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use cpu_local::{current_cpu_id, CpuLocal};
use x86_64::registers::control::{Cr4, Cr4Flags};

/// User-copy state with PID binding for SMP safety (V-5 fix)
///
/// Each CPU maintains its own copy state via CpuLocal<T>, ensuring that
/// concurrent user copies on different CPUs do not interfere with each other.
struct UserCopyState {
    /// True if currently executing a user copy operation
    active: AtomicBool,
    /// PID that owns the active user copy (0 = none/kernel)
    pid: AtomicUsize,
    /// True if a page fault occurred during the copy
    faulted: AtomicBool,
    /// Number of bytes remaining to copy (for progress tracking)
    remaining: AtomicUsize,
    /// Inclusive start address of the current user buffer
    start: AtomicUsize,
    /// Exclusive end address of the current user buffer
    end: AtomicUsize,
}

impl UserCopyState {
    /// Create a new zeroed UserCopyState
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            pid: AtomicUsize::new(0),
            faulted: AtomicBool::new(false),
            remaining: AtomicUsize::new(0),
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
        }
    }
}

/// Per-CPU user copy state (V-5 fix)
///
/// Each CPU has its own UserCopyState, ensuring SMP-safe operation.
static USER_COPY_STATE: CpuLocal<UserCopyState> = CpuLocal::new(UserCopyState::new);

/// Per-CPU SMAP guard nesting depth counter (S-5 + V-5 fix)
///
/// Tracks how many UserAccessGuard instances are currently active on this CPU.
/// STAC is only executed when depth transitions 0→1.
/// CLAC is only executed when depth transitions 1→0.
///
/// Per-CPU storage ensures correct nesting behavior in SMP environments.
static SMAP_GUARD_DEPTH: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));

/// Helper to get current process PID (0 if none)
#[inline]
fn current_pid_raw() -> usize {
    crate::process::current_pid().unwrap_or(0)
}

/// RAII guard to temporarily lift SMAP for intentional user memory access
///
/// When SMAP (Supervisor Mode Access Prevention) is enabled, the kernel cannot
/// directly read/write user memory. This guard uses STAC (Set AC flag) to
/// temporarily allow kernel access to user pages, and CLAC (Clear AC flag)
/// on drop to restore protection.
///
/// # Nesting Support (S-5 fix)
///
/// This guard supports nesting: only the outermost guard executes STAC/CLAC.
/// Nested guards simply increment/decrement a depth counter without affecting
/// the AC flag. This prevents the bug where nested guard drops would clear AC
/// prematurely (e.g., when `copy_user_str_array` calls `copy_user_cstring`).
///
/// # Safety
///
/// This guard should only be used around intentional user memory accesses
/// in controlled contexts (e.g., copy_from_user, copy_to_user).
#[must_use]
pub struct UserAccessGuard {
    /// Whether SMAP was active when the guard was created
    smap_active: bool,
    /// CPU this guard was created on (per-CPU depth must be balanced on same CPU)
    cpu_id: usize,
}

impl UserAccessGuard {
    /// Create a new guard that temporarily disables SMAP if active
    ///
    /// # Nesting Behavior
    ///
    /// - First guard (depth 0→1): Executes STAC to disable SMAP
    /// - Nested guards (depth >1): Only increments counter, no STAC
    #[inline]
    pub fn new() -> Self {
        let cpu_id = current_cpu_id();
        let smap_active = Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);

        if smap_active {
            // Only execute STAC when this is the outermost guard (depth 0→1)
            // V-5 fix: Use per-CPU depth counter
            let prev_depth = SMAP_GUARD_DEPTH.with(|d| d.fetch_add(1, Ordering::SeqCst));
            if prev_depth == 0 {
                // Set AC flag to allow supervisor access to user pages
                unsafe {
                    core::arch::asm!("stac", options(nostack, nomem));
                }
            }
        }

        UserAccessGuard {
            smap_active,
            cpu_id,
        }
    }
}

impl Default for UserAccessGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UserAccessGuard {
    /// Drop the guard, restoring SMAP protection if this is the outermost guard
    ///
    /// # Nesting Behavior
    ///
    /// - Outermost guard (depth 1→0): Executes CLAC to re-enable SMAP
    /// - Inner guards (depth >1): Only decrements counter, no CLAC
    #[inline]
    fn drop(&mut self) {
        // Detect CPU migration which would cause per-CPU depth imbalance
        // Use assert (not debug_assert) to catch this in release builds
        assert_eq!(
            current_cpu_id(),
            self.cpu_id,
            "UserAccessGuard dropped on different CPU; per-CPU SMAP depth would be imbalanced"
        );

        if self.smap_active {
            // Only execute CLAC when this is the outermost guard (depth 1→0)
            // V-5 fix: Use per-CPU depth counter
            let prev_depth = SMAP_GUARD_DEPTH.with(|d| d.fetch_sub(1, Ordering::SeqCst));
            // Check for underflow (should never happen with correct nesting)
            assert!(prev_depth > 0, "SMAP guard depth underflow");
            if prev_depth == 1 {
                // Clear AC flag to restore SMAP protection
                unsafe {
                    core::arch::asm!("clac", options(nostack, nomem));
                }
            }
        }
    }
}

/// Check if a user copy is currently in progress for the current process
///
/// # PID Binding (H-36 fix)
///
/// Returns true only if:
/// 1. A usercopy is active, AND
/// 2. The active usercopy belongs to the current process
///
/// This prevents false positive fault detection in SMP scenarios where
/// one CPU might fault while another CPU is doing a usercopy.
///
/// # V-5 fix
///
/// Now uses per-CPU state, so each CPU only checks its own usercopy status.
#[inline]
pub fn is_in_usercopy() -> bool {
    let pid = current_pid_raw();
    USER_COPY_STATE.with(|s| s.active.load(Ordering::SeqCst) && s.pid.load(Ordering::SeqCst) == pid)
}

/// Set the fault flag (called from page_fault_handler)
#[inline]
pub fn set_usercopy_fault() {
    USER_COPY_STATE.with(|s| s.faulted.store(true, Ordering::SeqCst));
}

/// Check if a fault occurred and clear the flag
#[inline]
fn check_and_clear_fault() -> bool {
    USER_COPY_STATE.with(|s| s.faulted.swap(false, Ordering::SeqCst))
}

/// RAII guard for user copy state with PID binding
struct UserCopyGuard {
    /// CPU this guard was created on (per-CPU state must be cleared on same CPU)
    cpu_id: usize,
}

impl UserCopyGuard {
    /// Create a new UserCopyGuard, registering the current copy operation
    ///
    /// # PID Binding
    ///
    /// Stores the current process PID to associate the copy with its owner.
    ///
    /// # V-5 fix
    ///
    /// Uses per-CPU state for SMP safety.
    #[inline]
    fn new(buffer_start: usize, len: usize) -> Self {
        let cpu_id = current_cpu_id();
        USER_COPY_STATE.with(|s| {
            s.faulted.store(false, Ordering::SeqCst);
            s.pid.store(current_pid_raw(), Ordering::SeqCst);
            s.start.store(buffer_start, Ordering::SeqCst);
            s.end
                .store(buffer_start.saturating_add(len), Ordering::SeqCst);
            s.active.store(true, Ordering::SeqCst);
        });
        UserCopyGuard { cpu_id }
    }
}

impl Drop for UserCopyGuard {
    #[inline]
    fn drop(&mut self) {
        // Detect CPU migration which would leave stale state on old CPU
        // Use assert (not debug_assert) to catch this in release builds
        assert_eq!(
            current_cpu_id(),
            self.cpu_id,
            "UserCopyGuard dropped on different CPU; per-CPU usercopy state would be stale"
        );

        USER_COPY_STATE.with(|s| {
            s.active.store(false, Ordering::SeqCst);
            s.pid.store(0, Ordering::SeqCst);
            s.start.store(0, Ordering::SeqCst);
            s.end.store(0, Ordering::SeqCst);
        });
    }
}

/// User space address boundary
const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

/// Validate that an address range is in user space
#[inline]
fn validate_user_range(ptr: usize, len: usize) -> bool {
    if ptr == 0 || len == 0 {
        return false;
    }
    match ptr.checked_add(len) {
        Some(end) => end < USER_SPACE_TOP, // Strict less-than
        None => false,
    }
}

/// Fault-tolerant copy from user space to kernel buffer
///
/// This function handles page faults gracefully by returning EFAULT
/// instead of panicking. It copies one byte at a time to ensure
/// we can detect faults at any point.
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space pointer
///
/// # Returns
/// * `Ok(())` - Copy succeeded
/// * `Err(())` - Page fault occurred (EFAULT)
///
/// # Safety
/// The caller must ensure `dst` is a valid kernel buffer.
pub fn copy_from_user_safe(dst: &mut [u8], src: *const u8) -> Result<(), ()> {
    let len = dst.len();
    if len == 0 {
        return Ok(());
    }

    // Validate user pointer range
    if !validate_user_range(src as usize, len) {
        return Err(());
    }

    // Allow supervisor access to user pages when SMAP is enabled
    let _smap_guard = UserAccessGuard::new();

    // Set up the copy state with buffer range tracking
    let _guard = UserCopyGuard::new(src as usize, len);
    USER_COPY_STATE.with(|s| s.remaining.store(len, Ordering::SeqCst));

    // Copy byte by byte to detect faults at each step
    // This is slower but guarantees we can catch faults
    for i in 0..len {
        // Check if a fault occurred in a previous iteration
        // (This handles the case where the fault handler returned)
        if check_and_clear_fault() {
            return Err(());
        }

        // Read one byte from user space
        // If this faults, the handler will set the fault flag
        let byte = unsafe {
            // Use volatile read to prevent optimization
            core::ptr::read_volatile(src.add(i))
        };

        // Check again after the read
        if check_and_clear_fault() {
            return Err(());
        }

        dst[i] = byte;
        USER_COPY_STATE.with(|s| s.remaining.store(len - i - 1, Ordering::SeqCst));
    }

    Ok(())
}

/// Fault-tolerant copy from kernel buffer to user space
///
/// # Arguments
/// * `dst` - Destination user space pointer
/// * `src` - Source kernel buffer
///
/// # Returns
/// * `Ok(())` - Copy succeeded
/// * `Err(())` - Page fault occurred (EFAULT)
pub fn copy_to_user_safe(dst: *mut u8, src: &[u8]) -> Result<(), ()> {
    let len = src.len();
    if len == 0 {
        return Ok(());
    }

    // Validate user pointer range
    if !validate_user_range(dst as usize, len) {
        return Err(());
    }

    // Allow supervisor access to user pages when SMAP is enabled
    let _smap_guard = UserAccessGuard::new();

    // Set up the copy state with buffer range tracking
    let _guard = UserCopyGuard::new(dst as usize, len);
    USER_COPY_STATE.with(|s| s.remaining.store(len, Ordering::SeqCst));

    // Copy byte by byte
    for i in 0..len {
        if check_and_clear_fault() {
            return Err(());
        }

        // Write one byte to user space
        unsafe {
            core::ptr::write_volatile(dst.add(i), src[i]);
        }

        if check_and_clear_fault() {
            return Err(());
        }

        USER_COPY_STATE.with(|s| s.remaining.store(len - i - 1, Ordering::SeqCst));
    }

    Ok(())
}

/// Try to handle a page fault that occurred during user copy
///
/// This should be called AFTER COW handling in the page_fault_handler.
///
/// # Arguments
/// * `fault_addr` - The address that caused the fault
///
/// # Returns
/// * `true` - Fault was in usercopy range; process should be terminated
/// * `false` - Not a user copy fault, handle normally
///
/// # PID Binding (H-36 fix)
///
/// Only returns true if the faulting process owns the active usercopy.
/// This prevents incorrect fault attribution in SMP scenarios.
///
/// # V-5 fix
///
/// Uses per-CPU state, ensuring each CPU checks only its own usercopy status.
///
/// # Important
///
/// Since x86 has variable-length instructions and we cannot easily determine
/// the instruction length to advance RIP, when this function returns true,
/// the page_fault_handler should terminate the current process gracefully
/// (returning EFAULT semantics to the caller).
pub fn try_handle_usercopy_fault(fault_addr: usize) -> bool {
    // Only handle if we're in a user copy for the current process
    // is_in_usercopy() already checks PID binding (H-36 fix)
    if !is_in_usercopy() {
        return false;
    }

    // Double-check PID for defense-in-depth (SMP safety)
    let current = current_pid_raw();
    let owner = USER_COPY_STATE.with(|s| s.pid.load(Ordering::SeqCst));
    if current != owner {
        return false;
    }

    // Only handle user-space addresses
    if fault_addr >= USER_SPACE_TOP {
        return false;
    }

    // Ensure the fault belongs to the active buffer range to avoid
    // swallowing unrelated user faults
    let (start, end) =
        USER_COPY_STATE.with(|s| (s.start.load(Ordering::SeqCst), s.end.load(Ordering::SeqCst)));
    if start == 0 || fault_addr < start || fault_addr >= end {
        return false;
    }

    // Set the fault flag (for completeness, though we'll terminate)
    set_usercopy_fault();

    // Return true to indicate this is a usercopy fault
    // The page_fault_handler should terminate the process gracefully
    true
}

/// Maximum length for user-space C strings (paths, arguments)
pub const MAX_CSTRING_LEN: usize = 4096;

/// Fault-tolerant copy of a NUL-terminated string from user space
///
/// Copies bytes from user space until a NUL terminator is found or
/// MAX_CSTRING_LEN is reached. Returns the string bytes WITHOUT the NUL.
///
/// # Arguments
/// * `src` - Source user space pointer to NUL-terminated string
///
/// # Returns
/// * `Ok(Vec<u8>)` - String bytes (not including NUL terminator)
/// * `Err(())` - Page fault occurred, null pointer, or string too long
///
/// # Security (Z-3 fix)
///
/// This function uses fault-tolerant byte-by-byte copy to safely handle:
/// - Unmapped user memory (returns EFAULT instead of kernel panic)
/// - TOCTOU attacks where memory is unmapped during copy
/// - Overly long strings (bounded by MAX_CSTRING_LEN)
pub fn copy_user_cstring(src: *const u8) -> Result<alloc::vec::Vec<u8>, ()> {
    use alloc::vec::Vec;

    if src.is_null() {
        return Err(());
    }

    // Validate that starting address is in user space
    let start_addr = src as usize;
    if start_addr >= USER_SPACE_TOP {
        return Err(());
    }

    // Allow supervisor access to user pages when SMAP is enabled
    let _smap_guard = UserAccessGuard::new();

    // Set up the copy state - we don't know exact length, use max
    let _guard = UserCopyGuard::new(start_addr, MAX_CSTRING_LEN);

    let mut result = Vec::with_capacity(256); // Typical path length

    for i in 0..MAX_CSTRING_LEN {
        // Check if a fault occurred in previous iteration
        if check_and_clear_fault() {
            return Err(());
        }

        // Validate each byte address is still in user space
        let byte_addr = match start_addr.checked_add(i) {
            Some(addr) if addr < USER_SPACE_TOP => addr,
            _ => return Err(()),
        };

        // Read one byte from user space
        let byte = unsafe { core::ptr::read_volatile(byte_addr as *const u8) };

        // Check for fault after read
        if check_and_clear_fault() {
            return Err(());
        }

        // NUL terminator found - done
        if byte == 0 {
            return Ok(result);
        }

        result.push(byte);
    }

    // String too long (no NUL found within MAX_CSTRING_LEN)
    Err(())
}
