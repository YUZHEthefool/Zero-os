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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// User-copy state (single-core for now)
///
/// TODO: Make per-CPU for SMP support
struct UserCopyState {
    /// True if currently executing a user copy operation
    active: AtomicBool,
    /// True if a page fault occurred during the copy
    faulted: AtomicBool,
    /// Number of bytes remaining to copy (for progress tracking)
    remaining: AtomicUsize,
    /// Inclusive start address of the current user buffer
    start: AtomicUsize,
    /// Exclusive end address of the current user buffer
    end: AtomicUsize,
}

static USER_COPY_STATE: UserCopyState = UserCopyState {
    active: AtomicBool::new(false),
    faulted: AtomicBool::new(false),
    remaining: AtomicUsize::new(0),
    start: AtomicUsize::new(0),
    end: AtomicUsize::new(0),
};

/// Check if a user copy is currently in progress
#[inline]
pub fn is_in_usercopy() -> bool {
    USER_COPY_STATE.active.load(Ordering::SeqCst)
}

/// Set the fault flag (called from page_fault_handler)
#[inline]
pub fn set_usercopy_fault() {
    USER_COPY_STATE.faulted.store(true, Ordering::SeqCst);
}

/// Check if a fault occurred and clear the flag
#[inline]
fn check_and_clear_fault() -> bool {
    USER_COPY_STATE.faulted.swap(false, Ordering::SeqCst)
}

/// RAII guard for user copy state
struct UserCopyGuard;

impl UserCopyGuard {
    #[inline]
    fn new(buffer_start: usize, len: usize) -> Self {
        USER_COPY_STATE.faulted.store(false, Ordering::SeqCst);
        USER_COPY_STATE.start.store(buffer_start, Ordering::SeqCst);
        USER_COPY_STATE
            .end
            .store(buffer_start.saturating_add(len), Ordering::SeqCst);
        USER_COPY_STATE.active.store(true, Ordering::SeqCst);
        UserCopyGuard
    }
}

impl Drop for UserCopyGuard {
    #[inline]
    fn drop(&mut self) {
        USER_COPY_STATE.active.store(false, Ordering::SeqCst);
        USER_COPY_STATE.start.store(0, Ordering::SeqCst);
        USER_COPY_STATE.end.store(0, Ordering::SeqCst);
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

    // Set up the copy state with buffer range tracking
    let _guard = UserCopyGuard::new(src as usize, len);
    USER_COPY_STATE.remaining.store(len, Ordering::SeqCst);

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
        USER_COPY_STATE.remaining.store(len - i - 1, Ordering::SeqCst);
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

    // Set up the copy state with buffer range tracking
    let _guard = UserCopyGuard::new(dst as usize, len);
    USER_COPY_STATE.remaining.store(len, Ordering::SeqCst);

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

        USER_COPY_STATE.remaining.store(len - i - 1, Ordering::SeqCst);
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
/// # Important
///
/// Since x86 has variable-length instructions and we cannot easily determine
/// the instruction length to advance RIP, when this function returns true,
/// the page_fault_handler should terminate the current process gracefully
/// (returning EFAULT semantics to the caller).
pub fn try_handle_usercopy_fault(fault_addr: usize) -> bool {
    // Only handle if we're in a user copy
    if !is_in_usercopy() {
        return false;
    }

    // Only handle user-space addresses
    if fault_addr >= USER_SPACE_TOP {
        return false;
    }

    // Ensure the fault belongs to the active buffer range to avoid
    // swallowing unrelated user faults
    let start = USER_COPY_STATE.start.load(Ordering::SeqCst);
    let end = USER_COPY_STATE.end.load(Ordering::SeqCst);
    if start == 0 || fault_addr < start || fault_addr >= end {
        return false;
    }

    // Set the fault flag (for completeness, though we'll terminate)
    set_usercopy_fault();

    // Return true to indicate this is a usercopy fault
    // The page_fault_handler should terminate the process gracefully
    true
}
