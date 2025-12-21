//! KASLR/KPTI Infrastructure for Zero-OS
//!
//! This module provides the infrastructure for Kernel Address Space Layout
//! Randomization (KASLR) and Kernel Page Table Isolation (KPTI).
//!
//! # Phase A.4 Preparation
//!
//! This is the preparation phase. Full implementation deferred to later phases:
//! - KASLR slide generation: Phase A.5
//! - Dual page tables: Phase B
//! - CR3 flips in syscall: Phase B
//!
//! # Current Status
//!
//! - KernelLayout: Provides runtime kernel location info (currently fixed)
//! - KPTI stubs: No-op hooks for future CR3 switching
//! - BootInfo extensions: Fields for KASLR (with zero/default values)
//!
//! # Design
//!
//! ```text
//! KASLR (future):
//! +------------------+
//! | Randomized Slide | (boot-time, from RDRAND)
//! +------------------+
//! | Kernel Text      | 0xffffffff80000000 + slide
//! +------------------+
//! | Kernel Data      | Text + text_size + slide
//! +------------------+
//!
//! KPTI (future):
//! User CR3:             Kernel CR3:
//! +------------------+  +------------------+
//! | User mappings    |  | User mappings    |
//! +------------------+  +------------------+
//! | Trampoline only  |  | Full kernel      |
//! +------------------+  +------------------+
//! ```

use core::sync::atomic::{AtomicBool, Ordering};

/// Whether KASLR is enabled (future: set by bootloader)
static KASLR_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether KPTI is enabled (future: set during init)
static KPTI_ENABLED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Kernel Layout
// ============================================================================

/// Current (fixed) kernel virtual base address
pub const KERNEL_VIRT_BASE: u64 = 0xffffffff80000000;

/// Current (fixed) kernel physical base address
pub const KERNEL_PHYS_BASE: u64 = 0x100000;

/// Current (fixed) kernel entry point offset from base
pub const KERNEL_ENTRY_OFFSET: u64 = 0x100000;

/// Current (fixed) physical memory offset for high-half direct mapping
pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xffffffff80000000;

/// Kernel layout information
///
/// This struct provides runtime information about the kernel's location
/// in memory. Currently uses fixed values; will support randomized layout
/// when KASLR is implemented.
///
/// # Section Fields
///
/// The section fields (text_start, rodata_start, etc.) are currently set to
/// placeholder values. They will be populated from linker symbols when
/// KASLR is implemented. Do not rely on these for bounds checking until
/// they are properly initialized.
#[derive(Debug, Clone, Copy)]
pub struct KernelLayout {
    /// Virtual base address of the kernel (high-half mapping)
    pub virt_base: u64,

    /// Physical base address where kernel is loaded
    pub phys_base: u64,

    /// KASLR slide value (0 = no randomization)
    pub kaslr_slide: u64,

    /// Virtual address of kernel text section start
    pub text_start: u64,

    /// Size of kernel text section in bytes
    pub text_size: u64,

    /// Virtual address of kernel rodata section start
    pub rodata_start: u64,

    /// Size of kernel rodata section in bytes
    pub rodata_size: u64,

    /// Virtual address of kernel data section start
    pub data_start: u64,

    /// Size of kernel data section in bytes
    pub data_size: u64,

    /// Virtual address of kernel BSS section start
    pub bss_start: u64,

    /// Size of kernel BSS section in bytes
    pub bss_size: u64,

    /// Virtual address of kernel heap start
    pub heap_start: u64,

    /// Size of kernel heap in bytes
    pub heap_size: u64,

    /// Physical memory offset (for phys-to-virt translation)
    pub phys_offset: u64,
}

impl Default for KernelLayout {
    fn default() -> Self {
        Self::fixed()
    }
}

impl KernelLayout {
    /// Create a kernel layout with fixed (non-randomized) addresses
    ///
    /// This is the current configuration. KASLR support will add
    /// a constructor that accepts a slide value.
    pub const fn fixed() -> Self {
        Self {
            virt_base: KERNEL_VIRT_BASE,
            phys_base: KERNEL_PHYS_BASE,
            kaslr_slide: 0,
            // Section bounds - placeholders until linker symbol integration
            // TODO: Populate from linker symbols (__text_start, __text_end, etc.)
            text_start: KERNEL_VIRT_BASE + KERNEL_ENTRY_OFFSET,
            text_size: 0,  // Unknown until linker symbols integrated
            rodata_start: 0,
            rodata_size: 0,
            data_start: 0,
            data_size: 0,
            bss_start: 0,
            bss_size: 0,
            // Fixed heap address (matches mm::memory.rs)
            heap_start: 0xffffffff80200000,
            heap_size: 1 * 1024 * 1024, // 1 MiB
            phys_offset: PHYSICAL_MEMORY_OFFSET,
        }
    }

    /// Create a kernel layout with KASLR slide (future)
    ///
    /// # Safety
    ///
    /// The slide value must be page-aligned and must not cause the kernel
    /// to overlap with other memory regions.
    #[allow(dead_code)]
    pub const fn with_slide(slide: u64) -> Self {
        Self {
            virt_base: KERNEL_VIRT_BASE + slide,
            phys_base: KERNEL_PHYS_BASE,
            kaslr_slide: slide,
            text_start: KERNEL_VIRT_BASE + KERNEL_ENTRY_OFFSET + slide,
            text_size: 0,
            rodata_start: 0,
            rodata_size: 0,
            data_start: 0,
            data_size: 0,
            bss_start: 0,
            bss_size: 0,
            heap_start: 0xffffffff80200000 + slide,
            heap_size: 1 * 1024 * 1024,
            phys_offset: 0,
        }
    }

    /// Check if this layout has KASLR enabled
    #[inline]
    pub fn has_kaslr(&self) -> bool {
        self.kaslr_slide != 0
    }

    /// Convert a physical address to virtual using this layout's offset
    #[inline]
    pub fn phys_to_virt(&self, phys: u64) -> u64 {
        phys + self.phys_offset
    }

    /// Convert a virtual address to physical (for high-half kernel addresses)
    #[inline]
    pub fn virt_to_phys(&self, virt: u64) -> Option<u64> {
        if virt >= self.virt_base {
            Some(virt - self.virt_base + self.phys_base)
        } else {
            None
        }
    }

    /// Get the kernel's entry point virtual address
    #[inline]
    pub fn entry_point(&self) -> u64 {
        self.text_start
    }
}

// ============================================================================
// KPTI Infrastructure
// ============================================================================

/// Page table context for KPTI
///
/// When KPTI is enabled, each process has two page table roots:
/// - `user_cr3`: Contains user mappings + minimal trampoline
/// - `kernel_cr3`: Contains user mappings + full kernel
///
/// # CR3 Format
///
/// The `user_cr3` and `kernel_cr3` fields contain the physical address of
/// the PML4 page table root. They do NOT include PCID bits - the PCID is
/// stored separately in the `pcid` field. When loading CR3, the caller
/// must combine them appropriately:
///
/// - Without PCID: `mov cr3, [user_cr3 or kernel_cr3]`
/// - With PCID: `mov cr3, [cr3_value | (pcid as u64) | (no_flush_bit)]`
///
/// The `cr3_with_pcid()` method handles this combination.
#[derive(Debug, Clone, Copy)]
pub struct KptiContext {
    /// User-mode page table root (physical address of PML4)
    /// Contains user mappings and trampoline only
    /// Does NOT include PCID bits
    pub user_cr3: u64,

    /// Kernel-mode page table root (physical address of PML4)
    /// Contains user mappings and full kernel
    /// Does NOT include PCID bits
    pub kernel_cr3: u64,

    /// PCID (Process Context ID) for TLB optimization
    /// 0 = PCID not used, 1-4095 = valid PCID
    pub pcid: u16,
}

impl Default for KptiContext {
    fn default() -> Self {
        Self {
            user_cr3: 0,
            kernel_cr3: 0,
            pcid: 0,
        }
    }
}

impl KptiContext {
    /// Create a KPTI-disabled context (single CR3)
    ///
    /// When KPTI is not enabled, both CR3 values point to the same root.
    pub fn single(cr3: u64) -> Self {
        Self {
            user_cr3: cr3,
            kernel_cr3: cr3,
            pcid: 0,
        }
    }

    /// Create a KPTI-enabled context with separate roots
    #[allow(dead_code)]
    pub fn dual(user_cr3: u64, kernel_cr3: u64, pcid: u16) -> Self {
        Self {
            user_cr3,
            kernel_cr3,
            pcid,
        }
    }

    /// Check if this context has KPTI separation
    #[inline]
    pub fn has_kpti(&self) -> bool {
        self.user_cr3 != self.kernel_cr3
    }

    /// Get CR3 value with PCID bits for user mode
    ///
    /// Returns the user_cr3 combined with PCID if enabled.
    /// The NO_FLUSH bit (bit 63) is not set - caller should set if needed.
    #[inline]
    pub fn user_cr3_with_pcid(&self) -> u64 {
        if self.pcid != 0 {
            self.user_cr3 | (self.pcid as u64)
        } else {
            self.user_cr3
        }
    }

    /// Get CR3 value with PCID bits for kernel mode
    ///
    /// Returns the kernel_cr3 combined with PCID if enabled.
    /// The NO_FLUSH bit (bit 63) is not set - caller should set if needed.
    #[inline]
    pub fn kernel_cr3_with_pcid(&self) -> u64 {
        if self.pcid != 0 {
            self.kernel_cr3 | (self.pcid as u64)
        } else {
            self.kernel_cr3
        }
    }
}

// ============================================================================
// KPTI Stubs (No-op until Phase B)
// ============================================================================

/// Switch to kernel CR3 on syscall/interrupt entry
///
/// # Safety
///
/// This function should only be called from syscall entry points.
/// Currently a no-op; will perform CR3 switch when KPTI is implemented.
#[inline]
pub fn enter_kernel_mode() {
    // No-op: KPTI not yet implemented
    // Future: load kernel CR3, update PCID, fence
    if KPTI_ENABLED.load(Ordering::Relaxed) {
        // Will be implemented in Phase B:
        // 1. Read current KPTI context from per-CPU data
        // 2. Load kernel_cr3 into CR3 register
        // 3. Apply PCID if supported
    }
}

/// Switch to user CR3 before returning to userspace
///
/// # Safety
///
/// This function should only be called from syscall/interrupt exit points.
/// Currently a no-op; will perform CR3 switch when KPTI is implemented.
#[inline]
pub fn return_to_user_mode() {
    // No-op: KPTI not yet implemented
    // Future: load user CR3, update PCID, fence
    if KPTI_ENABLED.load(Ordering::Relaxed) {
        // Will be implemented in Phase B:
        // 1. Read current KPTI context from per-CPU data
        // 2. Load user_cr3 into CR3 register
        // 3. Apply PCID if supported
    }
}

/// Invalidate TLB entries for a specific address
///
/// When KPTI is enabled, this may need to invalidate entries in both
/// page table hierarchies.
#[inline]
pub fn invalidate_page(addr: u64) {
    // Use invlpg instruction
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// Perform a full TLB flush
///
/// When KPTI is enabled, this flushes all TLB entries.
/// May use PCID-aware flush if supported.
#[inline]
pub fn flush_tlb() {
    // Reload CR3 to flush TLB
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

// ============================================================================
// KASLR/KPTI State Queries
// ============================================================================

/// Check if KASLR is currently enabled
#[inline]
pub fn is_kaslr_enabled() -> bool {
    KASLR_ENABLED.load(Ordering::Relaxed)
}

/// Check if KPTI is currently enabled
#[inline]
pub fn is_kpti_enabled() -> bool {
    KPTI_ENABLED.load(Ordering::Relaxed)
}

/// Get the current kernel layout
///
/// Returns the fixed layout for now; will return randomized layout
/// when KASLR is enabled.
pub fn get_kernel_layout() -> KernelLayout {
    if is_kaslr_enabled() {
        // Future: return layout with applied slide
        KernelLayout::fixed()
    } else {
        KernelLayout::fixed()
    }
}

/// Enable KASLR (called by bootloader/early init)
///
/// # Safety
///
/// This should only be called once during boot, before any code
/// relies on the kernel layout. Once enabled, KASLR cannot be disabled.
#[allow(dead_code)]
pub fn enable_kaslr() {
    KASLR_ENABLED.store(true, Ordering::SeqCst);
}

/// Enable KPTI (called during security init)
///
/// # Safety
///
/// This should only be called after page tables are set up with
/// dual roots. Once enabled, all syscall/interrupt paths must
/// use the KPTI CR3 switching stubs.
#[allow(dead_code)]
pub fn enable_kpti() {
    KPTI_ENABLED.store(true, Ordering::SeqCst);
}

// ============================================================================
// Trampoline Support (Preparation for KPTI)
// ============================================================================

/// Trampoline mapping descriptor
///
/// The trampoline is a small code region that must be mapped in both
/// user and kernel page tables for KPTI to work. It contains the
/// syscall entry/exit code that switches CR3.
#[derive(Debug, Clone, Copy)]
pub struct TrampolineDesc {
    /// Virtual address of the trampoline
    pub virt_addr: u64,

    /// Physical address of the trampoline
    pub phys_addr: u64,

    /// Size of the trampoline in bytes (must be page-aligned)
    pub size: u64,

    /// Page table flags for the trampoline mapping
    /// Must be: PRESENT | USER | not-WRITABLE (code only)
    pub flags: u64,
}

impl Default for TrampolineDesc {
    fn default() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            size: 0,
            flags: 0,
        }
    }
}

impl TrampolineDesc {
    /// Check if this is a valid trampoline descriptor
    pub fn is_valid(&self) -> bool {
        self.virt_addr != 0 && self.phys_addr != 0 && self.size > 0
    }

    /// Get the number of pages required for this trampoline
    pub fn page_count(&self) -> u64 {
        (self.size + 4095) / 4096
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize KASLR/KPTI subsystem
///
/// Currently just logs status; will perform actual initialization
/// when features are implemented.
pub fn init() {
    println!("  KASLR: {} (infrastructure ready)",
        if is_kaslr_enabled() { "enabled" } else { "disabled" });
    println!("  KPTI: {} (stubs installed)",
        if is_kpti_enabled() { "enabled" } else { "disabled" });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_layout_fixed() {
        let layout = KernelLayout::fixed();
        assert_eq!(layout.virt_base, KERNEL_VIRT_BASE);
        assert_eq!(layout.phys_base, KERNEL_PHYS_BASE);
        assert_eq!(layout.kaslr_slide, 0);
        assert!(!layout.has_kaslr());
    }

    #[test]
    fn test_kernel_layout_with_slide() {
        let slide = 0x200000; // 2 MiB slide
        let layout = KernelLayout::with_slide(slide);
        assert_eq!(layout.virt_base, KERNEL_VIRT_BASE + slide);
        assert_eq!(layout.kaslr_slide, slide);
        assert!(layout.has_kaslr());
    }

    #[test]
    fn test_virt_to_phys() {
        let layout = KernelLayout::fixed();
        let virt = KERNEL_VIRT_BASE + 0x1000;
        let phys = layout.virt_to_phys(virt);
        assert_eq!(phys, Some(KERNEL_PHYS_BASE + 0x1000));
    }

    #[test]
    fn test_kpti_context_single() {
        let ctx = KptiContext::single(0x12345000);
        assert_eq!(ctx.user_cr3, ctx.kernel_cr3);
        assert!(!ctx.has_kpti());
    }

    #[test]
    fn test_kpti_context_dual() {
        let ctx = KptiContext::dual(0x12345000, 0x67890000, 1);
        assert_ne!(ctx.user_cr3, ctx.kernel_cr3);
        assert!(ctx.has_kpti());
    }
}
