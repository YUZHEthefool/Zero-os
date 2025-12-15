//! Memory Hardening for Zero-OS
//!
//! This module provides memory protection hardening:
//!
//! - **Identity Map Cleanup**: Remove or restrict the bootloader's identity mapping
//! - **NX Enforcement**: Set the No-Execute bit on data pages
//! - **Section Protection**: Apply appropriate permissions to kernel sections
//!
//! # Security Goals
//!
//! 1. **Prevent Code Injection**: Data regions should not be executable
//! 2. **Prevent Code Modification**: Code regions should be read-only
//! 3. **Minimize Attack Surface**: Remove unnecessary memory mappings

use mm::memory::FrameAllocator;
use mm::page_table::{
    self,
    MapError,
    APIC_MMIO_SIZE,
    APIC_PHYS_ADDR,
    VGA_PHYS_ADDR,
    ensure_pte_range,
    map_mmio,
    mmio_flags,
    recursive_pdpt,
    recursive_pd,
    recursive_pt,
};
use x86_64::{
    PhysAddr,
    VirtAddr,
    instructions::tlb,
    structures::paging::{PageTable, PageTableFlags},
    structures::paging::page_table::PageTableEntry,
};

/// Strategy for handling the identity mapping after boot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCleanupStrategy {
    /// Completely remove the identity mapping
    Unmap,
    /// Keep mapping but remove WRITABLE flag and add NO_EXECUTE
    RemoveWritable,
    /// Skip identity map cleanup (for debugging only)
    Skip,
}

/// Outcome of identity map cleanup
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// Identity mapping was completely removed
    Unmapped,
    /// Identity mapping was made read-only with NX
    ReadOnlyUpdated { updated_entries: usize },
    /// Identity mapping was already absent
    AlreadyAbsent,
    /// Cleanup was skipped
    Skipped,
}

/// Memory hardening errors
#[derive(Debug)]
pub enum HardeningError {
    /// Required page table level is missing
    PageTableMissing(&'static str),
    /// Failed to allocate a frame for page table splitting
    FrameAllocFailed,
    /// Page table structure is inconsistent
    InconsistentTopology,
    /// Invalid virtual or physical address
    InvalidAddress,
    /// Operation would break kernel functionality
    UnsafeOperation(&'static str),
}

/// Summary of NX enforcement
#[derive(Debug, Clone, Copy)]
pub struct NxEnforcementSummary {
    /// Pages marked as R-X (text/code)
    pub text_rx_pages: usize,
    /// Pages marked as R-- (rodata)
    pub ro_pages: usize,
    /// Pages marked as RW- with NX (data/bss)
    pub data_nx_pages: usize,
}

// External linker symbols for section boundaries
#[allow(dead_code)]
extern "C" {
    static kernel_start: u8;
    static kernel_end: u8;
    static text_start: u8;
    static text_end: u8;
    static rodata_start: u8;
    static rodata_end: u8;
    static data_start: u8;
    static data_end: u8;
    static bss_start: u8;
    static bss_end: u8;
}

/// VGA MMIO region size (4 KiB)
const VGA_MMIO_SIZE: usize = 0x1000;

/// Clean up the identity mapping created by the bootloader
///
/// The bootloader creates an identity mapping (physical == virtual) for the
/// first 4GB. After initialization, this mapping should be restricted.
///
/// # Arguments
///
/// * `phys_offset` - Physical memory offset for page table access
/// * `strategy` - How to handle the identity mapping
///
/// # Returns
///
/// Cleanup outcome on success, error if the operation fails
pub fn cleanup_identity_map(
    _phys_offset: VirtAddr,
    strategy: IdentityCleanupStrategy,
) -> Result<CleanupOutcome, HardeningError> {
    if strategy == IdentityCleanupStrategy::Skip {
        return Ok(CleanupOutcome::Skipped);
    }

    // Ensure MMIO windows stay reachable before altering identity mappings
    let mut frame_allocator = FrameAllocator::new();
    protect_mmio_regions(&mut frame_allocator)?;

    // Get current RSP - we must preserve this region as writable
    // The bootloader sets up a stack in identity-mapped memory
    let current_rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, nostack));
    }
    // Calculate the 2MB region containing the stack
    let stack_pd_base = current_rsp & !0x1FFFFF; // Align to 2MB boundary

    unsafe {
        page_table::with_active_level_4_table(|pml4| {
            // PML4[0] covers virtual addresses 0x0 to 0x7FFFFFFFFFFF (low half)
            let entry = &mut pml4[0];

            if entry.is_unused() {
                return Ok(CleanupOutcome::AlreadyAbsent);
            }

            match strategy {
                IdentityCleanupStrategy::Unmap => {
                    // Completely remove the identity mapping
                    // WARNING: May break hardware access (VGA at 0xB8000, etc.)
                    entry.set_unused();
                    tlb::flush_all();
                    Ok(CleanupOutcome::Unmapped)
                }

                IdentityCleanupStrategy::RemoveWritable => {
                    // Make the identity mapping read-only with NX
                    // Use recursive page table access to reach page table frames
                    // at any physical address (not limited by high-half mapping)

                    // Verify PML4[510] recursive entry is set
                    let pml4_510 = &pml4[510];
                    if pml4_510.is_unused() {
                        return Err(HardeningError::PageTableMissing("PML4[510] recursive entry missing"));
                    }

                    let pdpt = recursive_pdpt(0);
                    let mut updated = 0usize;

                    // Walk PDPT entries (each covers 1GB)
                    for (pdpt_idx, pdpt_entry) in pdpt.iter_mut().enumerate() {
                        if pdpt_entry.is_unused() {
                            continue;
                        }

                        let pdpt_flags = pdpt_entry.flags();

                        // Handle 1GB huge pages - cannot split, error out
                        if pdpt_flags.contains(PageTableFlags::HUGE_PAGE) {
                            return Err(HardeningError::UnsafeOperation(
                                "Cannot harden 1GB identity mapping without splitting",
                            ));
                        }

                        // Walk PD entries (each covers 2MB)
                        let pd = recursive_pd(0, pdpt_idx);

                        for (pd_idx, pd_entry) in pd.iter_mut().enumerate() {
                            if pd_entry.is_unused() {
                                continue;
                            }

                            let pd_base = identity_pd_base(pdpt_idx, pd_idx);
                            updated += harden_identity_pd_entry_recursive(
                                pd_entry,
                                pd_base,
                                pdpt_idx,
                                pd_idx,
                                stack_pd_base,
                            )?;
                        }
                    }

                    tlb::flush_all();
                    Ok(CleanupOutcome::ReadOnlyUpdated { updated_entries: updated })
                }

                IdentityCleanupStrategy::Skip => Ok(CleanupOutcome::Skipped),
            }
        })
    }
}

// Silence unused warning for phys_offset parameter (kept for API compatibility)
#[allow(unused_variables)]

/// Enforce NX bit on kernel data sections
///
/// This function walks the high-half kernel mappings and applies proper
/// W^X permissions based on section type:
/// - text: R-X (executable, read-only)
/// - rodata: R-- (read-only, non-executable)
/// - data/bss: RW-NX (read-write, non-executable)
///
/// # Arguments
///
/// * `phys_offset` - Physical memory offset for page table access
/// * `frame_allocator` - Frame allocator for page table splitting
///
/// # Returns
///
/// Summary of pages protected on success
pub fn enforce_nx_for_kernel(
    phys_offset: VirtAddr,
    frame_allocator: &mut FrameAllocator,
) -> Result<NxEnforcementSummary, HardeningError> {
    let mut summary = NxEnforcementSummary {
        text_rx_pages: 0,
        ro_pages: 0,
        data_nx_pages: 0,
    };

    // Get kernel section boundaries from linker symbols
    let text = SectionRange::new(
        unsafe { &text_start as *const u8 as u64 },
        unsafe { &text_end as *const u8 as u64 },
    );
    let rodata = SectionRange::new(
        unsafe { &rodata_start as *const u8 as u64 },
        unsafe { &rodata_end as *const u8 as u64 },
    );
    let data = SectionRange::new(
        unsafe { &data_start as *const u8 as u64 },
        unsafe { &data_end as *const u8 as u64 },
    );
    let bss = SectionRange::new(
        unsafe { &bss_start as *const u8 as u64 },
        unsafe { &bss_end as *const u8 as u64 },
    );

    // Demote huge pages to 4KB granularity across all sections
    unsafe {
        ensure_pte_range(VirtAddr::new(text.start), text.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
        ensure_pte_range(VirtAddr::new(rodata.start), rodata.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
        ensure_pte_range(VirtAddr::new(data.start), data.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
        ensure_pte_range(VirtAddr::new(bss.start), bss.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
    }

    unsafe {
        page_table::with_active_level_4_table(|pml4| {
            // PML4[511] covers the high half (kernel space)
            let pml4_entry = &mut pml4[511];
            if pml4_entry.is_unused() {
                return Err(HardeningError::PageTableMissing("PML4[511] missing"));
            }

            let pdpt = get_table_from_entry(pml4_entry, phys_offset)?;

            // PDPT[510] covers 0xFFFFFFFF80000000 - 0xFFFFFFFFBFFFFFFF
            let pdpt_entry = &mut pdpt[510];
            if pdpt_entry.is_unused() {
                return Err(HardeningError::PageTableMissing("PDPT[510] missing"));
            }

            // Check if this is a huge page
            if pdpt_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(HardeningError::UnsafeOperation(
                    "Cannot split 1GB huge page for kernel"
                ));
            }

            let pd = get_table_from_entry(pdpt_entry, phys_offset)?;

            // Apply text section: R-X (executable, read-only)
            apply_section(
                pd,
                phys_offset,
                &text,
                |mut flags| {
                    flags.remove(PageTableFlags::WRITABLE);
                    flags.remove(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.text_rx_pages,
            )?;

            // Apply rodata section: R-- (read-only, non-executable)
            apply_section(
                pd,
                phys_offset,
                &rodata,
                |mut flags| {
                    flags.remove(PageTableFlags::WRITABLE);
                    flags.insert(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.ro_pages,
            )?;

            // Apply data section: RW-NX (read-write, non-executable)
            apply_section(
                pd,
                phys_offset,
                &data,
                |mut flags| {
                    flags.insert(PageTableFlags::WRITABLE);
                    flags.insert(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.data_nx_pages,
            )?;

            // Apply bss section: RW-NX (read-write, non-executable)
            apply_section(
                pd,
                phys_offset,
                &bss,
                |mut flags| {
                    flags.insert(PageTableFlags::WRITABLE);
                    flags.insert(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.data_nx_pages,
            )?;

            tlb::flush_all();
            Ok(summary)
        })
    }
}

/// Get child page table from a page table entry
unsafe fn get_table_from_entry(
    entry: &mut PageTableEntry,
    phys_offset: VirtAddr,
) -> Result<&'static mut PageTable, HardeningError> {
    if entry.is_unused() {
        return Err(HardeningError::PageTableMissing("entry is unused"));
    }

    let phys = entry.addr();
    let virt = phys_offset + phys.as_u64();
    Ok(&mut *(virt.as_u64() as *mut PageTable))
}

/// Calculate PD index for a virtual address
#[inline]
fn pd_index(vaddr: u64) -> usize {
    ((vaddr >> 21) & 0x1FF) as usize
}

/// Calculate base virtual address for a PD index (in high half)
#[inline]
fn pd_base_vaddr(pd_idx: usize) -> u64 {
    0xFFFF_FFFF_8000_0000u64 + (pd_idx as u64 * 0x200000)
}

// ============================================================================
// Helper types and functions for per-section W^X enforcement
// ============================================================================

/// Represents a kernel section address range (page-aligned)
#[derive(Clone, Copy)]
struct SectionRange {
    start: u64,
    end: u64,
}

impl SectionRange {
    fn new(start: u64, end: u64) -> Self {
        SectionRange {
            start: align_down(start),
            end: align_up(end),
        }
    }

    fn size(&self) -> usize {
        self.end.saturating_sub(self.start) as usize
    }
}

/// Apply protection flags to a kernel section
fn apply_section<F>(
    pd: &mut PageTable,
    phys_offset: VirtAddr,
    range: &SectionRange,
    mut adjust: F,
    counter: &mut usize,
) -> Result<(), HardeningError>
where
    F: FnMut(PageTableFlags) -> PageTableFlags,
{
    if range.size() == 0 {
        return Ok(());
    }

    let pd_start = pd_index(range.start);
    let pd_end = pd_index(range.end.saturating_sub(1));

    for pd_idx in pd_start..=pd_end {
        let pd_entry = &mut pd[pd_idx];
        if pd_entry.is_unused() {
            continue;
        }

        let flags = pd_entry.flags();
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(HardeningError::UnsafeOperation(
                "Expected 4KB pages after demotion",
            ));
        }

        let pt = unsafe { get_table_from_entry(pd_entry, phys_offset)? };
        let pd_base = pd_base_vaddr(pd_idx);

        for (pt_idx, pt_entry) in pt.iter_mut().enumerate() {
            if pt_entry.is_unused() {
                continue;
            }

            let page_vaddr = pd_base + (pt_idx as u64 * 4096);
            if page_vaddr < range.start || page_vaddr >= range.end {
                continue;
            }

            let new_flags = adjust(pt_entry.flags());
            pt_entry.set_addr(pt_entry.addr(), new_flags);
            *counter += 1;
        }
    }

    Ok(())
}

// ============================================================================
// Identity map hardening helpers
// ============================================================================

/// Harden a single PD entry in the identity mapping
///
/// Note: We do NOT split 2MB huge pages because the frame allocator returns
/// frames that may not be accessible via the high-half mapping (bootloader
/// only maps a limited range). Instead, we mark entire 2MB regions as RO+NX.
///
/// This means MMIO regions in the identity map become read-only (breaking
/// direct identity-map device access), but:
/// - VGA is accessible via high-half: PHYSICAL_MEMORY_OFFSET + 0xB8000
/// - APIC will need dedicated high-half mapping when SMP is implemented
fn harden_identity_pd_entry(
    pd_entry: &mut PageTableEntry,
    pd_base: u64,
    phys_offset: VirtAddr,
    _frame_allocator: &mut FrameAllocator,
) -> Result<usize, HardeningError> {
    if pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        // Mark entire 2MB huge page as RO+NX
        // We don't split because allocated frames may not be accessible
        let mut flags = pd_entry.flags();
        flags.remove(PageTableFlags::WRITABLE);
        flags.insert(PageTableFlags::NO_EXECUTE);
        pd_entry.set_addr(pd_entry.addr(), flags);
        return Ok(1);
    }

    // Already 4KB pages, harden each entry preserving MMIO access
    let pt = unsafe { get_table_from_entry(pd_entry, phys_offset)? };
    Ok(harden_identity_pt(pt, pd_base))
}

/// Harden a page table in the identity mapping, preserving MMIO pages
fn harden_identity_pt(pt: &mut PageTable, pd_base: u64) -> usize {
    let mut updated = 0usize;

    for (pt_idx, pt_entry) in pt.iter_mut().enumerate() {
        if pt_entry.is_unused() {
            continue;
        }

        let page_vaddr = pd_base + (pt_idx as u64 * 4096);
        let mut flags = pt_entry.flags();

        if is_mmio_page(page_vaddr) {
            // MMIO pages: keep writable, add NX, add uncached flags
            let mut mmio = mmio_flags();
            if flags.contains(PageTableFlags::GLOBAL) {
                mmio.insert(PageTableFlags::GLOBAL);
            }
            flags = mmio;
        } else {
            // Normal pages: make read-only, add NX
            flags.remove(PageTableFlags::WRITABLE);
            flags.insert(PageTableFlags::NO_EXECUTE);
        }

        pt_entry.set_addr(pt_entry.addr(), flags);
        updated += 1;
    }

    updated
}

/// Harden a single PD entry using recursive page table access
///
/// This version uses the recursive page table mapping (PML4[510]) to access
/// page table frames at any physical address, bypassing the high-half mapping
/// limitation.
fn harden_identity_pd_entry_recursive(
    pd_entry: &mut PageTableEntry,
    pd_base: u64,
    pdpt_idx: usize,
    pd_idx: usize,
    stack_pd_base: u64,
) -> Result<usize, HardeningError> {
    let flags = pd_entry.flags();
    if flags.contains(PageTableFlags::HUGE_PAGE) {
        // Check if this 2MB region contains MMIO - if so, preserve writability
        if is_mmio_2mb_region(pd_base) {
            // MMIO region: add NX but keep writable, add uncached flags
            let mut new_flags = mmio_flags();
            // Preserve HUGE_PAGE flag
            new_flags.insert(PageTableFlags::HUGE_PAGE);
            if flags.contains(PageTableFlags::GLOBAL) {
                new_flags.insert(PageTableFlags::GLOBAL);
            }
            if flags.contains(PageTableFlags::ACCESSED) {
                new_flags.insert(PageTableFlags::ACCESSED);
            }
            if flags.contains(PageTableFlags::DIRTY) {
                new_flags.insert(PageTableFlags::DIRTY);
            }
            pd_entry.set_addr(pd_entry.addr(), new_flags);
            return Ok(1);
        }

        // Check if this 2MB region contains the bootloader stack - preserve writability
        if pd_base == stack_pd_base {
            // Stack region: keep writable but add NX (code shouldn't run from stack)
            let mut new_flags = flags;
            new_flags.insert(PageTableFlags::NO_EXECUTE);
            pd_entry.set_addr(pd_entry.addr(), new_flags);
            return Ok(1);
        }

        // Normal region: make read-only + NX
        let mut new_flags = flags;
        new_flags.remove(PageTableFlags::WRITABLE);
        new_flags.insert(PageTableFlags::NO_EXECUTE);
        pd_entry.set_addr(pd_entry.addr(), new_flags);
        return Ok(1);
    }

    // 4KB pages - need to access PT via recursive mapping
    let pt = unsafe { recursive_pt(0, pdpt_idx, pd_idx) };
    Ok(harden_identity_pt(pt, pd_base))
}

// ============================================================================
// MMIO protection
// ============================================================================

/// Ensure MMIO regions are properly mapped before identity map cleanup
///
/// Note: This function is currently a no-op. MMIO protection in the identity
/// map is handled by harden_identity_pd_entry when it detects MMIO ranges.
/// The high-half VGA access uses PHYSICAL_MEMORY_OFFSET which is already
/// set up by the bootloader.
///
/// TODO: Implement proper high-half APIC mapping when needed for SMP.
fn protect_mmio_regions(_frame_allocator: &mut FrameAllocator) -> Result<(), HardeningError> {
    // MMIO in identity map is preserved by harden_identity_pd_entry
    // VGA high-half access works via PHYSICAL_MEMORY_OFFSET
    // APIC mapping deferred until SMP implementation
    Ok(())
}

/// Map a single MMIO region with proper flags
#[allow(dead_code)]
unsafe fn map_mmio_region(
    virt: VirtAddr,
    phys: PhysAddr,
    size: usize,
    frame_allocator: &mut FrameAllocator,
) -> Result<(), HardeningError> {
    map_mmio(virt, phys, size, frame_allocator).map_err(map_error_to_hardening)
}

// ============================================================================
// Utility functions
// ============================================================================

/// Calculate base address for identity map PD entry
#[inline]
fn identity_pd_base(pdpt_idx: usize, pd_idx: usize) -> u64 {
    (pdpt_idx as u64 * 0x4000_0000) + (pd_idx as u64 * 0x200000)
}

/// Check if two ranges overlap
#[inline]
fn overlaps(start_a: u64, end_a: u64, start_b: u64, end_b: u64) -> bool {
    start_a < end_b && start_b < end_a
}

/// Check if a page address is within an MMIO region
#[inline]
fn is_mmio_page(vaddr: u64) -> bool {
    overlaps(
        vaddr,
        vaddr.saturating_add(0x1000),
        VGA_PHYS_ADDR,
        VGA_PHYS_ADDR + VGA_MMIO_SIZE as u64,
    ) || overlaps(
        vaddr,
        vaddr.saturating_add(0x1000),
        APIC_PHYS_ADDR,
        APIC_PHYS_ADDR + APIC_MMIO_SIZE as u64,
    )
}

/// Check if a 2MB region contains any MMIO address
#[inline]
fn is_mmio_2mb_region(pd_base: u64) -> bool {
    let pd_end = pd_base + 0x200000;
    overlaps(
        pd_base,
        pd_end,
        VGA_PHYS_ADDR,
        VGA_PHYS_ADDR + VGA_MMIO_SIZE as u64,
    ) || overlaps(
        pd_base,
        pd_end,
        APIC_PHYS_ADDR,
        APIC_PHYS_ADDR + APIC_MMIO_SIZE as u64,
    )
}

/// Align address down to page boundary
#[inline]
fn align_down(addr: u64) -> u64 {
    addr & !0xfffu64
}

/// Align address up to page boundary
#[inline]
fn align_up(addr: u64) -> u64 {
    (addr + 0xfffu64) & !0xfffu64
}

/// Convert MapError to HardeningError
fn map_error_to_hardening(err: MapError) -> HardeningError {
    match err {
        MapError::FrameAllocationFailed => HardeningError::FrameAllocFailed,
        MapError::ParentEntryHugePage => HardeningError::UnsafeOperation(
            "Cannot demote huge page at requested granularity",
        ),
        MapError::PageAlreadyMapped => HardeningError::InconsistentTopology,
    }
}
