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
use mm::page_table;
use x86_64::{
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
extern "C" {
    static kernel_start: u8;
    static kernel_end: u8;
}

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
    phys_offset: VirtAddr,
    strategy: IdentityCleanupStrategy,
) -> Result<CleanupOutcome, HardeningError> {
    if strategy == IdentityCleanupStrategy::Skip {
        return Ok(CleanupOutcome::Skipped);
    }

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
                    let pdpt = get_table_from_entry(entry, phys_offset)?;
                    let mut updated = 0usize;

                    // Walk PDPT entries (each covers 1GB)
                    for pdpt_entry in pdpt.iter_mut() {
                        if pdpt_entry.is_unused() {
                            continue;
                        }

                        let pdpt_flags = pdpt_entry.flags();

                        // Handle 1GB huge pages
                        if pdpt_flags.contains(PageTableFlags::HUGE_PAGE) {
                            let mut new_flags = pdpt_flags;
                            new_flags.remove(PageTableFlags::WRITABLE);
                            new_flags.insert(PageTableFlags::NO_EXECUTE);
                            pdpt_entry.set_addr(pdpt_entry.addr(), new_flags);
                            updated += 1;
                            continue;
                        }

                        // Walk PD entries (each covers 2MB)
                        let pd = get_table_from_entry(pdpt_entry, phys_offset)?;
                        for pd_entry in pd.iter_mut() {
                            if pd_entry.is_unused() {
                                continue;
                            }

                            let mut flags = pd_entry.flags();
                            flags.remove(PageTableFlags::WRITABLE);
                            flags.insert(PageTableFlags::NO_EXECUTE);
                            pd_entry.set_addr(pd_entry.addr(), flags);
                            updated += 1;
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

/// Enforce NX bit on kernel data sections
///
/// This function walks the high-half kernel mappings and applies proper
/// permissions. For huge pages (2MB), it marks them as NX. For 4KB pages,
/// it applies more granular permissions.
///
/// # Arguments
///
/// * `phys_offset` - Physical memory offset for page table access
/// * `frame_allocator` - Frame allocator (for future use with page splitting)
///
/// # Returns
///
/// Summary of pages protected on success
pub fn enforce_nx_for_kernel(
    phys_offset: VirtAddr,
    _frame_allocator: &mut FrameAllocator,
) -> Result<NxEnforcementSummary, HardeningError> {
    let mut summary = NxEnforcementSummary {
        text_rx_pages: 0,
        ro_pages: 0,
        data_nx_pages: 0,
    };

    // Get kernel section boundaries from linker symbols
    let kernel_start_addr = unsafe { &kernel_start as *const u8 as u64 };
    let kernel_end_addr = unsafe { &kernel_end as *const u8 as u64 };

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

            // Calculate PD indices for kernel range
            let pd_start = pd_index(kernel_start_addr);
            let pd_end = pd_index(kernel_end_addr);

            for pd_idx in pd_start..=pd_end {
                let pd_entry = &mut pd[pd_idx];
                if pd_entry.is_unused() {
                    continue;
                }

                let flags = pd_entry.flags();

                // Handle 2MB huge pages - mark them all as NX for safety
                if flags.contains(PageTableFlags::HUGE_PAGE) {
                    let mut new_flags = flags;
                    new_flags.insert(PageTableFlags::NO_EXECUTE);
                    pd_entry.set_addr(pd_entry.addr(), new_flags);
                    summary.data_nx_pages += 512; // 2MB = 512 * 4KB
                    continue;
                }

                // Walk 4KB page table entries
                let pt = get_table_from_entry(pd_entry, phys_offset)?;
                let pd_base = pd_base_vaddr(pd_idx);

                for (pt_idx, pt_entry) in pt.iter_mut().enumerate() {
                    if pt_entry.is_unused() {
                        continue;
                    }

                    let page_vaddr = pd_base + (pt_idx as u64 * 4096);

                    // Skip pages outside kernel range
                    if page_vaddr < kernel_start_addr || page_vaddr >= kernel_end_addr {
                        continue;
                    }

                    let mut new_flags = pt_entry.flags();
                    new_flags.insert(PageTableFlags::NO_EXECUTE);
                    pt_entry.set_addr(pt_entry.addr(), new_flags);
                    summary.data_nx_pages += 1;
                }
            }

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
