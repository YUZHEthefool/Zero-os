//! VirtQueue implementation for Zero-OS
//!
//! This module provides a generic virtqueue implementation that can be shared
//! across different VirtIO device drivers (block, network, etc.).

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

use crate::{rmb, wmb, VringAvail, VringDesc, VringUsed, VringUsedElem};

/// Generic virtqueue implementation shared by VirtIO drivers.
///
/// This provides the core virtqueue functionality including:
/// - Descriptor allocation/deallocation
/// - Available ring management
/// - Used ring polling
pub struct VirtQueue {
    /// Queue size (number of descriptors).
    size: u16,
    /// Queue notify offset (for PCI transport).
    notify_off: u16,
    /// Descriptor table (DMA-able memory).
    desc: *mut VringDesc,
    /// Available ring.
    avail: *mut VringAvail,
    /// Used ring.
    used: *mut VringUsed,
    /// Free descriptor stack.
    free_list: Mutex<Vec<u16>>,
    /// Last seen used index.
    last_used_idx: AtomicU16,
    /// Physical address of descriptor table.
    desc_phys: u64,
    /// Physical address of available ring.
    avail_phys: u64,
    /// Physical address of used ring.
    used_phys: u64,
}

// SAFETY: VirtQueue contains raw pointers to DMA-able memory
// which is only accessed within synchronized contexts.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Calculate the total DMA memory needed for a virtqueue (bytes).
    ///
    /// Returns the size needed for descriptor table, available ring, and used ring,
    /// each aligned to 4KB for DMA compatibility.
    pub fn layout_size(queue_size: u16) -> usize {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize; // flags + idx + ring
        let used_size = 4 + 8 * queue_size as usize; // flags + idx + ring

        // Align each section to 4KB for DMA
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;
        let used_pages = (used_size + 4095) / 4096;

        (desc_pages + avail_pages + used_pages) * 4096
    }

    /// Create a new virtqueue at the given physical base address.
    ///
    /// # Arguments
    /// * `base_phys` - Physical address of the DMA buffer for the queue
    /// * `queue_size` - Number of descriptors in the queue
    /// * `phys_to_virt_offset` - Offset to convert physical to virtual address
    /// * `notify_off` - Notify offset for this queue (from transport)
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The memory region at `base_phys` is valid, DMA-able, and mapped
    /// - The region is large enough (use `layout_size()` to calculate)
    pub unsafe fn new(
        base_phys: u64,
        queue_size: u16,
        phys_to_virt_offset: u64,
        notify_off: u16,
    ) -> Self {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize;

        // Calculate aligned offsets
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;

        let desc_phys = base_phys;
        let avail_phys = desc_phys + (desc_pages * 4096) as u64;
        let used_phys = avail_phys + (avail_pages * 4096) as u64;

        // Convert to virtual addresses using the provided mapping offset
        let desc = (desc_phys + phys_to_virt_offset) as *mut VringDesc;
        let avail = (avail_phys + phys_to_virt_offset) as *mut VringAvail;
        let used = (used_phys + phys_to_virt_offset) as *mut VringUsed;

        // Initialize free list (push in reverse order so 0 is first to be allocated)
        let mut free_list = Vec::with_capacity(queue_size as usize);
        for i in (0..queue_size).rev() {
            free_list.push(i);
        }

        // Zero out the rings
        core::ptr::write_bytes(desc, 0, queue_size as usize);
        core::ptr::write_bytes(avail, 0, 1);
        core::ptr::write_bytes(used, 0, 1);

        Self {
            size: queue_size,
            notify_off,
            desc,
            avail,
            used,
            free_list: Mutex::new(free_list),
            last_used_idx: AtomicU16::new(0),
            desc_phys,
            avail_phys,
            used_phys,
        }
    }

    /// Queue size (number of descriptors).
    #[inline]
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Notify offset for this queue (PCI transport).
    #[inline]
    pub fn notify_offset(&self) -> u16 {
        self.notify_off
    }

    /// Physical address of the descriptor table.
    #[inline]
    pub fn desc_table_phys(&self) -> u64 {
        self.desc_phys
    }

    /// Physical address of the available ring.
    #[inline]
    pub fn avail_ring_phys(&self) -> u64 {
        self.avail_phys
    }

    /// Physical address of the used ring.
    #[inline]
    pub fn used_ring_phys(&self) -> u64 {
        self.used_phys
    }

    /// Allocate a descriptor from the free list.
    ///
    /// Returns `None` if no descriptors are available.
    pub fn alloc_desc(&self) -> Option<u16> {
        self.free_list.lock().pop()
    }

    /// Free a descriptor back to the free list.
    pub fn free_desc(&self, idx: u16) {
        self.free_list.lock().push(idx);
    }

    /// Get the number of available descriptors.
    pub fn available_descs(&self) -> usize {
        self.free_list.lock().len()
    }

    /// Push a descriptor chain to the available ring.
    ///
    /// # Safety
    /// The caller must ensure the descriptor chain is properly set up.
    pub unsafe fn push_avail(&self, head: u16) {
        let avail = &mut *self.avail;
        let idx = read_volatile(&avail.idx);
        let ring_idx = (idx % self.size) as usize;

        // Write to ring
        let ring_ptr = avail.ring.as_mut_ptr();
        write_volatile(ring_ptr.add(ring_idx), head);

        // Memory barrier before updating idx
        wmb();

        // Update index
        write_volatile(&mut avail.idx, idx.wrapping_add(1));
    }

    /// Check if there are used entries to process.
    pub fn has_used(&self) -> bool {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);
            used_idx != last
        }
    }

    /// Pop a used entry from the used ring.
    ///
    /// Returns `None` if no used entries are available.
    pub fn pop_used(&self) -> Option<VringUsedElem> {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);

            if used_idx == last {
                return None;
            }

            rmb();

            let ring_idx = (last % self.size) as usize;
            let ring_ptr = used.ring.as_ptr();
            let elem = read_volatile(ring_ptr.add(ring_idx));

            self.last_used_idx
                .store(last.wrapping_add(1), Ordering::Relaxed);

            Some(elem)
        }
    }

    /// Get mutable reference to a descriptor at the given index.
    ///
    /// # Safety
    /// The caller must ensure the index is valid and the descriptor
    /// is not currently in use by the device.
    pub unsafe fn desc_mut(&self, idx: u16) -> &mut VringDesc {
        &mut *self.desc.add(idx as usize)
    }

    /// Get a reference to a descriptor at the given index.
    ///
    /// # Safety
    /// The caller must ensure the index is valid.
    pub unsafe fn desc(&self, idx: u16) -> &VringDesc {
        &*self.desc.add(idx as usize)
    }
}
