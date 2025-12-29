//! VirtIO Block Device Driver for Zero-OS
//!
//! This module implements a virtio-blk driver supporting both MMIO and PCI transports.
//! It provides a simple synchronous interface for block I/O.
//!
//! # Features
//! - MMIO transport for embedded/virtio-mmio setups
//! - PCI modern transport for standard x86 VMs
//! - Synchronous read/write operations
//! - Proper feature negotiation
//! - Integration with Block Layer

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

use super::transport::{MmioTransport, VirtioPciAddrs, VirtioPciTransport, VirtioTransport};
use super::{
    blk_features, blk_status, blk_types, mb, rmb, wmb, VirtioBlkConfig, VirtioBlkReqHeader,
    VringAvail, VringDesc, VringUsed, VringUsedElem, VIRTIO_DEVICE_BLK, VIRTIO_F_VERSION_1,
    VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK, VIRTIO_VERSION_LEGACY, VIRTIO_VERSION_MODERN, VRING_DESC_F_NEXT,
    VRING_DESC_F_WRITE,
};
use crate::{Bio, BioOp, BioResult, BioVec, BlockDevice, BlockError};

// ============================================================================
// Constants
// ============================================================================

/// Default queue size.
const DEFAULT_QUEUE_SIZE: u16 = 128;

/// Maximum pending requests.
const MAX_PENDING: usize = 64;

// ============================================================================
// DMA Address Translation (R28-1 Fix)
// ============================================================================

/// Translate a kernel virtual address to a DMA-safe physical address.
///
/// For kernel heap allocations (which are in the high-half direct map),
/// we can simply subtract PHYSICAL_MEMORY_OFFSET to get the physical address.
///
/// # Arguments
/// * `ptr` - Virtual address pointer
/// * `len` - Length of the buffer (must be > 0)
///
/// # Returns
/// Physical address suitable for DMA, or BlockError::Invalid if translation fails.
///
/// # Safety
/// The caller must ensure the buffer is in kernel address space (high-half direct map).
fn virt_to_phys_dma(ptr: *const u8, len: usize) -> Result<u64, BlockError> {
    if len == 0 {
        return Err(BlockError::Invalid);
    }

    let virt = ptr as u64;

    // Kernel high-half direct map: 0xffffffff80000000 -> physical 0x0
    // This covers the first 1GB of physical memory where kernel allocations reside.
    const PHYSICAL_MEMORY_OFFSET: u64 = 0xffff_ffff_8000_0000;

    // Verify the address is in the expected kernel range
    if virt < PHYSICAL_MEMORY_OFFSET {
        // Address is not in kernel direct map - this is a programming error
        // User-space buffers should never reach here
        return Err(BlockError::Invalid);
    }

    let phys = virt - PHYSICAL_MEMORY_OFFSET;

    // Overflow check: ensure the entire buffer is within valid physical memory
    // The direct map covers 0-1GB (0x0 to 0x40000000)
    let end = phys.checked_add(len as u64 - 1).ok_or(BlockError::Invalid)?;
    if end >= 0x4000_0000 {
        // Beyond direct map coverage - likely an error
        return Err(BlockError::Invalid);
    }

    Ok(phys)
}

// ============================================================================
// VirtQueue Implementation
// ============================================================================

/// A single virtqueue for the device.
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
    /// Free descriptor list (simple stack).
    free_head: AtomicU16,
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
    /// Calculate the size needed for a virtqueue.
    fn calc_size(queue_size: u16) -> usize {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize; // flags + idx + ring
        let used_size = 4 + 8 * queue_size as usize; // flags + idx + ring

        // Align each section to 4KB for DMA
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;
        let used_pages = (used_size + 4095) / 4096;

        (desc_pages + avail_pages + used_pages) * 4096
    }

    /// Create a new virtqueue at the given physical address.
    ///
    /// # Safety
    /// The caller must ensure the memory region is valid and DMA-able.
    /// DMA memory is accessed via the kernel's high-half mapping (PHYSICAL_MEMORY_OFFSET).
    unsafe fn new(base_phys: u64, queue_size: u16, _virt_offset: u64, notify_off: u16) -> Self {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize;

        // Calculate aligned offsets
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;

        let desc_phys = base_phys;
        let avail_phys = desc_phys + (desc_pages * 4096) as u64;
        let used_phys = avail_phys + (avail_pages * 4096) as u64;

        // Convert to virtual addresses using kernel's high-half mapping
        // DMA memory from buddy allocator uses PHYSICAL_MEMORY_OFFSET, not the MMIO virt_offset
        let desc = (desc_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringDesc;
        let avail = (avail_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringAvail;
        let used = (used_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringUsed;

        // Initialize free list
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
            free_head: AtomicU16::new(0),
            free_list: Mutex::new(free_list),
            last_used_idx: AtomicU16::new(0),
            desc_phys,
            avail_phys,
            used_phys,
        }
    }

    /// Allocate a descriptor from the free list.
    fn alloc_desc(&self) -> Option<u16> {
        self.free_list.lock().pop()
    }

    /// Free a descriptor back to the free list.
    fn free_desc(&self, idx: u16) {
        self.free_list.lock().push(idx);
    }

    /// Get available descriptor count.
    fn available_descs(&self) -> usize {
        self.free_list.lock().len()
    }

    /// Push a descriptor chain to the available ring.
    unsafe fn push_avail(&self, head: u16) {
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
    fn has_used(&self) -> bool {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);
            used_idx != last
        }
    }

    /// Pop a used entry.
    fn pop_used(&self) -> Option<VringUsedElem> {
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

            self.last_used_idx.store(last.wrapping_add(1), Ordering::Relaxed);

            Some(elem)
        }
    }

    /// Get descriptor at index.
    unsafe fn desc(&self, idx: u16) -> &mut VringDesc {
        &mut *self.desc.add(idx as usize)
    }
}

// ============================================================================
// VirtIO Block Device
// ============================================================================

/// VirtIO block device.
pub struct VirtioBlkDevice {
    /// Device name.
    name: String,
    /// Transport layer (MMIO or PCI).
    transport: VirtioTransport,
    /// Virtqueue for requests.
    queue: VirtQueue,
    /// Device capacity in sectors.
    capacity: u64,
    /// Sector size.
    sector_size: u32,
    /// Read-only flag.
    read_only: bool,
    /// Negotiated features.
    features: u64,
    /// Lock for synchronous operations.
    lock: Mutex<()>,
    /// Request buffers (header + status).
    req_buffers: Mutex<Vec<RequestBuffer>>,
}

/// Buffer for a single request.
struct RequestBuffer {
    /// Request header.
    header: VirtioBlkReqHeader,
    /// Status byte.
    status: u8,
    /// In use flag.
    in_use: bool,
}

// SAFETY: VirtioBlkDevice is designed for single-threaded access
// with internal locking for synchronization.
unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}

impl VirtioBlkDevice {
    /// Probe for a virtio-blk device using MMIO transport.
    ///
    /// # Arguments
    /// * `mmio_phys` - Physical address of the MMIO region
    /// * `virt_offset` - Offset to add for virtual address conversion
    /// * `name` - Device name (e.g., "vda")
    ///
    /// # Safety
    /// Caller must ensure the MMIO address is valid and mapped.
    pub unsafe fn probe_mmio(
        mmio_phys: u64,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        let transport = MmioTransport::probe(mmio_phys, virt_offset)
            .ok_or(BlockError::NotFound)?;
        Self::probe_with_transport(VirtioTransport::Mmio(transport), virt_offset, name)
    }

    /// Probe for a virtio-blk device using virtio-pci modern transport.
    ///
    /// # Arguments
    /// * `pci_addrs` - Parsed PCI capability addresses
    /// * `virt_offset` - Offset to add for virtual address conversion
    /// * `name` - Device name (e.g., "vda")
    ///
    /// # Safety
    /// Caller must ensure the MMIO windows are mapped (identity mapped low memory).
    pub unsafe fn probe_pci(
        pci_addrs: VirtioPciAddrs,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        let transport = VirtioPciTransport::from_addrs(pci_addrs, virt_offset)
            .ok_or(BlockError::NotSupported)?;
        Self::probe_with_transport(VirtioTransport::Pci(transport), virt_offset, name)
    }

    /// Common probe logic for any transport.
    unsafe fn probe_with_transport(
        transport: VirtioTransport,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        // Check device type
        let device_id = transport.device_id();
        if device_id != VIRTIO_DEVICE_BLK {
            return Err(BlockError::NotFound);
        }

        // Check version
        let version = transport.version();
        if version != VIRTIO_VERSION_LEGACY && version != VIRTIO_VERSION_MODERN {
            return Err(BlockError::NotSupported);
        }

        Self::init_device(transport, virt_offset, name)
    }

    /// Initialize the device.
    unsafe fn init_device(
        transport: VirtioTransport,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        // Reset device
        transport.reset();
        mb();

        // Acknowledge device
        transport.set_status(VIRTIO_STATUS_ACKNOWLEDGE);

        // Set DRIVER status
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_DRIVER);

        // Read device features
        let device_features = transport.device_features();

        // Select features we want
        let mut driver_features = 0u64;
        // Modern virtio devices (1.0+) require VIRTIO_F_VERSION_1 to be acknowledged
        if device_features & VIRTIO_F_VERSION_1 != 0 {
            driver_features |= VIRTIO_F_VERSION_1;
        }
        if device_features & blk_features::VIRTIO_BLK_F_RO != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_RO;
        }
        if device_features & blk_features::VIRTIO_BLK_F_FLUSH != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_FLUSH;
        }
        if device_features & blk_features::VIRTIO_BLK_F_BLK_SIZE != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_BLK_SIZE;
        }

        // Write driver features
        transport.write_driver_features(driver_features);

        // Set FEATURES_OK
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_FEATURES_OK);

        // Verify FEATURES_OK
        let status = transport.status();
        if status & VIRTIO_STATUS_FEATURES_OK == 0 {
            return Err(BlockError::NotSupported);
        }

        // Read device config
        let config = transport.read_blk_config();
        let capacity = config.capacity;
        let sector_size = if config.blk_size != 0 {
            config.blk_size
        } else {
            512
        };
        let read_only = driver_features & blk_features::VIRTIO_BLK_F_RO != 0;

        // Setup queue 0
        let queue_size_max = transport.queue_max(0);
        let queue_size = queue_size_max.min(DEFAULT_QUEUE_SIZE);

        if queue_size == 0 {
            return Err(BlockError::NotSupported);
        }

        // Allocate queue memory (simplified: use high physical memory)
        // In a real implementation, this would use a proper DMA allocator
        let queue_mem_size = VirtQueue::calc_size(queue_size);
        let queue_phys = Self::alloc_dma_memory(queue_mem_size)?;

        // Get notify offset for PCI transport
        let notify_off = transport.queue_notify_off(0);

        // Create virtqueue
        let queue = VirtQueue::new(queue_phys, queue_size, virt_offset, notify_off);

        // Configure queue
        transport.setup_queue(
            0,
            queue_size,
            queue.desc_phys,
            queue.avail_phys,
            queue.used_phys,
        );
        transport.queue_ready(0, true);

        // Set DRIVER_OK
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_DRIVER_OK);

        // Create request buffers
        let mut req_buffers = Vec::with_capacity(MAX_PENDING);
        for _ in 0..MAX_PENDING {
            req_buffers.push(RequestBuffer {
                header: VirtioBlkReqHeader::default(),
                status: 0,
                in_use: false,
            });
        }

        Ok(Arc::new(Self {
            name: String::from(name),
            transport,
            queue,
            capacity,
            sector_size,
            read_only,
            features: driver_features,
            lock: Mutex::new(()),
            req_buffers: Mutex::new(req_buffers),
        }))
    }

    /// Allocate DMA-able memory using the kernel's buddy allocator.
    ///
    /// Returns the physical address of the allocated memory.
    /// The memory is zeroed before returning.
    fn alloc_dma_memory(size: usize) -> Result<u64, BlockError> {
        use mm::buddy_allocator;

        // Calculate number of 4KB pages needed
        let pages = (size + 4095) / 4096;

        // Allocate from buddy allocator
        let frame = buddy_allocator::alloc_physical_pages(pages)
            .ok_or(BlockError::NoMem)?;

        let phys_addr = frame.start_address().as_u64();

        // Zero the memory using high-half kernel mapping
        // Physical memory is mapped at PHYSICAL_MEMORY_OFFSET (0xffffffff80000000)
        unsafe {
            let virt_addr = (phys_addr + mm::PHYSICAL_MEMORY_OFFSET) as *mut u8;
            core::ptr::write_bytes(virt_addr, 0, pages * 4096);
        }

        Ok(phys_addr)
    }

    /// Notify the device of new available descriptors.
    fn notify(&self) {
        unsafe {
            self.transport.notify(0, self.queue.notify_off);
        }
    }

    /// Process a single synchronous request.
    fn do_request(&self, sector: u64, buf: &mut [u8], is_write: bool) -> Result<usize, BlockError> {
        if is_write && self.read_only {
            return Err(BlockError::ReadOnly);
        }

        // R28-2 Fix: Validate buffer alignment and capacity bounds
        if buf.is_empty() {
            return Err(BlockError::Invalid);
        }
        if (buf.len() as u32) % self.sector_size != 0 {
            return Err(BlockError::Invalid);
        }
        let sectors_count = (buf.len() as u64) / (self.sector_size as u64);
        let end_sector = sector.checked_add(sectors_count).ok_or(BlockError::Invalid)?;
        if end_sector > self.capacity {
            return Err(BlockError::Invalid);
        }

        let _lock = self.lock.lock();

        // Get a request buffer
        let buf_idx = {
            let mut buffers = self.req_buffers.lock();
            let idx = buffers.iter().position(|b| !b.in_use);
            match idx {
                Some(i) => {
                    buffers[i].in_use = true;
                    buffers[i].header.req_type = if is_write {
                        blk_types::VIRTIO_BLK_T_OUT
                    } else {
                        blk_types::VIRTIO_BLK_T_IN
                    };
                    buffers[i].header.reserved = 0;
                    buffers[i].header.sector = sector;
                    buffers[i].status = 0xFF; // Invalid status
                    i
                }
                None => return Err(BlockError::Busy),
            }
        };

        // R28-1 Fix: Convert virtual addresses to physical addresses for DMA
        // The device will DMA to these physical addresses, so we must translate them.
        let header_phys = {
            let buffers = self.req_buffers.lock();
            let header_ptr = &buffers[buf_idx].header as *const _ as *const u8;
            virt_to_phys_dma(header_ptr, core::mem::size_of::<VirtioBlkReqHeader>())?
        };
        let status_phys = {
            let buffers = self.req_buffers.lock();
            let status_ptr = &buffers[buf_idx].status as *const u8;
            virt_to_phys_dma(status_ptr, 1)?
        };
        let data_phys = virt_to_phys_dma(buf.as_ptr(), buf.len())?;

        // Allocate 3 descriptors
        let desc0 = self.queue.alloc_desc().ok_or(BlockError::Busy)?;
        let desc1 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                return Err(BlockError::Busy);
            }
        };
        let desc2 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                self.queue.free_desc(desc1);
                return Err(BlockError::Busy);
            }
        };

        unsafe {
            // Descriptor 0: Header (device reads)
            let d0 = self.queue.desc(desc0);
            d0.addr = header_phys;
            d0.len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
            d0.flags = VRING_DESC_F_NEXT;
            d0.next = desc1;

            // Descriptor 1: Data buffer
            let d1 = self.queue.desc(desc1);
            d1.addr = data_phys;
            d1.len = buf.len() as u32;
            d1.flags = VRING_DESC_F_NEXT | if is_write { 0 } else { VRING_DESC_F_WRITE };
            d1.next = desc2;

            // Descriptor 2: Status (device writes)
            let d2 = self.queue.desc(desc2);
            d2.addr = status_phys;
            d2.len = 1;
            d2.flags = VRING_DESC_F_WRITE;
            d2.next = 0;

            // Push to available ring
            self.queue.push_avail(desc0);
        }

        // Notify device
        mb();
        self.notify();

        // Poll for completion
        let mut timeout = 1_000_000u32;
        while !self.queue.has_used() && timeout > 0 {
            core::hint::spin_loop();
            timeout -= 1;
        }

        // Process completion
        let result = if let Some(used) = self.queue.pop_used() {
            // Free descriptors
            self.queue.free_desc(desc0);
            self.queue.free_desc(desc1);
            self.queue.free_desc(desc2);

            // Check status
            let status = {
                let buffers = self.req_buffers.lock();
                buffers[buf_idx].status
            };

            match status {
                blk_status::VIRTIO_BLK_S_OK => Ok(buf.len()),
                blk_status::VIRTIO_BLK_S_IOERR => Err(BlockError::Io),
                blk_status::VIRTIO_BLK_S_UNSUPP => Err(BlockError::NotSupported),
                _ => Err(BlockError::Io),
            }
        } else {
            // Timeout
            self.queue.free_desc(desc0);
            self.queue.free_desc(desc1);
            self.queue.free_desc(desc2);
            Err(BlockError::Io)
        };

        // Release buffer
        {
            let mut buffers = self.req_buffers.lock();
            buffers[buf_idx].in_use = false;
        }

        result
    }
}

impl BlockDevice for VirtioBlkDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn max_sectors_per_bio(&self) -> u32 {
        // Conservative limit for now
        128
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn submit_bio(&self, bio: Bio) -> Result<(), BlockError> {
        // For now, we only support synchronous operations
        // A proper implementation would queue the BIO
        Err(BlockError::NotSupported)
    }

    fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
        self.do_request(sector, buf, false)
    }

    fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, BlockError> {
        // Need mutable buffer for the interface, but we won't modify it
        let mut buf_copy = buf.to_vec();
        self.do_request(sector, &mut buf_copy, true)
    }

    fn flush(&self) -> Result<(), BlockError> {
        if self.features & blk_features::VIRTIO_BLK_F_FLUSH == 0 {
            return Ok(()); // No flush support, assume write-through
        }
        // TODO: Implement flush
        Ok(())
    }
}
