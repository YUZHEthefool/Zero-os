use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::PhysFrame,
    PhysAddr,
};
use crate::buddy_allocator;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_START: usize = 0x4444_4444_0000;
const HEAP_SIZE: usize = 8 * 1024 * 1024; // 升级到8MB堆

/// 物理内存管理起始地址（在256MB处）
const PHYS_MEM_START: u64 = 0x10000000;
/// 物理内存管理大小（64MB）
const PHYS_MEM_SIZE: usize = 64 * 1024 * 1024;

pub fn init() {
    // 初始化堆分配器
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
    println!("Heap allocator initialized: {} MB at 0x{:x}", HEAP_SIZE / (1024 * 1024), HEAP_START);
    
    // 初始化Buddy物理页分配器
    buddy_allocator::init_buddy_allocator(
        PhysAddr::new(PHYS_MEM_START),
        PHYS_MEM_SIZE
    );
    
    // 运行自测（可选）
    #[cfg(debug_assertions)]
    buddy_allocator::run_self_test();
    
    println!("Memory manager fully initialized");
}

/// 改进的物理帧分配器（使用Buddy分配器）
pub struct FrameAllocator;

impl FrameAllocator {
    pub fn new() -> Self {
        FrameAllocator
    }
    
    /// 分配单个物理帧
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        buddy_allocator::alloc_physical_pages(1)
    }
    
    /// 分配连续的多个物理帧
    pub fn allocate_contiguous_frames(&mut self, count: usize) -> Option<PhysFrame> {
        buddy_allocator::alloc_physical_pages(count)
    }
    
    /// 释放物理帧
    pub fn deallocate_frame(&mut self, frame: PhysFrame) {
        buddy_allocator::free_physical_pages(frame, 1);
    }
    
    /// 释放连续的多个物理帧
    pub fn deallocate_contiguous_frames(&mut self, frame: PhysFrame, count: usize) {
        buddy_allocator::free_physical_pages(frame, count);
    }
    
    /// 获取内存统计信息
    pub fn stats(&self) -> MemoryStats {
        let buddy_stats = buddy_allocator::get_allocator_stats()
            .unwrap_or(buddy_allocator::AllocatorStats {
                total_pages: 0,
                free_pages: 0,
                used_pages: 0,
                fragmentation: 0.0,
            });
            
        MemoryStats {
            total_physical_pages: buddy_stats.total_pages,
            free_physical_pages: buddy_stats.free_pages,
            used_physical_pages: buddy_stats.used_pages,
            fragmentation_percent: (buddy_stats.fragmentation * 100.0) as u32,
            heap_used_bytes: HEAP_SIZE - unsafe {
                ALLOCATOR.lock().free()
            },
            heap_total_bytes: HEAP_SIZE,
        }
    }
}

/// 内存统计信息
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    pub total_physical_pages: usize,
    pub free_physical_pages: usize,
    pub used_physical_pages: usize,
    pub fragmentation_percent: u32,
    pub heap_used_bytes: usize,
    pub heap_total_bytes: usize,
}

impl MemoryStats {
    /// 打印内存统计信息
    pub fn print(&self) {
        println!("=== Memory Statistics ===");
        println!("Physical Memory:");
        println!("  Total: {} pages ({} MB)",
            self.total_physical_pages,
            self.total_physical_pages * 4 / 1024);
        println!("  Free:  {} pages ({} MB)",
            self.free_physical_pages,
            self.free_physical_pages * 4 / 1024);
        println!("  Used:  {} pages ({} MB)",
            self.used_physical_pages,
            self.used_physical_pages * 4 / 1024);
        println!("  Fragmentation: {}%", self.fragmentation_percent);
        println!("Kernel Heap:");
        println!("  Used:  {} KB / {} KB",
            self.heap_used_bytes / 1024,
            self.heap_total_bytes / 1024);
    }
}
