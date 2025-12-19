#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub mod buddy_allocator;
pub mod memory;
pub mod page_table;

pub use memory::{BootInfo, FrameAllocator, MemoryMapInfo};
pub use page_table::{
    phys_to_virt, with_current_manager, MapError, PageTableManager, UnmapError, UpdateFlagsError,
    PHYSICAL_MEMORY_OFFSET,
};

pub fn init() {
    println!("Memory management module initialized");
}
