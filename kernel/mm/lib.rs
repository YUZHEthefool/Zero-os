#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub mod memory;
pub mod buddy_allocator;
pub mod page_table;

pub use page_table::{PageTableManager, MapError, UnmapError, UpdateFlagsError};

pub fn init() {
    println!("Memory management module initialized");
}
