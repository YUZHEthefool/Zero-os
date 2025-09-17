#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub use kernel_core::process;

pub mod ipc;

pub fn init() {
    println!("IPC module initialized");
}
