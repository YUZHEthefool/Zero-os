#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

extern crate kernel_core;
extern crate lazy_static;
extern crate spin;

pub use kernel_core::process;

pub mod enhanced_scheduler;
pub mod lock_ordering;
pub mod scheduler;

pub fn init() {
    println!("Scheduler module initialized");
    enhanced_scheduler::init();
}

pub fn schedule() {
    // 简单的调度函数
}
