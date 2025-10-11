#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(naked_functions)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub mod interrupts;
pub mod context_switch;

pub use context_switch::{Context, switch_context, save_context, restore_context};

pub fn init() {
    println!("Arch module initialized");
}
