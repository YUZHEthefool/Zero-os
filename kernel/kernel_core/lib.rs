#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate，这会自动导入其导出的宏
#[macro_use]
extern crate drivers;

// 导出 vga_buffer 模块中的其他公共函数
pub use drivers::vga_buffer;

pub mod process;
pub mod syscall;
pub mod fork;

pub use fork::{sys_fork, ForkError, ForkResult};

pub fn init() {
    println!("Kernel core module initialized");
}
