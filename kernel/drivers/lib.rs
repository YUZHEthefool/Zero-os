#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

pub mod vga_buffer;

// 宏已经通过 #[macro_export] 在 crate 根部导出了，无需重新导出

pub fn init() {
    // 不使用 println! 宏，因为它还没有完全初始化
    // 驱动程序初始化静默完成
}
