#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;
use core::panic::PanicInfo;

// 引入模块化子系统，drivers需要在最前面以便使用其宏
#[macro_use]
extern crate drivers;
extern crate arch;
extern crate mm;
extern crate sched;
extern crate ipc;
extern crate kernel_core;

// 演示模块
mod demo;
mod process_demo;
mod syscall_demo;

// 串口端口
const SERIAL_PORT: u16 = 0x3F8;

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
    );
}

unsafe fn serial_write_byte(byte: u8) {
    outb(SERIAL_PORT, byte);
}

unsafe fn serial_write_str(s: &str) {
    for byte in s.bytes() {
        serial_write_byte(byte);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 初始化各个子系统
    arch::init();
    mm::init();
    drivers::init();
    ipc::init();
    sched::init();
    kernel_core::init();

    // 初始化硬件与子系统
    drivers::vga_buffer::init();
    drivers::vga_buffer::write_str("KERNEL: Started!\n");

    arch::interrupts::init();
    mm::memory::init();
    kernel_core::syscall::init();
    sched::scheduler::init();

    drivers::vga_buffer::clear_screen();
    drivers::vga_buffer::write_str("KERNEL OK\n\n");
    
    // 运行内存管理演示
    drivers::vga_buffer::write_str("=== Memory Management Demos ===\n");
    demo::run_all_demos();
    
    // 运行进程管理演示
    drivers::vga_buffer::write_str("\n=== Process Management Demos ===\n");
    process_demo::run_all_demos();
    
    // 运行系统调用演示
    drivers::vga_buffer::write_str("\n=== System Call Demos ===\n");
    syscall_demo::run_all_demos();
    
    drivers::vga_buffer::write_str("\n=== All demos completed ===\n");
    drivers::vga_buffer::write_str("\nEntering kernel main loop...\n");

    // 内核主循环
    loop {
        sched::schedule();
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("Allocation error: {:?}", layout);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        serial_write_str("KERNEL PANIC: ");
        if let Some(location) = info.location() {
            // 简单地输出位置信息
            serial_write_str(location.file());
        }
        serial_write_str("\n");
    }
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
