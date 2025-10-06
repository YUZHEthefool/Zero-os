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
mod interrupt_demo;

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
    // 最早期的调试：直接写 VGA，不依赖任何初始化
    unsafe {
        let vga = 0xb8000 as *mut u16;
        let msg = b"KERN>";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(i as isize) = (byte as u16) | (0x0F << 8);
        }
    }
    
    // ========================================
    // 阶段 1: 基础硬件初始化（不使用堆分配）
    // ========================================
    drivers::vga_buffer::init();
    drivers::vga_buffer::write_str("KERNEL: Booting...\n");
    
    // ========================================
    // 阶段 2: 内存管理初始化
    // ========================================
    // 初始化堆分配器 - 必须在任何使用 println! 的代码之前
    mm::memory::init();
    
    // ========================================
    // 阶段 3: 子系统初始化（现在可以安全使用 println!）
    // ========================================
    arch::init();
    mm::init();
    drivers::init();
    ipc::init();
    sched::init();
    kernel_core::init();
    
    // ========================================
    // 阶段 4: 高级功能初始化
    // ========================================
    arch::interrupts::init();
    kernel_core::syscall::init();
    sched::scheduler::init();
    
    // ========================================
    // 阶段 5: 启动完成
    // ========================================
    drivers::vga_buffer::clear_screen();
    drivers::vga_buffer::write_str("KERNEL OK\n\n");
    
    // 暂时禁用演示代码以诊断启动问题
    drivers::vga_buffer::write_str("Kernel successfully started!\n");
    drivers::vga_buffer::write_str("All subsystems initialized.\n");
    drivers::vga_buffer::write_str("\n");
    drivers::vga_buffer::write_str("Note: Demo code temporarily disabled for debugging.\n");
    drivers::vga_buffer::write_str("To enable demos, uncomment the demo calls in main.rs\n");
    
    // TODO: 取消注释以下代码来运行演示
    // demo::run_all_demos();
    // process_demo::run_all_demos();
    // syscall_demo::run_all_demos();
    // interrupt_demo::run_all_demos();
    
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
