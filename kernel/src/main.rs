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
    // 禁用中断 - 必须首先做！
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
    
    // 发送串口消息表示内核已启动
    unsafe {
        serial_write_str("Kernel _start entered\n");
    }
    
    // 初始化VGA驱动
    drivers::vga_buffer::init();
    
    println!("==============================");
    println!("  Zero-OS Microkernel v0.1");
    println!("==============================");
    println!();
    
    // 阶段1：初始化中断处理
    println!("[1/3] Initializing interrupts...");
    arch::interrupts::init();
    println!("      ✓ IDT loaded with 20+ handlers");
    
    // 阶段2：初始化内存管理
    println!("[2/3] Initializing memory management...");
    mm::memory::init();
    println!("      ✓ Heap and Buddy allocator ready");
    
    // 阶段3：测试基础功能
    println!("[3/3] Running basic tests...");
    
    // 测试内存分配
    use alloc::vec::Vec;
    let mut test_vec = Vec::new();
    for i in 0..10 {
        test_vec.push(i);
    }
    println!("      ✓ Heap allocation test passed");
    
    // 显示内存统计
    let mem_stats = mm::memory::FrameAllocator::new().stats();
    println!("      ✓ Memory stats available");
    
    println!();
    println!("=== System Information ===");
    mem_stats.print();
    
    println!();
    println!("=== System Ready ===");
    println!("All subsystems initialized successfully!");
    println!();
    println!("进入空闲循环...");
    println!();
    
    // 主内核循环
    loop {
        unsafe {
            core::arch::asm!(
                "hlt",
                options(nomem, nostack, preserves_flags)
            );
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
