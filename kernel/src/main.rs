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
    
    // VGA 缓冲区在物理地址 0xb8000
    // 由于页表映射 0xffffffff80000000 -> 物理0x0
    // 所以虚拟地址 0xffffffff800b8000 对应物理地址 0xb8000
    unsafe {
        let vga = 0xffffffff800b8000 as *mut u16;
        
        // 写入 "KERNEL!" 到屏幕第一行
        let msg = b"KERNEL!";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(i as isize) = (byte as u16) | (0x0A << 8);  // 绿色文字
        }
        
        // 写入 "SUCCESS" 到第二行
        let second_line = 80;
        let addr_msg = b"SUCCESS";
        for (i, &byte) in addr_msg.iter().enumerate() {
            *vga.offset((second_line + i) as isize) = (byte as u16) | (0x0E << 8);  // 黄色文字
        }
        
        serial_write_str("VGA write completed\n");
    }
    
    // 无限循环，使用 hlt 降低CPU使用率
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
