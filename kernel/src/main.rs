#![no_std]
#![no_main]

use core::panic::PanicInfo;

// 引入模块化子系统
extern crate arch;
extern crate mm;
extern crate sched;
extern crate ipc;
extern crate drivers;
extern crate kernel_core;

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
    // 初始化硬件与子系统
    drivers::vga_buffer::init();
    drivers::vga_buffer::write_str("KERNEL: Started!\n");

    arch::interrupts::init();
    mm::memory::init();
    kernel_core::syscall::init();
    sched::scheduler::init();

    drivers::vga_buffer::clear_screen();
    drivers::vga_buffer::write_str("KERNEL OK\n");

    // 进入调度循环
    sched::scheduler::run();
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
