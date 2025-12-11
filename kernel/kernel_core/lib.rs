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
pub mod time;
pub mod scheduler_hook;
pub mod elf_loader;

pub use fork::{sys_fork, ForkError, ForkResult, PAGE_REF_COUNT, create_fresh_address_space};
pub use process::{register_ipc_cleanup, allocate_kernel_stack, kernel_stack_slot, KernelStackError, KSTACK_BASE, KSTACK_STRIDE, free_kernel_stack, free_address_space};
pub use time::{current_timestamp_ms, get_ticks, on_timer_tick};
pub use scheduler_hook::{
    register_timer_callback, register_resched_callback,
    on_scheduler_tick, reschedule_if_needed, force_reschedule,
    request_resched_from_irq,
};
pub use elf_loader::{load_elf, ElfLoadError, ElfLoadResult, USER_STACK_TOP, USER_STACK_SIZE};

pub fn init() {
    process::init(); // 必须最先初始化，确保 BOOT_CR3 被缓存
    time::init();
    println!("Kernel core module initialized");
}
