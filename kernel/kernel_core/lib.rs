#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate，这会自动导入其导出的宏
#[macro_use]
extern crate drivers;

// 导出 vga_buffer 模块中的其他公共函数
pub use drivers::vga_buffer;

pub mod elf_loader;
pub mod fork;
pub mod process;
pub mod scheduler_hook;
pub mod signal;
pub mod syscall;
pub mod time;
pub mod usercopy;

pub use elf_loader::{load_elf, ElfLoadError, ElfLoadResult, USER_STACK_SIZE, USER_STACK_TOP};
pub use fork::{create_fresh_address_space, sys_fork, ForkError, ForkResult, PAGE_REF_COUNT};
pub use process::{
    add_supplementary_group,
    allocate_kernel_stack,
    current_credentials,
    current_egid,
    current_euid,
    current_supplementary_groups,
    current_umask,
    free_address_space,
    free_kernel_stack,
    kernel_stack_slot,
    register_ipc_cleanup,
    remove_supplementary_group,
    set_current_supplementary_groups,
    set_current_umask,
    // DAC support
    Credentials,
    FileDescriptor,
    FileOps,
    KernelStackError,
    KSTACK_BASE,
    KSTACK_STRIDE,
    MAX_FD,
    NGROUPS_MAX,
};
pub use scheduler_hook::{
    force_reschedule, on_scheduler_tick, register_resched_callback, register_timer_callback,
    request_resched_from_irq, reschedule_if_needed,
};
pub use signal::{
    default_action, register_resume_callback, send_signal, signal_name, PendingSignals, Signal,
    SignalAction, SignalError,
};
pub use syscall::{
    register_fd_close_callback, register_fd_read_callback, register_fd_write_callback,
    register_futex_callback, register_pipe_callback, register_vfs_lseek_callback,
    register_vfs_open_callback, register_vfs_stat_callback, wake_stdin_waiters, SyscallError,
    VfsStat,
};
pub use time::{current_timestamp_ms, get_ticks, on_timer_tick};

pub fn init() {
    process::init(); // 必须最先初始化，确保 BOOT_CR3 被缓存
    time::init();
    println!("Kernel core module initialized");
}
