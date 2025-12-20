#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub mod context_switch;
pub mod cpu_protection;
pub mod gdt;
pub mod interrupts;
pub mod syscall;

pub use context_switch::{
    enter_usermode, init_fpu, jump_to_usermode, restore_context, save_context, switch_context,
    Context, FxSaveArea, USER_CODE_SELECTOR, USER_DATA_SELECTOR,
};
pub use cpu_protection::{check_cpu_features, enable_protections, CpuProtectionStatus};
pub use gdt::{
    default_kernel_stack_top, get_kernel_stack, init as init_gdt, selectors, set_ist_stack,
    set_kernel_stack, Selectors, DOUBLE_FAULT_IST_INDEX, DOUBLE_FAULT_STACK_SIZE,
    KERNEL_STACK_SIZE,
};
pub use syscall::{
    get_current_syscall_frame, init_syscall_msr, is_initialized as syscall_initialized,
    register_frame_callback, SyscallFrame,
};

// Re-export cpu_local from the cpu_local crate for backwards compatibility
pub use cpu_local::{current_cpu_id, max_cpus, CpuLocal};

pub fn init() {
    gdt::init();
    context_switch::init_fpu();
    syscall::register_frame_callback(); // 注册 syscall 帧回调
    println!("Arch module initialized (FPU/SIMD enabled)");
}
