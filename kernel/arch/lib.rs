#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub mod gdt;
pub mod interrupts;
pub mod context_switch;
pub mod cpu_protection;
pub mod syscall;

pub use context_switch::{Context, FxSaveArea, switch_context, save_context, restore_context, init_fpu, enter_usermode, jump_to_usermode, USER_CODE_SELECTOR, USER_DATA_SELECTOR};
pub use gdt::{init as init_gdt, set_kernel_stack, get_kernel_stack, set_ist_stack, selectors, Selectors, DOUBLE_FAULT_IST_INDEX, KERNEL_STACK_SIZE, DOUBLE_FAULT_STACK_SIZE, default_kernel_stack_top};
pub use cpu_protection::{CpuProtectionStatus, check_cpu_features, enable_protections};
pub use syscall::{init_syscall_msr, is_initialized as syscall_initialized};

// Re-export cpu_local from the cpu_local crate for backwards compatibility
pub use cpu_local::{CpuLocal, current_cpu_id, max_cpus};

pub fn init() {
    gdt::init();
    context_switch::init_fpu();
    println!("Arch module initialized (FPU/SIMD enabled)");
}
