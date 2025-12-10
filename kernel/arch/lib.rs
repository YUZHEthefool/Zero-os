#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(naked_functions)]
#![feature(raw_ref_op)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;
extern crate sched;

pub mod gdt;
pub mod interrupts;
pub mod context_switch;

pub use context_switch::{Context, FxSaveArea, switch_context, save_context, restore_context, init_fpu};
pub use gdt::{init as init_gdt, set_kernel_stack, set_ist_stack, selectors, Selectors, DOUBLE_FAULT_IST_INDEX, KERNEL_STACK_SIZE, DOUBLE_FAULT_STACK_SIZE};

pub fn init() {
    gdt::init();
    context_switch::init_fpu();
    println!("Arch module initialized (FPU/SIMD enabled)");
}
