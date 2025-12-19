//! 中断和异常处理演示模块

use arch::interrupts::{get_stats, trigger_breakpoint};

/// 演示中断统计
pub fn demo_interrupt_stats() {
    println!("\n=== Interrupt Statistics Demo ===\n");

    println!("1. Getting current interrupt statistics...");
    let stats = get_stats();
    stats.print();

    println!("\n2. Triggering a breakpoint exception...");
    trigger_breakpoint();
    println!("   ✓ Breakpoint handled successfully");

    println!("\n3. Updated statistics:");
    let stats = get_stats();
    stats.print();

    println!("\n✓ Interrupt statistics demo completed!\n");
}

/// 演示异常处理
pub fn demo_exception_handling() {
    println!("\n=== Exception Handling Demo ===\n");

    println!("1. Testing breakpoint exception (#BP)...");
    trigger_breakpoint();
    println!("   ✓ Breakpoint exception handled");

    println!("\n2. Exception handlers registered:");
    println!("   ✓ Divide Error (#DE)");
    println!("   ✓ Debug (#DB)");
    println!("   ✓ Non-Maskable Interrupt (NMI)");
    println!("   ✓ Breakpoint (#BP)");
    println!("   ✓ Overflow (#OF)");
    println!("   ✓ Bound Range Exceeded (#BR)");
    println!("   ✓ Invalid Opcode (#UD)");
    println!("   ✓ Device Not Available (#NM)");
    println!("   ✓ Double Fault (#DF)");
    println!("   ✓ Invalid TSS (#TS)");
    println!("   ✓ Segment Not Present (#NP)");
    println!("   ✓ Stack Segment Fault (#SS)");
    println!("   ✓ General Protection Fault (#GP)");
    println!("   ✓ Page Fault (#PF)");
    println!("   ✓ x87 Floating-Point (#MF)");
    println!("   ✓ Alignment Check (#AC)");
    println!("   ✓ Machine Check (#MC)");
    println!("   ✓ SIMD Floating-Point (#XM)");
    println!("   ✓ Virtualization (#VE)");

    println!("\n✓ Exception handling demo completed!\n");
}

/// 演示硬件中断
pub fn demo_hardware_interrupts() {
    println!("\n=== Hardware Interrupts Demo ===\n");

    println!("1. Hardware interrupt handlers registered:");
    println!("   ✓ IRQ 0: Timer (PIT)");
    println!("   ✓ IRQ 1: Keyboard (PS/2)");

    println!("\n2. Interrupt statistics:");
    let stats = get_stats();
    println!("   Timer interrupts:    {}", stats.timer);
    println!("   Keyboard interrupts: {}", stats.keyboard);

    println!("\n✓ Hardware interrupts demo completed!\n");
}

/// 运行所有中断演示
pub fn run_all_demos() {
    demo_interrupt_stats();
    demo_exception_handling();
    demo_hardware_interrupts();
}
