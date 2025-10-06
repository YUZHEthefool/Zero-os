//! 中断和异常处理
//! 
//! 实现完整的x86_64中断描述符表（IDT）和异常处理器

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use lazy_static::lazy_static;
use spin::Mutex;

/// 中断统计信息
#[derive(Debug, Default, Clone, Copy)]
pub struct InterruptStats {
    pub breakpoint: u64,
    pub page_fault: u64,
    pub double_fault: u64,
    pub general_protection_fault: u64,
    pub invalid_opcode: u64,
    pub divide_error: u64,
    pub overflow: u64,
    pub bound_range_exceeded: u64,
    pub invalid_tss: u64,
    pub segment_not_present: u64,
    pub stack_segment_fault: u64,
    pub alignment_check: u64,
    pub machine_check: u64,
    pub simd_floating_point: u64,
    pub virtualization: u64,
    pub timer: u64,
    pub keyboard: u64,
}

impl InterruptStats {
    pub fn print(&self) {
        println!("=== Interrupt Statistics ===");
        println!("Exceptions:");
        println!("  Breakpoint:       {}", self.breakpoint);
        println!("  Page Fault:       {}", self.page_fault);
        println!("  Double Fault:     {}", self.double_fault);
        println!("  GP Fault:         {}", self.general_protection_fault);
        println!("  Invalid Opcode:   {}", self.invalid_opcode);
        println!("  Divide Error:     {}", self.divide_error);
        println!("Hardware Interrupts:");
        println!("  Timer:            {}", self.timer);
        println!("  Keyboard:         {}", self.keyboard);
    }
}

lazy_static! {
    /// 全局中断描述符表
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        
        // CPU异常处理器 (0-31)
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.debug.set_handler_fn(debug_handler);
        idt.non_maskable_interrupt.set_handler_fn(nmi_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.overflow.set_handler_fn(overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(bound_range_exceeded_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        idt.segment_not_present.set_handler_fn(segment_not_present_handler);
        idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
        idt.alignment_check.set_handler_fn(alignment_check_handler);
        idt.machine_check.set_handler_fn(machine_check_handler);
        idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);
        idt.virtualization.set_handler_fn(virtualization_handler);
        
        // 硬件中断处理器 (32-255)
        idt[32].set_handler_fn(timer_interrupt_handler);      // IRQ 0: Timer
        idt[33].set_handler_fn(keyboard_interrupt_handler);   // IRQ 1: Keyboard
        
        idt
    };
    
    /// 中断统计
    static ref INTERRUPT_STATS: Mutex<InterruptStats> = Mutex::new(InterruptStats::default());
}

/// 初始化中断处理
pub fn init() {
    IDT.load();
    println!("Interrupt Descriptor Table (IDT) loaded");
    println!("  Exception handlers: 20");
    println!("  Hardware interrupt handlers: 2");
}

/// 获取中断统计信息
pub fn get_stats() -> InterruptStats {
    *INTERRUPT_STATS.lock()
}

// ============================================================================
// CPU异常处理器 (0-31)
// ============================================================================

/// #DE - Divide Error (除法错误)
extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().divide_error += 1;
    println!("\n!!! EXCEPTION: DIVIDE ERROR (#DE) !!!");
    println!("Instruction Pointer: {:#x}", stack_frame.instruction_pointer);
    println!("{:#?}", stack_frame);
    panic!("Divide by zero or division overflow");
}

/// #DB - Debug Exception (调试异常)
extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    println!("\n--- DEBUG EXCEPTION (#DB) ---");
    println!("{:#?}", stack_frame);
}

/// #NMI - Non-Maskable Interrupt (不可屏蔽中断)
extern "x86-interrupt" fn nmi_handler(stack_frame: InterruptStackFrame) {
    println!("\n!!! NON-MASKABLE INTERRUPT (NMI) !!!");
    println!("{:#?}", stack_frame);
}

/// #BP - Breakpoint (断点)
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().breakpoint += 1;
    println!("\n--- BREAKPOINT (#BP) ---");
    println!("Instruction Pointer: {:#x}", stack_frame.instruction_pointer);
}

/// #OF - Overflow (溢出)
extern "x86-interrupt" fn overflow_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().overflow += 1;
    println!("\n!!! EXCEPTION: OVERFLOW (#OF) !!!");
    println!("{:#?}", stack_frame);
    panic!("Arithmetic overflow");
}

/// #BR - Bound Range Exceeded (边界范围超出)
extern "x86-interrupt" fn bound_range_exceeded_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().bound_range_exceeded += 1;
    println!("\n!!! EXCEPTION: BOUND RANGE EXCEEDED (#BR) !!!");
    println!("{:#?}", stack_frame);
    panic!("Bound range exceeded");
}

/// #UD - Invalid Opcode (无效操作码)
extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().invalid_opcode += 1;
    println!("\n!!! EXCEPTION: INVALID OPCODE (#UD) !!!");
    println!("Instruction Pointer: {:#x}", stack_frame.instruction_pointer);
    println!("{:#?}", stack_frame);
    panic!("Invalid or undefined opcode");
}

/// #NM - Device Not Available (设备不可用)
extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    println!("\n!!! EXCEPTION: DEVICE NOT AVAILABLE (#NM) !!!");
    println!("{:#?}", stack_frame);
    panic!("FPU or SIMD device not available");
}

/// #DF - Double Fault (双重错误)
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    INTERRUPT_STATS.lock().double_fault += 1;
    println!("\n!!! FATAL: DOUBLE FAULT (#DF) !!!");
    println!("Error Code: {:#x}", error_code);
    println!("{:#?}", stack_frame);
    panic!("Double fault - system halted");
}

/// #TS - Invalid TSS (无效TSS)
extern "x86-interrupt" fn invalid_tss_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().invalid_tss += 1;
    println!("\n!!! EXCEPTION: INVALID TSS (#TS) !!!");
    println!("Error Code: {:#x}", error_code);
    println!("{:#?}", stack_frame);
    panic!("Invalid Task State Segment");
}

/// #NP - Segment Not Present (段不存在)
extern "x86-interrupt" fn segment_not_present_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().segment_not_present += 1;
    println!("\n!!! EXCEPTION: SEGMENT NOT PRESENT (#NP) !!!");
    println!("Error Code: {:#x}", error_code);
    println!("{:#?}", stack_frame);
    panic!("Segment not present");
}

/// #SS - Stack Segment Fault (栈段错误)
extern "x86-interrupt" fn stack_segment_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().stack_segment_fault += 1;
    println!("\n!!! EXCEPTION: STACK SEGMENT FAULT (#SS) !!!");
    println!("Error Code: {:#x}", error_code);
    println!("{:#?}", stack_frame);
    panic!("Stack segment fault");
}

/// #GP - General Protection Fault (一般保护错误)
extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().general_protection_fault += 1;
    println!("\n!!! EXCEPTION: GENERAL PROTECTION FAULT (#GP) !!!");
    println!("Error Code: {:#x}", error_code);
    println!("Instruction Pointer: {:#x}", stack_frame.instruction_pointer);
    println!("{:#?}", stack_frame);
    
    // 解析错误码
    if error_code != 0 {
        let external = (error_code & 0x1) != 0;
        let table = (error_code >> 1) & 0x3;
        let index = (error_code >> 3) & 0x1FFF;
        
        println!("Error Details:");
        println!("  External: {}", external);
        println!("  Table: {} ({})", table, match table {
            0 => "GDT",
            1 | 3 => "IDT",
            2 => "LDT",
            _ => "Unknown",
        });
        println!("  Index: {:#x}", index);
    }
    
    panic!("General protection fault");
}

/// #PF - Page Fault (页错误)
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    
    INTERRUPT_STATS.lock().page_fault += 1;
    
    let accessed_address = Cr2::read();
    
    println!("\n!!! EXCEPTION: PAGE FAULT (#PF) !!!");
    println!("Accessed Address: {:?}", accessed_address);
    println!("Error Code: {:?}", error_code);
    println!("  Present: {}", error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION));
    println!("  Write: {}", error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE));
    println!("  User: {}", error_code.contains(PageFaultErrorCode::USER_MODE));
    println!("  Reserved Write: {}", error_code.contains(PageFaultErrorCode::MALFORMED_TABLE));
    println!("  Instruction Fetch: {}", error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH));
    println!("Instruction Pointer: {:#x}", stack_frame.instruction_pointer);
    println!("{:#?}", stack_frame);
    
    panic!("Page fault");
}

/// #MF - x87 Floating-Point Exception (x87浮点异常)
extern "x86-interrupt" fn x87_floating_point_handler(stack_frame: InterruptStackFrame) {
    println!("\n!!! EXCEPTION: x87 FLOATING-POINT (#MF) !!!");
    println!("{:#?}", stack_frame);
    panic!("x87 floating-point exception");
}

/// #AC - Alignment Check (对齐检查)
extern "x86-interrupt" fn alignment_check_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    INTERRUPT_STATS.lock().alignment_check += 1;
    println!("\n!!! EXCEPTION: ALIGNMENT CHECK (#AC) !!!");
    println!("Error Code: {:#x}", error_code);
    println!("{:#?}", stack_frame);
    panic!("Alignment check failed");
}

/// #MC - Machine Check (机器检查)
extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    INTERRUPT_STATS.lock().machine_check += 1;
    println!("\n!!! FATAL: MACHINE CHECK (#MC) !!!");
    println!("{:#?}", stack_frame);
    panic!("Machine check - hardware error");
}

/// #XM - SIMD Floating-Point Exception (SIMD浮点异常)
extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().simd_floating_point += 1;
    println!("\n!!! EXCEPTION: SIMD FLOATING-POINT (#XM) !!!");
    println!("{:#?}", stack_frame);
    panic!("SIMD floating-point exception");
}

/// #VE - Virtualization Exception (虚拟化异常)
extern "x86-interrupt" fn virtualization_handler(stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().virtualization += 1;
    println!("\n!!! EXCEPTION: VIRTUALIZATION (#VE) !!!");
    println!("{:#?}", stack_frame);
    panic!("Virtualization exception");
}

// ============================================================================
// 硬件中断处理器 (32-255)
// ============================================================================

/// IRQ 0 - Timer Interrupt (定时器中断)
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().timer += 1;
    
    // 调用调度器的tick函数
    // sched::scheduler::tick();
    
    // 发送EOI (End of Interrupt)
    unsafe {
        // 向PIC发送EOI信号
        // 这里简化处理，实际应该使用APIC
        core::arch::asm!("mov al, 0x20; out 0x20, al", options(nostack, nomem));
    }
}

/// IRQ 1 - Keyboard Interrupt (键盘中断)
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.lock().keyboard += 1;
    
    // 读取键盘扫描码
    let scancode: u8 = unsafe {
        let mut scancode: u8;
        core::arch::asm!("in al, 0x60", out("al") scancode, options(nostack, nomem));
        scancode
    };
    
    // 简单的键盘处理（可以扩展）
    if scancode < 0x80 {
        // 按键按下
        println!("Key pressed: scancode {:#x}", scancode);
    }
    
    // 发送EOI
    unsafe {
        core::arch::asm!("mov al, 0x20; out 0x20, al", options(nostack, nomem));
    }
}

/// 触发断点异常（用于测试）
pub fn trigger_breakpoint() {
    x86_64::instructions::interrupts::int3();
}

/// 触发页错误（用于测试）
pub fn trigger_page_fault() {
    unsafe {
        let ptr = 0xdeadbeef as *mut u8;
        *ptr = 42;
    }
}
