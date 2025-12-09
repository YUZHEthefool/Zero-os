//! 中断和异常处理
//!
//! 实现完整的x86_64中断描述符表（IDT）和异常处理器

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use lazy_static::lazy_static;

/// 中断统计信息快照（用于外部查询）
#[derive(Debug, Default, Clone, Copy)]
pub struct InterruptStatsSnapshot {
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

impl InterruptStatsSnapshot {
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

/// 原子中断统计计数器（用于中断处理程序内部，避免死锁）
struct AtomicInterruptStats {
    breakpoint: AtomicU64,
    page_fault: AtomicU64,
    double_fault: AtomicU64,
    general_protection_fault: AtomicU64,
    invalid_opcode: AtomicU64,
    divide_error: AtomicU64,
    overflow: AtomicU64,
    bound_range_exceeded: AtomicU64,
    invalid_tss: AtomicU64,
    segment_not_present: AtomicU64,
    stack_segment_fault: AtomicU64,
    alignment_check: AtomicU64,
    machine_check: AtomicU64,
    simd_floating_point: AtomicU64,
    virtualization: AtomicU64,
    timer: AtomicU64,
    keyboard: AtomicU64,
}

impl AtomicInterruptStats {
    const fn new() -> Self {
        Self {
            breakpoint: AtomicU64::new(0),
            page_fault: AtomicU64::new(0),
            double_fault: AtomicU64::new(0),
            general_protection_fault: AtomicU64::new(0),
            invalid_opcode: AtomicU64::new(0),
            divide_error: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            bound_range_exceeded: AtomicU64::new(0),
            invalid_tss: AtomicU64::new(0),
            segment_not_present: AtomicU64::new(0),
            stack_segment_fault: AtomicU64::new(0),
            alignment_check: AtomicU64::new(0),
            machine_check: AtomicU64::new(0),
            simd_floating_point: AtomicU64::new(0),
            virtualization: AtomicU64::new(0),
            timer: AtomicU64::new(0),
            keyboard: AtomicU64::new(0),
        }
    }

    /// 获取当前统计的快照
    fn snapshot(&self) -> InterruptStatsSnapshot {
        InterruptStatsSnapshot {
            breakpoint: self.breakpoint.load(Ordering::Relaxed),
            page_fault: self.page_fault.load(Ordering::Relaxed),
            double_fault: self.double_fault.load(Ordering::Relaxed),
            general_protection_fault: self.general_protection_fault.load(Ordering::Relaxed),
            invalid_opcode: self.invalid_opcode.load(Ordering::Relaxed),
            divide_error: self.divide_error.load(Ordering::Relaxed),
            overflow: self.overflow.load(Ordering::Relaxed),
            bound_range_exceeded: self.bound_range_exceeded.load(Ordering::Relaxed),
            invalid_tss: self.invalid_tss.load(Ordering::Relaxed),
            segment_not_present: self.segment_not_present.load(Ordering::Relaxed),
            stack_segment_fault: self.stack_segment_fault.load(Ordering::Relaxed),
            alignment_check: self.alignment_check.load(Ordering::Relaxed),
            machine_check: self.machine_check.load(Ordering::Relaxed),
            simd_floating_point: self.simd_floating_point.load(Ordering::Relaxed),
            virtualization: self.virtualization.load(Ordering::Relaxed),
            timer: self.timer.load(Ordering::Relaxed),
            keyboard: self.keyboard.load(Ordering::Relaxed),
        }
    }
}

/// 全局原子中断统计（避免中断处理程序中的锁争用）
static INTERRUPT_STATS: AtomicInterruptStats = AtomicInterruptStats::new();

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
}

/// 初始化中断处理
pub fn init() {
    // 初始化 8259 PIC，重映射 IRQ 向量避免与 CPU 异常冲突
    unsafe { pic_init(); }

    // 加载中断描述符表
    IDT.load();

    println!("Interrupt Descriptor Table (IDT) loaded");
    println!("  Exception handlers: 20");
    println!("  Hardware interrupt handlers: 2 (Timer, Keyboard)");
}

/// 获取中断统计信息
pub fn get_stats() -> InterruptStatsSnapshot {
    INTERRUPT_STATS.snapshot()
}

// ============================================================================
// CPU异常处理器 (0-31)
// ============================================================================

/// #DE - Divide Error (除法错误)
extern "x86-interrupt" fn divide_error_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.divide_error.fetch_add(1, Ordering::Relaxed);
    // 注意：中断处理程序中不使用 println! 以避免死锁
    panic!("Divide by zero or division overflow");
}

/// #DB - Debug Exception (调试异常)
extern "x86-interrupt" fn debug_handler(_stack_frame: InterruptStackFrame) {
    // 调试异常：静默处理
}

/// #NMI - Non-Maskable Interrupt (不可屏蔽中断)
extern "x86-interrupt" fn nmi_handler(_stack_frame: InterruptStackFrame) {
    // NMI：可能是硬件错误，静默处理
}

/// #BP - Breakpoint (断点)
extern "x86-interrupt" fn breakpoint_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.breakpoint.fetch_add(1, Ordering::Relaxed);
    // 断点异常：通常用于调试，静默处理
}

/// #OF - Overflow (溢出)
extern "x86-interrupt" fn overflow_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.overflow.fetch_add(1, Ordering::Relaxed);
    panic!("Arithmetic overflow");
}

/// #BR - Bound Range Exceeded (边界范围超出)
extern "x86-interrupt" fn bound_range_exceeded_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.bound_range_exceeded.fetch_add(1, Ordering::Relaxed);
    panic!("Bound range exceeded");
}

/// #UD - Invalid Opcode (无效操作码)
extern "x86-interrupt" fn invalid_opcode_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.invalid_opcode.fetch_add(1, Ordering::Relaxed);
    panic!("Invalid or undefined opcode");
}

/// #NM - Device Not Available (设备不可用)
extern "x86-interrupt" fn device_not_available_handler(_stack_frame: InterruptStackFrame) {
    panic!("FPU or SIMD device not available");
}

/// #DF - Double Fault (双重错误)
extern "x86-interrupt" fn double_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    INTERRUPT_STATS.double_fault.fetch_add(1, Ordering::Relaxed);
    panic!("Double fault - system halted");
}

/// #TS - Invalid TSS (无效TSS)
extern "x86-interrupt" fn invalid_tss_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    INTERRUPT_STATS.invalid_tss.fetch_add(1, Ordering::Relaxed);
    panic!("Invalid Task State Segment");
}

/// #NP - Segment Not Present (段不存在)
extern "x86-interrupt" fn segment_not_present_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    INTERRUPT_STATS.segment_not_present.fetch_add(1, Ordering::Relaxed);
    panic!("Segment not present");
}

/// #SS - Stack Segment Fault (栈段错误)
extern "x86-interrupt" fn stack_segment_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    INTERRUPT_STATS.stack_segment_fault.fetch_add(1, Ordering::Relaxed);
    panic!("Stack segment fault");
}

/// #GP - General Protection Fault (一般保护错误)
extern "x86-interrupt" fn general_protection_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    INTERRUPT_STATS.general_protection_fault.fetch_add(1, Ordering::Relaxed);
    panic!("General protection fault");
}

/// #PF - Page Fault (页错误)
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    INTERRUPT_STATS.page_fault.fetch_add(1, Ordering::Relaxed);

    // 获取导致缺页的地址
    let fault_addr = Cr2::read()
        .unwrap_or_else(|_| panic!("Invalid CR2 address"))
        .as_u64() as usize;

    // 检查是否为写入导致的保护违规缺页（可能是 COW）
    // PROTECTION_VIOLATION 表示页面存在但权限不足，区别于页面不存在的情况
    if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE)
        && error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION)
    {
        if let Some(pid) = kernel_core::process::current_pid() {
            // 尝试处理 COW 缺页
            if unsafe { kernel_core::fork::handle_cow_page_fault(pid, fault_addr).is_ok() } {
                return; // COW 已修复，返回继续执行
            }
        }
    }

    // 无法处理的缺页错误
    panic!(
        "Page fault at 0x{:x} ({:?})\n{:#?}",
        fault_addr, error_code, stack_frame
    );
}

/// #MF - x87 Floating-Point Exception (x87浮点异常)
extern "x86-interrupt" fn x87_floating_point_handler(_stack_frame: InterruptStackFrame) {
    panic!("x87 floating-point exception");
}

/// #AC - Alignment Check (对齐检查)
extern "x86-interrupt" fn alignment_check_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    INTERRUPT_STATS.alignment_check.fetch_add(1, Ordering::Relaxed);
    panic!("Alignment check failed");
}

/// #MC - Machine Check (机器检查)
extern "x86-interrupt" fn machine_check_handler(_stack_frame: InterruptStackFrame) -> ! {
    INTERRUPT_STATS.machine_check.fetch_add(1, Ordering::Relaxed);
    panic!("Machine check - hardware error");
}

/// #XM - SIMD Floating-Point Exception (SIMD浮点异常)
extern "x86-interrupt" fn simd_floating_point_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.simd_floating_point.fetch_add(1, Ordering::Relaxed);
    panic!("SIMD floating-point exception");
}

/// #VE - Virtualization Exception (虚拟化异常)
extern "x86-interrupt" fn virtualization_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.virtualization.fetch_add(1, Ordering::Relaxed);
    panic!("Virtualization exception");
}

// ============================================================================
// 硬件中断处理器 (32-255)
// ============================================================================

/// IRQ 0 - Timer Interrupt (定时器中断)
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.timer.fetch_add(1, Ordering::Relaxed);

    // 更新系统时钟计数器
    kernel_core::on_timer_tick();

    // TODO: 调用调度器的 tick 函数
    // sched::scheduler::tick();

    // 发送 EOI (End of Interrupt) 到 PIC
    unsafe {
        core::arch::asm!("mov al, 0x20; out 0x20, al", options(nostack, nomem));
    }
}

/// IRQ 1 - Keyboard Interrupt (键盘中断)
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    INTERRUPT_STATS.keyboard.fetch_add(1, Ordering::Relaxed);

    // 读取并丢弃键盘扫描码（清除中断）
    unsafe {
        let _scancode: u8;
        core::arch::asm!("in al, 0x60", out("al") _scancode, options(nostack, nomem));
    }

    // 发送 EOI 到 PIC
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

// ============================================================================
// 8259 PIC (Programmable Interrupt Controller) 支持
// ============================================================================

/// PIC 端口定义
const PIC1_CMD: u16 = 0x20;   // 主 PIC 命令端口
const PIC1_DATA: u16 = 0x21;  // 主 PIC 数据端口
const PIC2_CMD: u16 = 0xA0;   // 从 PIC 命令端口
const PIC2_DATA: u16 = 0xA1;  // 从 PIC 数据端口

/// PIC 中断向量偏移
pub const PIC1_OFFSET: u8 = 0x20;  // 主 PIC: IRQ 0-7 -> 向量 32-39
pub const PIC2_OFFSET: u8 = 0x28;  // 从 PIC: IRQ 8-15 -> 向量 40-47

/// 等待 I/O 完成（用于 PIC 初始化时的延迟）
#[inline]
unsafe fn io_wait() {
    // 向未使用的端口 0x80 写入任意值，产生足够的延迟
    core::arch::asm!("out 0x80, al", in("al") 0u8, options(nostack, nomem));
}

/// 初始化并重映射 8259 PIC
///
/// 将主 PIC (IRQ 0-7) 映射到向量 offset1 开始
/// 将从 PIC (IRQ 8-15) 映射到向量 offset2 开始
///
/// # Safety
///
/// 必须在启用中断前调用。offset1 和 offset2 不得与 CPU 异常向量 (0-31) 重叠。
pub unsafe fn pic_init() {
    // 保存当前中断掩码
    let mask1: u8;
    let mask2: u8;
    core::arch::asm!("in al, dx", out("al") mask1, in("dx") PIC1_DATA, options(nostack, nomem));
    core::arch::asm!("in al, dx", out("al") mask2, in("dx") PIC2_DATA, options(nostack, nomem));

    // ICW1: 开始初始化序列（边沿触发，级联模式，需要 ICW4）
    core::arch::asm!("out dx, al", in("dx") PIC1_CMD, in("al") 0x11u8, options(nostack, nomem));
    io_wait();
    core::arch::asm!("out dx, al", in("dx") PIC2_CMD, in("al") 0x11u8, options(nostack, nomem));
    io_wait();

    // ICW2: 设置中断向量偏移
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") PIC1_OFFSET, options(nostack, nomem));
    io_wait();
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") PIC2_OFFSET, options(nostack, nomem));
    io_wait();

    // ICW3: 配置级联
    // 主 PIC: IR2 连接从 PIC (位掩码 0x04)
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") 4u8, options(nostack, nomem));
    io_wait();
    // 从 PIC: 级联标识为 2
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") 2u8, options(nostack, nomem));
    io_wait();

    // ICW4: 设置 8086/88 模式
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") 0x01u8, options(nostack, nomem));
    io_wait();
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") 0x01u8, options(nostack, nomem));
    io_wait();

    // 恢复中断掩码（或设置新掩码）
    // 默认只启用 IRQ0 (定时器) 和 IRQ1 (键盘)
    let new_mask1: u8 = 0xFC;  // 11111100 - 启用 IRQ0 和 IRQ1
    let new_mask2: u8 = 0xFF;  // 11111111 - 禁用所有从 PIC 中断
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") new_mask1, options(nostack, nomem));
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") new_mask2, options(nostack, nomem));

    println!("PIC initialized: IRQ0-7 -> vectors {}-{}, IRQ8-15 -> vectors {}-{}",
             PIC1_OFFSET, PIC1_OFFSET + 7, PIC2_OFFSET, PIC2_OFFSET + 7);
}

/// 发送 EOI (End of Interrupt) 到 PIC
///
/// # Arguments
/// * `irq` - 中断请求号 (0-15)
#[inline]
pub unsafe fn pic_send_eoi(irq: u8) {
    if irq >= 8 {
        // 从 PIC 的中断，需要同时发送 EOI 到从 PIC 和主 PIC
        core::arch::asm!("out dx, al", in("dx") PIC2_CMD, in("al") 0x20u8, options(nostack, nomem));
    }
    core::arch::asm!("out dx, al", in("dx") PIC1_CMD, in("al") 0x20u8, options(nostack, nomem));
}
