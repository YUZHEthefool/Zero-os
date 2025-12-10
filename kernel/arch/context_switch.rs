//! 进程上下文切换
//!
//! 提供进程上下文的保存、恢复和切换功能

use core::arch::asm;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

/// FXSAVE 区域大小（512 字节）
const FXSAVE_SIZE: usize = 512;

/// FPU 保存区在 Context 中的偏移量
/// 原有寄存器占用 0xA0 字节，向上取 64 字节对齐得到 0xC0
const FXSAVE_OFFSET: usize = 0xC0;

/// 512 字节的 FXSAVE/FXRSTOR 区域
/// 按 64 字节对齐以兼容 XSAVE 路径
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FxSaveArea {
    pub data: [u8; FXSAVE_SIZE],
}

impl core::fmt::Debug for FxSaveArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FxSaveArea")
            .field("fcw", &u16::from_le_bytes([self.data[0], self.data[1]]))
            .field("fsw", &u16::from_le_bytes([self.data[2], self.data[3]]))
            .field("mxcsr", &u32::from_le_bytes([self.data[24], self.data[25], self.data[26], self.data[27]]))
            .finish_non_exhaustive()
    }
}

impl Default for FxSaveArea {
    fn default() -> Self {
        let mut area = FxSaveArea { data: [0; FXSAVE_SIZE] };
        // 设置默认的 FCW（FPU Control Word）：双精度、所有异常屏蔽
        area.data[0] = 0x7F;
        area.data[1] = 0x03;
        // 设置默认的 MXCSR（SSE Control/Status）：所有异常屏蔽
        area.data[24] = 0x80;
        area.data[25] = 0x1F;
        area
    }
}

/// 进程上下文结构
///
/// 保存进程执行时的CPU寄存器状态，包括通用寄存器和 FPU/SIMD 状态
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct Context {
    // 通用寄存器 (偏移 0x00 - 0x7F)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // 指令指针和标志寄存器 (偏移 0x80 - 0x8F)
    pub rip: u64,
    pub rflags: u64,

    // 段寄存器 (偏移 0x90 - 0x9F)
    pub cs: u64,
    pub ss: u64,

    // 填充以对齐 FxSaveArea 到 64 字节边界 (偏移 0xA0 - 0xBF)
    _padding: [u64; 4],

    /// FPU/SIMD 保存区 (偏移 0xC0)
    /// 用于 FXSAVE/FXRSTOR 指令
    pub fx: FxSaveArea,
}

impl Context {
    /// 创建一个新的空上下文
    pub const fn new() -> Self {
        Context {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x202, // IF (中断使能) 位设置
            cs: 0x08,      // 内核代码段
            ss: 0x10,      // 内核数据段
            _padding: [0; 4],
            fx: FxSaveArea { data: [0; FXSAVE_SIZE] },
        }
    }

    /// 为新进程初始化上下文
    ///
    /// # Arguments
    ///
    /// * `entry_point` - 进程入口点地址
    /// * `stack_top` - 栈顶地址
    pub fn init_for_process(entry_point: u64, stack_top: u64) -> Self {
        let mut ctx = Self::new();
        ctx.rip = entry_point;
        ctx.rsp = stack_top;
        ctx.rbp = stack_top;
        ctx.rflags = 0x202; // IF位使能
        ctx.fx = FxSaveArea::default(); // 使用默认的 FPU 状态
        ctx
    }

    /// 为用户态进程初始化上下文
    pub fn init_for_user_process(entry_point: u64, stack_top: u64) -> Self {
        let mut ctx = Self::new();
        ctx.rip = entry_point;
        ctx.rsp = stack_top;
        ctx.rbp = stack_top;
        ctx.rflags = 0x202;  // IF位使能
        ctx.cs = 0x1B;       // 用户代码段 (GDT索引3, RPL=3)
        ctx.ss = 0x23;       // 用户数据段 (GDT索引4, RPL=3)
        ctx.fx = FxSaveArea::default(); // 使用默认的 FPU 状态
        ctx
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// 保存当前上下文并切换到新上下文
///
/// # Safety
///
/// 此函数直接操作CPU寄存器，必须确保：
/// - old_ctx 和 new_ctx 指向有效的Context结构
/// - 调用者了解上下文切换的影响
/// - FPU 已通过 init_fpu() 初始化
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old_ctx: *mut Context, _new_ctx: *const Context) {
    core::arch::naked_asm!(
        // 保存当前 FPU/SIMD 状态到 old_ctx
        "fxsave64 [rdi + {fxoff}]",

        // 先保存 rcx/rdx（在覆盖前使用 rdi 作为基址）
        "mov [rdi + 0x10], rcx",   // 保存rcx
        "mov [rdi + 0x18], rdx",   // 保存rdx

        // 将 rdi/rsi 移至 rdx/rcx 作为上下文指针
        // 此时 rdi/rsi 仍保持原始任务值
        "mov rdx, rdi",            // rdx = old_ctx 指针
        "mov rcx, rsi",            // rcx = new_ctx 指针

        // 保存当前上下文到 old_ctx (rdx)
        // 注意：rsi/rdi 现在仍是原始任务的寄存器值！
        "mov [rdx + 0x00], rax",   // 保存rax
        "mov [rdx + 0x08], rbx",   // 保存rbx
        "mov [rdx + 0x20], rsi",   // 保存rsi（原始任务值）
        "mov [rdx + 0x28], rdi",   // 保存rdi（原始任务值）
        "mov [rdx + 0x30], rbp",   // 保存rbp
        "mov [rdx + 0x38], rsp",   // 保存rsp
        "mov [rdx + 0x40], r8",    // 保存r8
        "mov [rdx + 0x48], r9",    // 保存r9
        "mov [rdx + 0x50], r10",   // 保存r10
        "mov [rdx + 0x58], r11",   // 保存r11
        "mov [rdx + 0x60], r12",   // 保存r12
        "mov [rdx + 0x68], r13",   // 保存r13
        "mov [rdx + 0x70], r14",   // 保存r14
        "mov [rdx + 0x78], r15",   // 保存r15

        // 保存rip (返回地址在栈顶)
        "mov rax, [rsp]",
        "mov [rdx + 0x80], rax",

        // 保存rflags
        "pushfq",
        "pop rax",
        "mov [rdx + 0x88], rax",

        // 保存段寄存器
        "mov ax, cs",
        "mov [rdx + 0x90], rax",
        "mov ax, ss",
        "mov [rdx + 0x98], rax",

        // 恢复新进程的 FPU/SIMD 状态
        "fxrstor64 [rcx + {fxoff}]",

        // 加载新上下文从 new_ctx (rcx)
        "mov rax, [rcx + 0x00]",   // 恢复rax
        "mov rbx, [rcx + 0x08]",   // 恢复rbx
        "mov rdx, [rcx + 0x18]",   // 恢复rdx
        "mov rbp, [rcx + 0x30]",   // 恢复rbp
        "mov rsp, [rcx + 0x38]",   // 恢复rsp
        "mov r8,  [rcx + 0x40]",   // 恢复r8
        "mov r9,  [rcx + 0x48]",   // 恢复r9
        "mov r10, [rcx + 0x50]",   // 恢复r10
        "mov r11, [rcx + 0x58]",   // 恢复r11
        "mov r12, [rcx + 0x60]",   // 恢复r12
        "mov r13, [rcx + 0x68]",   // 恢复r13
        "mov r14, [rcx + 0x70]",   // 恢复r14
        "mov r15, [rcx + 0x78]",   // 恢复r15

        // 恢复rip (跳转地址)
        "push qword ptr [rcx + 0x80]",

        // 恢复rflags
        "push qword ptr [rcx + 0x88]",
        "popfq",

        // 最后恢复 rdi/rsi/rcx（易失寄存器）
        "mov rdi, [rcx + 0x28]",   // 恢复rdi
        "mov rsi, [rcx + 0x20]",   // 恢复rsi
        "mov rcx, [rcx + 0x10]",   // 恢复rcx（必须最后，因为 rcx 是基址）

        // 返回到新进程
        "ret",
        fxoff = const FXSAVE_OFFSET,
    )
}

/// 保存当前上下文
///
/// # Safety
///
/// 调用者必须确保ctx指向有效的Context结构，且 FPU 已初始化
#[inline]
pub unsafe fn save_context(ctx: *mut Context) {
    asm!(
        "fxsave64 [{ctx} + {fxoff}]",
        "mov [{ctx} + 0x00], rax",
        "mov [{ctx} + 0x08], rbx",
        "mov [{ctx} + 0x10], rcx",
        "mov [{ctx} + 0x18], rdx",
        "mov [{ctx} + 0x20], rsi",
        "mov [{ctx} + 0x28], rdi",
        "mov [{ctx} + 0x30], rbp",
        "mov [{ctx} + 0x38], rsp",
        "mov [{ctx} + 0x40], r8",
        "mov [{ctx} + 0x48], r9",
        "mov [{ctx} + 0x50], r10",
        "mov [{ctx} + 0x58], r11",
        "mov [{ctx} + 0x60], r12",
        "mov [{ctx} + 0x68], r13",
        "mov [{ctx} + 0x70], r14",
        "mov [{ctx} + 0x78], r15",
        ctx = in(reg) ctx,
        fxoff = const FXSAVE_OFFSET,
        options(nostack)
    );
}

/// 恢复上下文
///
/// # Safety
///
/// 调用者必须确保ctx指向有效的Context结构，且 FPU 已初始化
#[inline]
pub unsafe fn restore_context(ctx: *const Context) {
    asm!(
        "fxrstor64 [{ctx} + {fxoff}]",
        "mov rax, [{ctx} + 0x00]",
        "mov rbx, [{ctx} + 0x08]",
        "mov rcx, [{ctx} + 0x10]",
        "mov rdx, [{ctx} + 0x18]",
        "mov rsi, [{ctx} + 0x20]",
        "mov rdi, [{ctx} + 0x28]",
        "mov rbp, [{ctx} + 0x30]",
        "mov rsp, [{ctx} + 0x38]",
        "mov r8,  [{ctx} + 0x40]",
        "mov r9,  [{ctx} + 0x48]",
        "mov r10, [{ctx} + 0x50]",
        "mov r11, [{ctx} + 0x58]",
        "mov r12, [{ctx} + 0x60]",
        "mov r13, [{ctx} + 0x68]",
        "mov r14, [{ctx} + 0x70]",
        "mov r15, [{ctx} + 0x78]",
        ctx = in(reg) ctx,
        fxoff = const FXSAVE_OFFSET,
        options(nostack)
    );
}

/// 初始化 FPU/SIMD 支持
///
/// 必须在使用 FXSAVE/FXRSTOR 之前调用一次。
/// 设置 CR0 和 CR4 中的相关位以启用 SSE 和 FPU 支持。
pub fn init_fpu() {
    unsafe {
        // CR0: 关闭 EM（协处理器仿真），开启 MP（监控协处理器），清除 TS（任务切换）
        let mut cr0 = Cr0::read();
        cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
        cr0.remove(Cr0Flags::TASK_SWITCHED); // 清除 TS 防止 #NM
        cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
        unsafe { Cr0::write(cr0) };

        // CR4: 启用 OSFXSR（允许 FXSAVE/FXRSTOR）和 OSXMMEXCPT（SSE 异常处理）
        let mut cr4 = Cr4::read();
        cr4.insert(Cr4Flags::OSFXSR);
        cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
        unsafe { Cr4::write(cr4) };
    }
}
