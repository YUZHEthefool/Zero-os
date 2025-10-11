//! 进程上下文切换
//! 
//! 提供进程上下文的保存、恢复和切换功能

use core::arch::asm;

/// 进程上下文结构
/// 
/// 保存进程执行时的CPU寄存器状态
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Context {
    // 通用寄存器
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
    
    // 指令指针和标志寄存器
    pub rip: u64,
    pub rflags: u64,
    
    // 段寄存器
    pub cs: u64,
    pub ss: u64,
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
            cs: 0x08,  // 内核代码段
            ss: 0x10,  // 内核数据段
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
        ctx
    }
    
    /// 为用户态进程初始化上下文
    pub fn init_for_user_process(entry_point: u64, stack_top: u64) -> Self {
        let mut ctx = Self::new();
        ctx.rip = entry_point;
        ctx.rsp = stack_top;
        ctx.rbp = stack_top;
        ctx.rflags = 0x202; // IF位使能
        ctx.cs = 0x1B;  // 用户代码段 (GDT索引3, RPL=3)
        ctx.ss = 0x23;  // 用户数据段 (GDT索引4, RPL=3)
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
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old_ctx: *mut Context, _new_ctx: *const Context) {
    core::arch::naked_asm!(
        // 保存当前上下文到old_ctx (rdi)
        "mov [rdi + 0x00], rax",   // 保存rax
        "mov [rdi + 0x08], rbx",   // 保存rbx
        "mov [rdi + 0x10], rcx",   // 保存rcx
        "mov [rdi + 0x18], rdx",   // 保存rdx
        "mov [rdi + 0x20], rsi",   // 保存rsi
        "mov [rdi + 0x28], rdi",   // 保存rdi
        "mov [rdi + 0x30], rbp",   // 保存rbp
        "mov [rdi + 0x38], rsp",   // 保存rsp
        "mov [rdi + 0x40], r8",    // 保存r8
        "mov [rdi + 0x48], r9",    // 保存r9
        "mov [rdi + 0x50], r10",   // 保存r10
        "mov [rdi + 0x58], r11",   // 保存r11
        "mov [rdi + 0x60], r12",   // 保存r12
        "mov [rdi + 0x68], r13",   // 保存r13
        "mov [rdi + 0x70], r14",   // 保存r14
        "mov [rdi + 0x78], r15",   // 保存r15
        
        // 保存rip (返回地址在栈顶)
        "mov rax, [rsp]",
        "mov [rdi + 0x80], rax",
        
        // 保存rflags
        "pushfq",
        "pop rax",
        "mov [rdi + 0x88], rax",
        
        // 保存段寄存器
        "mov ax, cs",
        "mov [rdi + 0x90], rax",
        "mov ax, ss",
        "mov [rdi + 0x98], rax",
        
        // 加载新上下文从new_ctx (rsi)
        "mov rax, [rsi + 0x00]",   // 恢复rax
        "mov rbx, [rsi + 0x08]",   // 恢复rbx
        "mov rcx, [rsi + 0x10]",   // 恢复rcx
        "mov rdx, [rsi + 0x18]",   // 恢复rdx
        // rsi稍后恢复
        "mov rdi, [rsi + 0x28]",   // 恢复rdi
        "mov rbp, [rsi + 0x30]",   // 恢复rbp
        "mov rsp, [rsi + 0x38]",   // 恢复rsp
        "mov r8,  [rsi + 0x40]",   // 恢复r8
        "mov r9,  [rsi + 0x48]",   // 恢复r9
        "mov r10, [rsi + 0x50]",   // 恢复r10
        "mov r11, [rsi + 0x58]",   // 恢复r11
        "mov r12, [rsi + 0x60]",   // 恢复r12
        "mov r13, [rsi + 0x68]",   // 恢复r13
        "mov r14, [rsi + 0x70]",   // 恢复r14
        "mov r15, [rsi + 0x78]",   // 恢复r15
        
        // 恢复rip (跳转地址)
        "push qword ptr [rsi + 0x80]",
        
        // 恢复rflags
        "push qword ptr [rsi + 0x88]",
        "popfq",
        
        // 最后恢复rsi
        "mov rsi, [rsi + 0x20]",
        
        // 返回到新进程
        "ret"
    )
}

/// 保存当前上下文
/// 
/// # Safety
/// 
/// 调用者必须确保ctx指向有效的Context结构
#[inline]
pub unsafe fn save_context(ctx: *mut Context) {
    asm!(
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
        options(nostack)
    );
}

/// 恢复上下文
/// 
/// # Safety
/// 
/// 调用者必须确保ctx指向有效的Context结构
#[inline]
pub unsafe fn restore_context(ctx: *const Context) {
    asm!(
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
        options(nostack)
    );
}
