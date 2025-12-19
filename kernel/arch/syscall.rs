//! SYSCALL/SYSRET 系统调用入口配置
//!
//! 配置 x86_64 的快速系统调用机制，包括：
//! - IA32_STAR: 内核/用户代码段选择子
//! - IA32_LSTAR: 系统调用入口点地址
//! - IA32_SFMASK: RFLAGS 掩码
//! - IA32_EFER: 启用 SYSCALL/SYSRET 扩展
//!
//! # Phase 6: User Space Support
//!
//! 这是实现 Ring 3 用户态支持的关键组件。
//!
//! ## SYSCALL 寄存器约定
//!
//! 用户态调用 SYSCALL 时：
//! - RAX: 系统调用号
//! - RDI: arg0, RSI: arg1, RDX: arg2
//! - R10: arg3 (不是 RCX，因为 SYSCALL 会覆盖它)
//! - R8: arg4, R9: arg5
//!
//! SYSCALL 指令执行后：
//! - RCX = 用户态 RIP (返回地址)
//! - R11 = 用户态 RFLAGS
//! - CS/SS 根据 STAR MSR 切换

use crate::gdt;
use core::arch::asm;

/// IA32_STAR MSR 地址
const IA32_STAR: u32 = 0xC000_0081;

/// IA32_LSTAR MSR 地址 (64-bit SYSCALL 入口点)
const IA32_LSTAR: u32 = 0xC000_0082;

/// IA32_CSTAR MSR 地址 (32-bit 兼容模式，暂不使用)
#[allow(dead_code)]
const IA32_CSTAR: u32 = 0xC000_0083;

/// IA32_SFMASK MSR 地址 (SYSCALL RFLAGS 掩码)
const IA32_SFMASK: u32 = 0xC000_0084;

/// IA32_EFER MSR 地址
const IA32_EFER: u32 = 0xC000_0080;

/// EFER.SCE 位 (System Call Extensions)
const EFER_SCE: u64 = 1 << 0;

/// RFLAGS 中断标志位
const RFLAGS_IF: u64 = 1 << 9;
/// RFLAGS 单步标志位
const RFLAGS_TF: u64 = 1 << 8;
/// RFLAGS 方向标志位
const RFLAGS_DF: u64 = 1 << 10;
/// RFLAGS AC 标志位 (SMAP)
const RFLAGS_AC: u64 = 1 << 18;
/// RFLAGS IOPL 位 (I/O 特权级)
const RFLAGS_IOPL: u64 = 0b11 << 12;
/// RFLAGS NT 位 (嵌套任务)
const RFLAGS_NT: u64 = 1 << 14;
/// RFLAGS RF 位 (恢复标志)
const RFLAGS_RF: u64 = 1 << 16;

/// 用户代码段选择子 (SYSRET/IRET 回退用)
const USER_CODE_SELECTOR: u64 = 0x23;
/// 用户数据段选择子
const USER_DATA_SELECTOR: u64 = 0x1B;

// ============================================================================
// 系统调用帧定义
// ============================================================================

/// 系统调用保存帧中的寄存器数量
const SYSCALL_FRAME_QWORDS: usize = 16;

/// 系统调用帧大小（字节）
const SYSCALL_FRAME_SIZE: usize = SYSCALL_FRAME_QWORDS * 8;

/// 临时栈大小（4KB，仅用于单核）
const SYSCALL_SCRATCH_SIZE: usize = 4096;

/// FPU/SIMD 保存区大小（FXSAVE/FXRSTOR 需要 512 字节且 16 字节对齐）
/// Z-1 fix: 用于在 syscall 路径中保存/恢复用户态 FPU 状态
const FPU_SAVE_AREA_SIZE: usize = 512;

// 帧内各寄存器的偏移量
const OFF_RAX: usize = 0; // 系统调用号 / 返回值
const OFF_RCX: usize = 8; // 用户 RIP
const OFF_RDX: usize = 16; // arg2
const OFF_RBX: usize = 24; // callee-saved
const OFF_RSP: usize = 32; // 用户 RSP
const OFF_RBP: usize = 40; // callee-saved
const OFF_RSI: usize = 48; // arg1
const OFF_RDI: usize = 56; // arg0
const OFF_R8: usize = 64; // arg4
const OFF_R9: usize = 72; // arg5
const OFF_R10: usize = 80; // arg3
const OFF_R11: usize = 88; // 用户 RFLAGS
const OFF_R12: usize = 96; // callee-saved
const OFF_R13: usize = 104; // callee-saved
const OFF_R14: usize = 112; // callee-saved
const OFF_R15: usize = 120; // callee-saved

/// 对齐的栈存储（确保 16 字节对齐满足 ABI 要求）
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct AlignedStack<const N: usize>([u8; N]);

// ============================================================================
// R23-2 fix: Per-CPU syscall 临时数据
// ============================================================================
// 将原来的全局变量改为 per-CPU 数组，为 SMP 支持做准备。
// 当前 current_cpu_id() 总是返回 0，所以实际行为与单核相同。
// 未来启用 SMP 时，只需实现真正的 CPU ID 获取逻辑即可。
//
// **SMP 升级路径**：
// 1. 实现 current_cpu_id() 读取 APIC ID
// 2. 在汇编中通过 GS 段或 APIC ID 计算 per-CPU 偏移
// 3. 将 `lea rsp, [{scratch_stacks}]` 改为 `lea rsp, [{scratch_stacks} + cpu_id * SCRATCH_SIZE]`

/// 最大支持的 CPU 数量（必须与 cpu_local crate 保持一致）
const SYSCALL_MAX_CPUS: usize = 64;

// 编译时断言：确保 SYSCALL_MAX_CPUS 与 cpu_local::max_cpus() 一致
const _: () = {
    assert!(SYSCALL_MAX_CPUS == 64, "SYSCALL_MAX_CPUS must match cpu_local::max_cpus()");
    // 注意：cpu_local::max_cpus() 是 const fn，但由于跨 crate 常量引用限制，
    // 这里硬编码为 64。如果 cpu_local 修改了 MAX_CPUS，需要同步更新此处。
};

/// Per-CPU scratch 栈数组
///
/// 每个 CPU 有独立的 4KB 临时栈，用于 syscall 入口时保存用户寄存器。
/// 使用 `#[no_mangle]` 以便汇编代码可以直接引用符号地址。
///
/// # Safety
///
/// - 在中断禁用状态下使用（SFMASK 清除 IF），不会重入
/// - 每个 CPU 只访问自己的 slot，通过 CPU ID 索引
/// - 当前实现中 CPU ID = 0，总是使用 slot 0
/// - 数组元素继承 AlignedStack 的 16 字节对齐属性
#[no_mangle]
static mut SYSCALL_SCRATCH_STACKS: [AlignedStack<SYSCALL_SCRATCH_SIZE>; SYSCALL_MAX_CPUS] =
    [AlignedStack([0; SYSCALL_SCRATCH_SIZE]); SYSCALL_MAX_CPUS];

/// Per-CPU 用户 RSP 暂存数组
///
/// 每个 CPU 有独立的 u64 槽位，用于暂存用户态 RSP。
/// 避免泄露用户栈指针或覆盖其他 CPU 的数据。
#[no_mangle]
static mut SYSCALL_USER_RSP_SHADOWS: [u64; SYSCALL_MAX_CPUS] = [0; SYSCALL_MAX_CPUS];

// ============================================================================
// MSR 操作
// ============================================================================

/// 读取 MSR
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// 写入 MSR
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

/// 系统调用入口是否已初始化
static mut SYSCALL_INITIALIZED: bool = false;

/// 初始化 SYSCALL/SYSRET MSR
///
/// 配置快速系统调用机制，使用户态程序可以通过 SYSCALL 指令进入内核。
///
/// # Arguments
///
/// * `syscall_entry` - 系统调用入口函数地址（汇编存根）
///
/// # Safety
///
/// - 必须在 GDT 初始化后调用
/// - syscall_entry 必须是有效的系统调用处理程序地址
/// - 只能调用一次
///
/// # STAR MSR 布局 (64-bit 模式)
///
/// ```text
/// bits 63:48 = 用户代码段选择子基址（SYSRET 加载 CS = 此值 + 16, SS = 此值 + 8）
/// bits 47:32 = 内核代码段选择子（SYSCALL 加载 CS = 此值, SS = 此值 + 8）
/// bits 31:0  = 保留（32-bit 模式使用）
/// ```
pub unsafe fn init_syscall_msr(syscall_entry: u64) {
    if SYSCALL_INITIALIZED {
        println!("Warning: SYSCALL MSR already initialized");
        return;
    }

    let sel = gdt::selectors();

    // 获取选择子的原始值（不含 RPL）
    let kernel_cs = sel.kernel_code.0 as u64;
    let user_data = sel.user_data.0 as u64;

    // STAR 布局计算：
    // SYSRET (64-bit): CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
    // 目标：CS = 0x23 (user_code | RPL=3), SS = 0x1b (user_data | RPL=3)
    // 计算：STAR[63:48] = 0x23 - 16 = 0x13 = (user_data - 8) | 3
    let sysret_base = (user_data - 8) | 3;

    let star_value = (sysret_base << 48) | (kernel_cs << 32);

    // 写入 STAR
    wrmsr(IA32_STAR, star_value);

    // 写入 LSTAR (系统调用入口点)
    wrmsr(IA32_LSTAR, syscall_entry);

    // 写入 SFMASK (SYSCALL 时清除的 RFLAGS 位)
    // 清除 IF/TF/DF/AC 以及 IOPL/NT/RF，防止特权/调试位带入内核
    let sfmask =
        RFLAGS_IF | RFLAGS_TF | RFLAGS_DF | RFLAGS_AC | RFLAGS_IOPL | RFLAGS_NT | RFLAGS_RF;
    wrmsr(IA32_SFMASK, sfmask);

    // 启用 EFER.SCE (System Call Extensions)
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | EFER_SCE);

    SYSCALL_INITIALIZED = true;

    println!("SYSCALL MSR initialized:");
    println!("  STAR:   0x{:016x}", star_value);
    println!("  LSTAR:  0x{:016x}", syscall_entry);
    println!("  SFMASK: 0x{:016x}", sfmask);
    println!(
        "  Kernel CS: 0x{:x}, SYSRET base: 0x{:x}",
        kernel_cs, sysret_base
    );
}

/// 检查 SYSCALL/SYSRET 是否已初始化
pub fn is_initialized() -> bool {
    unsafe { SYSCALL_INITIALIZED }
}

/// 获取当前 STAR MSR 值（调试用）
pub fn get_star() -> u64 {
    unsafe { rdmsr(IA32_STAR) }
}

/// 获取当前 LSTAR MSR 值（调试用）
pub fn get_lstar() -> u64 {
    unsafe { rdmsr(IA32_LSTAR) }
}

// ============================================================================
// C ABI 辅助函数
// ============================================================================

/// 获取内核栈顶（TSS RSP0）
///
/// # Safety
///
/// 仅由 syscall_entry_stub 汇编代码调用
#[no_mangle]
extern "C" fn syscall_get_kernel_rsp0() -> u64 {
    gdt::get_kernel_stack().as_u64()
}

/// 系统调用分发器桥接
///
/// 将 C ABI 调用转发到 Rust 的 syscall_dispatcher
///
/// # Safety
///
/// 仅由 syscall_entry_stub 汇编代码调用
#[no_mangle]
extern "C" fn syscall_dispatcher_bridge(
    syscall_num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    kernel_core::syscall::syscall_dispatcher(syscall_num, arg0, arg1, arg2, arg3, arg4, arg5)
}

// ============================================================================
// 系统调用入口点
// ============================================================================

/// 系统调用入口点
///
/// 处理从用户态通过 SYSCALL 指令进入内核的情况。
///
/// ## 执行流程
///
/// 1. 保存用户 RSP 到暂存区
/// 2. 切换到临时栈
/// 3. 保存所有用户寄存器
/// 4. 获取内核栈并复制帧
/// 5. 启用中断，调用 syscall_dispatcher
/// 6. 禁用中断，恢复寄存器
/// 7. 执行 SYSRETQ 返回用户态
///
/// ## 寄存器约定
///
/// 进入时（来自 SYSCALL）：
/// - RAX = 系统调用号
/// - RDI/RSI/RDX/R10/R8/R9 = arg0-arg5
/// - RCX = 用户 RIP
/// - R11 = 用户 RFLAGS
/// - RSP = 用户栈（需要保存）
///
/// 退出时（SYSRETQ 前）：
/// - RAX = 返回值
/// - RCX = 用户 RIP
/// - R11 = 用户 RFLAGS
/// - 其他寄存器已恢复
///
/// ## 已知限制
///
/// 1. **Per-CPU 数据**：SYSCALL_SCRATCH_STACKS 和 SYSCALL_USER_RSP_SHADOWS
///    已改为 per-CPU 数组（R23-2 fix）。当前 current_cpu_id() 总是返回 0，
///    所以实际使用 slot 0。未来启用 SMP 时需要实现真正的 CPU ID 获取，
///    并在汇编中根据 APIC ID 计算偏移。
///
/// 2. **FPU/SIMD 状态**：在分发器调用前后使用 FXSAVE64/FXRSTOR64 保存并
///    恢复用户态 FPU/SIMD 状态。当前仍为单核实现，SMP 场景需要改为 per-CPU
///    保存区。（Z-1 fix）
///
/// # Safety
///
/// 此函数不应被直接调用，仅作为 LSTAR 的目标。
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry_stub() -> ! {
    core::arch::naked_asm!(
        // ========================================
        // 阶段 1: SMAP 安全 & 保存用户 RSP
        // ========================================
        // NOTE: CLAC requires SMAP support (CR4.SMAP). If CPU doesn't support SMAP,
        // CLAC is undefined and causes #UD. Using NOP instead for compatibility.
        // TODO: Check SMAP support at runtime and conditionally use CLAC.
        "nop", "nop", "nop",                        // 替代 clac (需要 SMAP 支持)
        // R23-2 fix: 使用 per-CPU 数组 slot 0（当前 CPU ID = 0）
        "mov [{user_rsp_arr}], rsp",                // 保存用户 RSP 到 per-CPU 暂存区

        // ========================================
        // 阶段 2: 切换到临时栈
        // ========================================
        // R23-2 fix: 使用 per-CPU scratch 栈数组 slot 0
        "lea rsp, [{scratch_stacks} + {scratch_size}]",  // 使用 per-CPU 临时栈
        "cld",                                      // 清除方向标志

        // ========================================
        // 阶段 3: 保存用户寄存器到临时栈
        // ========================================
        "sub rsp, {frame_size}",                    // 分配帧空间

        "mov [rsp + {off_rax}], rax",               // 系统调用号
        "mov [rsp + {off_rcx}], rcx",               // 用户 RIP
        "mov [rsp + {off_rdx}], rdx",               // arg2
        "mov [rsp + {off_rbx}], rbx",               // callee-saved

        // R23-2 fix: 从 per-CPU 数组获取保存的用户 RSP
        "mov rax, [{user_rsp_arr}]",
        "mov [rsp + {off_rsp}], rax",               // 用户 RSP

        "mov [rsp + {off_rbp}], rbp",               // callee-saved
        "mov [rsp + {off_rsi}], rsi",               // arg1
        "mov [rsp + {off_rdi}], rdi",               // arg0
        "mov [rsp + {off_r8}], r8",                 // arg4
        "mov [rsp + {off_r9}], r9",                 // arg5
        "mov [rsp + {off_r10}], r10",               // arg3
        "mov [rsp + {off_r11}], r11",               // 用户 RFLAGS
        "mov [rsp + {off_r12}], r12",               // callee-saved
        "mov [rsp + {off_r13}], r13",               // callee-saved
        "mov [rsp + {off_r14}], r14",               // callee-saved
        "mov [rsp + {off_r15}], r15",               // callee-saved

        // 清除用户设置的调试寄存器，防止硬件断点打进内核
        "xor rax, rax",
        "mov dr7, rax",
        "mov dr6, rax",

        // ========================================
        // 阶段 4: 切换到内核栈
        // ========================================
        "mov r12, rsp",                             // r12 = 临时栈上的帧指针

        // 获取内核栈顶（TSS RSP0）- 栈已 16B 对齐无需额外调整
        "call {get_rsp0}",                          // 返回值在 rax
        "mov rsp, rax",                             // 切换到内核栈

        // Z-1 fix: 在内核栈上分配 FPU 保存区与通用寄存器帧
        // 内存布局（从高到低）：
        //   [TSS RSP0]        <- 内核栈顶（16B 对齐）
        //   [FPU save area]   <- 512 字节，16B 对齐
        //   [syscall frame]   <- 128 字节，通用寄存器
        "sub rsp, {fpu_save_size}",                 // 512B FPU 保存区
        "sub rsp, {frame_size}",                    // 128B 通用寄存器帧
        "mov rdi, rsp",                             // dst = 内核栈帧
        "mov rsi, r12",                             // src = 临时栈帧
        "mov rcx, {frame_qwords}",                  // count
        "rep movsq",                                // 复制帧

        "mov r12, rsp",                             // r12 = 内核栈帧指针（保留用于恢复）
        "lea r13, [rsp + {frame_size}]",            // r13 = FPU 保存区指针（位于帧上方）

        // Z-1 fix: 保存用户 FPU/SIMD 状态
        "fxsave64 [r13]",

        // ========================================
        // 阶段 5: 调用系统调用分发器
        // ========================================
        // System V AMD64 ABI: rdi, rsi, rdx, rcx, r8, r9, [stack]
        // syscall_dispatcher(num, arg0, arg1, arg2, arg3, arg4, arg5)

        "sti",                                      // 启用中断

        "mov rdi, [r12 + {off_rax}]",               // syscall_num (原 RAX)
        "mov rsi, [r12 + {off_rdi}]",               // arg0 (原 RDI)
        "mov rdx, [r12 + {off_rsi}]",               // arg1 (原 RSI)
        "mov rcx, [r12 + {off_rdx}]",               // arg2 (原 RDX)
        "mov r8,  [r12 + {off_r10}]",               // arg3 (原 R10，不是 RCX)
        "mov r9,  [r12 + {off_r8}]",                // arg4 (原 R8)

        // Z-2 fix: 栈对齐修复
        // 当前 RSP 是 16B 对齐（frame 和 FPU 区都是 16 的倍数）
        // System V ABI: call 前 RSP 必须 16B 对齐（call 后入口 RSP+8 是 16B 对齐）
        // 需要 sub 8 + push = 16B，保持对齐
        "sub rsp, 8",                               // 对齐填充
        "push qword ptr [r12 + {off_r9}]",          // arg5 (原 R9)

        "call {dispatcher}",                        // 调用分发器

        "add rsp, 16",                              // 清理栈参数 + 对齐填充

        // ========================================
        // 阶段 6: 恢复寄存器
        // ========================================
        "cli",                                      // 禁用中断

        // Z-1 fix: 恢复用户 FPU/SIMD 状态
        "fxrstor64 [r13]",

        // SYSRET 安全检查：用户 RIP/RSP 必须是规范地址且在低半区
        // 这是防御 CVE-2014-4699/CVE-2014-9322 类漏洞的关键
        "mov rdx, [r12 + {off_rcx}]",               // 用户 RIP
        "mov rbx, rdx",
        "shl rbx, 16",
        "sar rbx, 16",
        "cmp rbx, rdx",
        "jne 2f",                                   // 非规范地址，跳转到 IRETQ 回退
        "bt rdx, 47",
        "jc 2f",                                    // 高半区地址，跳转到 IRETQ 回退

        "mov rdx, [r12 + {off_rsp}]",               // 用户 RSP
        "mov rbx, rdx",
        "shl rbx, 16",
        "sar rbx, 16",
        "cmp rbx, rdx",
        "jne 2f",                                   // 非规范地址，跳转到 IRETQ 回退
        "bt rdx, 47",
        "jc 2f",                                    // 高半区地址，跳转到 IRETQ 回退

        // 地址检查通过，执行正常 SYSRET 路径
        // RAX 已经是返回值，不需要恢复
        "mov rcx, [r12 + {off_rcx}]",               // 用户 RIP
        "mov rdx, [r12 + {off_rdx}]",
        "mov rbx, [r12 + {off_rbx}]",
        "mov rbp, [r12 + {off_rbp}]",
        "mov rsi, [r12 + {off_rsi}]",
        "mov rdi, [r12 + {off_rdi}]",
        "mov r8,  [r12 + {off_r8}]",
        "mov r9,  [r12 + {off_r9}]",
        "mov r10, [r12 + {off_r10}]",
        "mov r11, [r12 + {off_r11}]",               // 用户 RFLAGS
        "mov r13, [r12 + {off_r13}]",
        "mov r14, [r12 + {off_r14}]",
        "mov r15, [r12 + {off_r15}]",

        // 恢复用户 RSP（必须在 r12 恢复前完成）
        "mov rsp, [r12 + {off_rsp}]",

        // 最后恢复 r12
        "mov r12, [r12 + {off_r12}]",

        // ========================================
        // 阶段 7: 返回用户态 (SYSRET 快速路径)
        // ========================================
        "sysretq",                                  // 返回用户态

        // ========================================
        // IRETQ 回退路径：非规范或高半区地址
        // ========================================
        "2:",
        // Z-1 fix: IRETQ 路径也需要恢复 FPU 状态（r13 仍指向 FPU 保存区）
        "fxrstor64 [r13]",
        "mov rcx, [r12 + {off_rcx}]",               // 用户 RIP
        "mov rbx, [r12 + {off_rbx}]",
        "mov rbp, [r12 + {off_rbp}]",
        "mov rsi, [r12 + {off_rsi}]",
        "mov rdi, [r12 + {off_rdi}]",
        "mov r8,  [r12 + {off_r8}]",
        "mov r9,  [r12 + {off_r9}]",
        "mov r10, [r12 + {off_r10}]",
        "mov r11, [r12 + {off_r11}]",               // 用户 RFLAGS
        "mov r13, [r12 + {off_r13}]",
        "mov r14, [r12 + {off_r14}]",
        "mov r15, [r12 + {off_r15}]",
        "mov rdx, [r12 + {off_rsp}]",               // 用户 RSP (临时保存到 rdx)
        // 构建 IRETQ 帧
        "push {user_ss}",
        "push rdx",                                 // 用户 RSP
        "push r11",                                 // 用户 RFLAGS
        "push {user_cs}",
        "push rcx",                                 // 用户 RIP
        "mov rdx, [r12 + {off_rdx}]",               // 恢复用户 rdx
        "mov r12, [r12 + {off_r12}]",               // 恢复 r12
        "iretq",                                    // 通过 IRETQ 返回用户态

        // 符号绑定
        // R23-2 fix: 符号绑定 - 使用 per-CPU 数组（当前 CPU ID = 0，使用 slot 0）
        // 未来 SMP 支持时，需要在汇编中根据 APIC ID 计算偏移
        user_rsp_arr = sym SYSCALL_USER_RSP_SHADOWS,
        scratch_stacks = sym SYSCALL_SCRATCH_STACKS,
        scratch_size = const SYSCALL_SCRATCH_SIZE,
        frame_size = const SYSCALL_FRAME_SIZE,
        frame_qwords = const SYSCALL_FRAME_QWORDS,
        fpu_save_size = const FPU_SAVE_AREA_SIZE,
        off_rax = const OFF_RAX,
        off_rcx = const OFF_RCX,
        off_rdx = const OFF_RDX,
        off_rbx = const OFF_RBX,
        off_rsp = const OFF_RSP,
        off_rbp = const OFF_RBP,
        off_rsi = const OFF_RSI,
        off_rdi = const OFF_RDI,
        off_r8 = const OFF_R8,
        off_r9 = const OFF_R9,
        off_r10 = const OFF_R10,
        off_r11 = const OFF_R11,
        off_r12 = const OFF_R12,
        off_r13 = const OFF_R13,
        off_r14 = const OFF_R14,
        off_r15 = const OFF_R15,
        get_rsp0 = sym syscall_get_kernel_rsp0,
        dispatcher = sym syscall_dispatcher_bridge,
        user_cs = const USER_CODE_SELECTOR,
        user_ss = const USER_DATA_SELECTOR,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msr_helpers() {
        assert_eq!(IA32_STAR, 0xC000_0081);
        assert_eq!(IA32_LSTAR, 0xC000_0082);
    }

    #[test]
    fn test_frame_layout() {
        // 验证帧大小正确
        assert_eq!(SYSCALL_FRAME_SIZE, 128);
        // 验证所有偏移量都在帧范围内
        assert!(OFF_R15 + 8 <= SYSCALL_FRAME_SIZE);
        // Z-1 fix: 验证 FPU 保存区大小和对齐要求
        assert_eq!(FPU_SAVE_AREA_SIZE, 512);
        assert_eq!(FPU_SAVE_AREA_SIZE % 16, 0); // FXSAVE 需要 16B 对齐
    }
}
