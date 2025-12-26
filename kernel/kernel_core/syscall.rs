//! 系统调用接口
//!
//! 实现类POSIX系统调用，提供用户程序与内核交互的接口
//!
//! # Audit Integration
//!
//! All syscalls are audited with entry and exit events for security monitoring.
//! Events include: syscall number, arguments, result, and process context.

use crate::fork::PAGE_REF_COUNT;
use crate::process::{
    cleanup_zombie, create_process, current_pid, get_process, terminate_process, ProcessId,
    ProcessState,
};
use crate::usercopy::UserAccessGuard;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

// Audit integration for syscall security monitoring
use audit::{AuditKind, AuditObject, AuditOutcome, AuditSubject};

// Seccomp/Pledge syscall filtering
extern crate seccomp;

// LSM hook infrastructure
extern crate lsm;

/// 最大参数数量（防止恶意用户传递过多参数）
const MAX_ARG_COUNT: usize = 256;

// ============================================================================
// Seccomp/Prctl Constants (Linux x86_64 ABI)
// ============================================================================

/// Seccomp operation modes
const SECCOMP_SET_MODE_STRICT: u32 = 0;
const SECCOMP_SET_MODE_FILTER: u32 = 1;

/// Seccomp mode return values for prctl(PR_GET_SECCOMP)
const SECCOMP_MODE_DISABLED: usize = 0;
const SECCOMP_MODE_STRICT: usize = 1;
const SECCOMP_MODE_FILTER: usize = 2;

/// prctl option codes for seccomp operations
const PR_GET_SECCOMP: i32 = 21;
const PR_SET_SECCOMP: i32 = 22;
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_GET_NO_NEW_PRIVS: i32 = 39;

/// User-space BPF instruction opcodes (simplified encoding)
/// These define the wire format for filters passed from userspace
const SECCOMP_USER_OP_LD_NR: u8 = 0;
const SECCOMP_USER_OP_LD_ARG: u8 = 1;
const SECCOMP_USER_OP_LD_CONST: u8 = 2;
const SECCOMP_USER_OP_AND: u8 = 3;
const SECCOMP_USER_OP_OR: u8 = 4;
const SECCOMP_USER_OP_SHR: u8 = 5;
const SECCOMP_USER_OP_JMP_EQ: u8 = 6;
const SECCOMP_USER_OP_JMP_NE: u8 = 7;
const SECCOMP_USER_OP_JMP_LT: u8 = 8;
const SECCOMP_USER_OP_JMP_LE: u8 = 9;
const SECCOMP_USER_OP_JMP_GT: u8 = 10;
const SECCOMP_USER_OP_JMP_GE: u8 = 11;
const SECCOMP_USER_OP_JMP: u8 = 12;
const SECCOMP_USER_OP_RET: u8 = 13;

/// Seccomp action codes for RET instruction
const SECCOMP_USER_ACTION_ALLOW: u32 = 0;
const SECCOMP_USER_ACTION_LOG: u32 = 1;
const SECCOMP_USER_ACTION_ERRNO: u32 = 2;
const SECCOMP_USER_ACTION_TRAP: u32 = 3;
const SECCOMP_USER_ACTION_KILL: u32 = 4;

/// User-space seccomp instruction structure
/// Matches the format passed from userspace via sys_seccomp(FILTER)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UserSeccompInsn {
    /// Opcode (SECCOMP_USER_OP_*)
    op: u8,
    _padding: [u8; 7],
    /// First operand (varies by opcode)
    arg0: u64,
    /// Second operand (jump targets for conditional jumps)
    arg1: u64,
    /// Third operand (false branch offset for conditional jumps)
    arg2: u64,
}

/// User-space seccomp program header
/// Describes the filter to be installed
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UserSeccompProg {
    /// Number of instructions
    len: u32,
    /// Default action (applied when no instruction returns)
    default_action: u32,
    /// Pointer to instruction array
    filter: u64, // Using u64 instead of *const for safe Copy
}

// ============================================================================
// Linux ABI struct definitions for new syscalls
// ============================================================================

/// AT_FDCWD sentinel for *at() syscalls (openat, fstatat, etc.)
const AT_FDCWD: i32 = -100;

/// struct timeval (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

/// struct timespec (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// struct utsname (Linux ABI, fixed-size strings)
#[repr(C)]
#[derive(Clone, Copy)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
        }
    }
}

/// Linux dirent64 layout for getdents64 syscall
#[repr(C)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // followed by name bytes + '\0'
}

// ============================================================================
// R23-5 fix: stdin 阻塞等待支持
// ============================================================================

use alloc::collections::VecDeque;

/// stdin 等待队列
///
/// 当 sys_read(fd=0) 没有数据时，进程会被加入此队列并阻塞。
/// 键盘/串口中断通过 wake_stdin_waiters() 唤醒等待者。
static STDIN_WAITERS: spin::Mutex<VecDeque<ProcessId>> = spin::Mutex::new(VecDeque::new());

/// 准备等待 stdin 输入（第一阶段）
///
/// 在检查缓冲区为空后调用此函数，将当前进程加入等待队列。
/// 必须在持有键盘缓冲区检查的同一临界区内调用，以避免丢失唤醒。
///
/// # Returns
///
/// 成功入队返回 true，无当前进程返回 false
fn stdin_prepare_to_wait() -> bool {
    let pid = match current_pid() {
        Some(p) => p,
        None => return false,
    };

    // 在关中断状态下操作
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut waiters = STDIN_WAITERS.lock();

        // 避免重复添加：检查是否已经在等待队列中
        // 这防止了当 force_reschedule 返回（因没有其他进程）时
        // 进程在循环中反复将自己添加到队列导致内存耗尽
        if !waiters.iter().any(|&p| p == pid) {
            waiters.push_back(pid);
        }

        // 将进程状态设为阻塞
        if let Some(proc_arc) = get_process(pid) {
            let mut proc = proc_arc.lock();
            proc.state = ProcessState::Blocked;
        }
    });

    true
}

/// 完成等待（第二阶段）
///
/// 在 prepare_to_wait 后调用，实际让出 CPU。
/// 如果没有其他进程可调度，会进入 HLT 循环等待中断唤醒。
fn stdin_finish_wait() {
    // 尝试切换到其他进程
    crate::force_reschedule();

    // 如果 force_reschedule 返回，说明没有其他进程可运行
    // 当前进程已被标记为 Blocked，需要等待中断（键盘/串口）唤醒
    // 进入 HLT 循环，避免忙等消耗 CPU
    loop {
        // 必须在关中断状态下检查进程状态，避免与中断处理程序竞争
        // enable_and_hlt 后中断是开启的，需要先关闭再检查
        let should_continue = x86_64::instructions::interrupts::without_interrupts(|| {
            if let Some(pid) = current_pid() {
                if let Some(proc_arc) = get_process(pid) {
                    let proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        // 已被唤醒（可能是键盘中断），退出等待
                        return false;
                    }
                }
            }
            true // 继续等待
        });

        if !should_continue {
            break;
        }

        // 启用中断并等待（HLT 会在下一个中断时唤醒）
        // 键盘/串口中断会调用 wake_stdin_waiters() 将进程设为 Ready
        x86_64::instructions::interrupts::enable_and_hlt();
    }
}

/// 唤醒一个等待 stdin 的进程
///
/// 由键盘/串口中断处理器调用。
/// 使用 wake_one 语义以避免惊群效应。
pub fn wake_stdin_waiters() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut waiters = STDIN_WAITERS.lock();
        // 清理已退出的进程并唤醒第一个有效等待者
        while let Some(pid) = waiters.pop_front() {
            if let Some(proc_arc) = get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.state = ProcessState::Ready;
                    return; // 只唤醒一个
                }
            }
            // 进程不存在或不在阻塞状态，继续检查下一个
        }
    });
}

/// 最大参数总字节数（argv + envp 字符串总大小上限）
const MAX_ARG_TOTAL: usize = 128 * 1024;

/// 单个参数最大长度
const MAX_ARG_STRLEN: usize = 4096;

/// 最大单次读写长度（X-2 安全修复：防止内核堆耗尽 DoS）
///
/// 用户可请求任意大小的 count，如果不限制会导致：
/// - 内核尝试分配 GB 级别的 Vec
/// - OOM panic 或堆耗尽
/// - 任意用户进程可 DoS 整个系统
///
/// Linux 通常允许单次最大 2GB，但考虑到 Zero-OS 是微内核，
/// 1MB 上限足够大多数场景，同时保护内核免受资源耗尽攻击。
const MAX_RW_SIZE: usize = 1 * 1024 * 1024;

/// 系统调用号定义（参考Linux系统调用表）
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // 进程管理
    Exit = 60,           // 退出进程
    ExitGroup = 231,     // 退出进程组
    Fork = 57,           // 创建子进程
    Exec = 59,           // 执行程序
    Wait = 61,           // 等待子进程
    GetPid = 39,         // 获取进程ID
    GetTid = 186,        // 获取线程ID
    GetPPid = 110,       // 获取父进程ID
    SetTidAddress = 218, // 设置 clear_child_tid
    SetRobustList = 273, // 设置 robust_list
    Kill = 62,           // 发送信号

    // 文件I/O
    Read = 0,   // 读取文件
    Write = 1,  // 写入文件
    Open = 2,   // 打开文件
    Close = 3,  // 关闭文件
    Stat = 4,   // 获取文件状态
    Fstat = 5,  // 获取文件描述符状态
    Lseek = 8,  // 移动文件指针
    Ioctl = 16, // I/O 控制

    // 内存管理
    Brk = 12,      // 改变数据段大小
    Mmap = 9,      // 内存映射
    Munmap = 11,   // 取消内存映射
    Mprotect = 10, // 设置内存保护

    // 进程间通信
    Pipe = 22, // 创建管道
    Dup = 32,  // 复制文件描述符
    Dup2 = 33, // 复制文件描述符到指定位置

    // 时间相关
    Time = 201,  // 获取时间
    Sleep = 35,  // 睡眠
    Futex = 202, // 快速用户空间互斥锁

    // 其他
    Yield = 24,      // 主动让出CPU
    GetCwd = 79,     // 获取当前工作目录
    Chdir = 80,      // 改变当前工作目录
    GetRandom = 318, // 获取随机字节
}

/// 系统调用错误码
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    Success = 0,   // 成功
    EPERM = -1,    // 操作不允许
    ENOENT = -2,   // 文件或目录不存在
    ESRCH = -3,    // 进程不存在
    EINTR = -4,    // 系统调用被中断
    EIO = -5,      // I/O错误
    ENXIO = -6,    // 设备不存在
    E2BIG = -7,    // 参数列表过长
    ENOEXEC = -8,  // 执行格式错误
    EBADF = -9,    // 文件描述符错误
    ECHILD = -10,  // 没有子进程
    EAGAIN = -11,  // 资源暂时不可用
    ENOMEM = -12,  // 内存不足
    EACCES = -13,  // 权限不足
    EFAULT = -14,  // 地址错误
    EBUSY = -16,   // 设备或资源忙
    EEXIST = -17,  // 文件已存在
    ENOTDIR = -20, // 不是目录
    EISDIR = -21,  // 是目录
    EINVAL = -22,  // 无效参数
    ENFILE = -23,  // 系统打开文件过多
    EMFILE = -24,  // 进程打开文件过多
    ENOTTY = -25,  // 不是终端设备
    EPIPE = -32,   // 管道破裂
    ERANGE = -34,  // 结果超出范围
    ENOSYS = -38,  // 功能未实现
    ENOTEMPTY = -39, // 目录非空
}

impl SyscallError {
    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

/// 系统调用结果类型
pub type SyscallResult = Result<usize, SyscallError>;

// ============================================================================
// Syscall 帧访问（供 clone/fork 使用）
// ============================================================================

/// Syscall 帧结构（与 arch::syscall 中的布局一致）
///
/// 表示 syscall_entry_stub 保存到内核栈上的寄存器帧。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    pub rax: u64,  // 0x00: 系统调用号 / 返回值
    pub rcx: u64,  // 0x08: 用户 RIP (syscall 保存)
    pub rdx: u64,  // 0x10: arg2
    pub rbx: u64,  // 0x18: callee-saved
    pub rsp: u64,  // 0x20: 用户 RSP
    pub rbp: u64,  // 0x28: callee-saved
    pub rsi: u64,  // 0x30: arg1
    pub rdi: u64,  // 0x38: arg0
    pub r8: u64,   // 0x40: arg4
    pub r9: u64,   // 0x48: arg5
    pub r10: u64,  // 0x50: arg3
    pub r11: u64,  // 0x58: 用户 RFLAGS (syscall 保存)
    pub r12: u64,  // 0x60: callee-saved
    pub r13: u64,  // 0x68: callee-saved
    pub r14: u64,  // 0x70: callee-saved
    pub r15: u64,  // 0x78: callee-saved
}

/// 获取当前 syscall 帧的回调类型
///
/// 由 arch 模块注册，用于 clone/fork 读取调用者的寄存器状态
pub type GetSyscallFrameCallback = fn() -> Option<&'static SyscallFrame>;

/// 全局 syscall 帧回调
static SYSCALL_FRAME_CALLBACK: spin::Mutex<Option<GetSyscallFrameCallback>> =
    spin::Mutex::new(None);

/// 注册获取 syscall 帧的回调
///
/// 由 arch 模块在初始化时调用
pub fn register_syscall_frame_callback(cb: GetSyscallFrameCallback) {
    *SYSCALL_FRAME_CALLBACK.lock() = Some(cb);
}

/// 获取当前 syscall 帧
///
/// 仅在 syscall 处理期间有效，用于 clone/fork
fn get_current_syscall_frame() -> Option<&'static SyscallFrame> {
    if let Some(cb) = *SYSCALL_FRAME_CALLBACK.lock() {
        cb()
    } else {
        None
    }
}

/// 管道创建回调类型
///
/// 由 ipc 模块注册，返回 (read_fd, write_fd) 或错误
pub type PipeCreateCallback = fn() -> Result<(i32, i32), SyscallError>;

/// 文件描述符读取回调类型
///
/// 由 ipc 模块注册，处理管道等文件描述符的读取
/// 参数: (fd, buf, count) -> bytes_read 或错误
pub type FdReadCallback = fn(i32, &mut [u8]) -> Result<usize, SyscallError>;

/// 文件描述符写入回调类型
///
/// 由 ipc 模块注册，处理管道等文件描述符的写入
/// 参数: (fd, buf) -> bytes_written 或错误
pub type FdWriteCallback = fn(i32, &[u8]) -> Result<usize, SyscallError>;

/// 文件描述符关闭回调类型
///
/// 由 ipc 模块注册，处理文件描述符的关闭
pub type FdCloseCallback = fn(i32) -> Result<(), SyscallError>;

/// Futex 操作回调类型
///
/// 由 ipc 模块注册，处理 FUTEX_WAIT 和 FUTEX_WAKE 操作
/// 参数: (uaddr, op, val, current_value) -> result 或错误
pub type FutexCallback = fn(usize, i32, u32, u32) -> Result<usize, SyscallError>;

/// VFS 打开文件回调类型
///
/// 由 vfs 模块注册，处理文件打开
/// 参数: (path, flags, mode) -> FileOps box 或错误
/// 返回的 FileOps 由 syscall 模块存入 fd_table
pub type VfsOpenCallback =
    fn(&str, u32, u32) -> Result<crate::process::FileDescriptor, SyscallError>;

/// VFS 获取文件状态回调类型
///
/// 由 vfs 模块注册，处理 stat 系统调用
/// 参数: (path) -> (size, mode, ino, dev, nlink, uid, gid, rdev, atime, mtime, ctime) 或错误
pub type VfsStatCallback = fn(&str) -> Result<VfsStat, SyscallError>;

/// VFS lseek 回调类型
///
/// 由 vfs 模块注册，处理文件 seek 操作
/// 参数: (file_ops_ref, offset, whence) -> 新偏移位置 或错误
/// file_ops_ref 是通过 as_any 获取的引用
pub type VfsLseekCallback = fn(&dyn core::any::Any, i64, i32) -> Result<u64, SyscallError>;

/// VFS 创建文件/目录回调类型
///
/// 由 vfs 模块注册，处理文件和目录创建
/// 参数: (path, mode, is_dir) -> () 或错误
pub type VfsCreateCallback = fn(&str, u32, bool) -> Result<(), SyscallError>;

/// VFS 删除文件/目录回调类型
///
/// 由 vfs 模块注册，处理文件和目录删除
/// 参数: (path) -> () 或错误
pub type VfsUnlinkCallback = fn(&str) -> Result<(), SyscallError>;

/// VFS 读取目录项回调类型
///
/// 由 vfs 模块注册，处理目录内容读取
/// 参数: (fd, buf) -> 返回实际读取的目录项列表
pub type VfsReaddirCallback = fn(i32) -> Result<alloc::vec::Vec<DirEntry>, SyscallError>;

/// VFS 截断文件回调类型
///
/// 由 vfs 模块注册，处理文件截断操作
/// 参数: (fd, length) -> () 或错误
pub type VfsTruncateCallback = fn(i32, u64) -> Result<(), SyscallError>;

/// 文件类型枚举(本地定义避免循环依赖)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Symlink,
    Fifo,
    Socket,
}

/// 目录项结构(本地定义避免循环依赖)
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub ino: u64,
    pub file_type: FileType,
}

/// VFS 文件状态信息
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VfsStat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

lazy_static::lazy_static! {
    /// 管道创建回调
    static ref PIPE_CREATE_CALLBACK: spin::Mutex<Option<PipeCreateCallback>> = spin::Mutex::new(None);
    /// 文件描述符读取回调
    static ref FD_READ_CALLBACK: spin::Mutex<Option<FdReadCallback>> = spin::Mutex::new(None);
    /// 文件描述符写入回调
    static ref FD_WRITE_CALLBACK: spin::Mutex<Option<FdWriteCallback>> = spin::Mutex::new(None);
    /// 文件描述符关闭回调
    static ref FD_CLOSE_CALLBACK: spin::Mutex<Option<FdCloseCallback>> = spin::Mutex::new(None);
    /// Futex 操作回调
    static ref FUTEX_CALLBACK: spin::Mutex<Option<FutexCallback>> = spin::Mutex::new(None);
    /// VFS 打开文件回调
    static ref VFS_OPEN_CALLBACK: spin::Mutex<Option<VfsOpenCallback>> = spin::Mutex::new(None);
    /// VFS stat 回调
    static ref VFS_STAT_CALLBACK: spin::Mutex<Option<VfsStatCallback>> = spin::Mutex::new(None);
    /// VFS lseek 回调
    static ref VFS_LSEEK_CALLBACK: spin::Mutex<Option<VfsLseekCallback>> = spin::Mutex::new(None);
    /// VFS 创建回调
    static ref VFS_CREATE_CALLBACK: spin::Mutex<Option<VfsCreateCallback>> = spin::Mutex::new(None);
    /// VFS 删除回调
    static ref VFS_UNLINK_CALLBACK: spin::Mutex<Option<VfsUnlinkCallback>> = spin::Mutex::new(None);
    /// VFS 读取目录回调
    static ref VFS_READDIR_CALLBACK: spin::Mutex<Option<VfsReaddirCallback>> = spin::Mutex::new(None);
    /// VFS 截断回调
    static ref VFS_TRUNCATE_CALLBACK: spin::Mutex<Option<VfsTruncateCallback>> = spin::Mutex::new(None);
}

/// 注册管道创建回调
pub fn register_pipe_callback(cb: PipeCreateCallback) {
    *PIPE_CREATE_CALLBACK.lock() = Some(cb);
}

/// 注册文件描述符读取回调
pub fn register_fd_read_callback(cb: FdReadCallback) {
    *FD_READ_CALLBACK.lock() = Some(cb);
}

/// 注册文件描述符写入回调
pub fn register_fd_write_callback(cb: FdWriteCallback) {
    *FD_WRITE_CALLBACK.lock() = Some(cb);
}

/// 注册文件描述符关闭回调
pub fn register_fd_close_callback(cb: FdCloseCallback) {
    *FD_CLOSE_CALLBACK.lock() = Some(cb);
}

/// 注册 Futex 操作回调
pub fn register_futex_callback(cb: FutexCallback) {
    *FUTEX_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 打开文件回调
pub fn register_vfs_open_callback(cb: VfsOpenCallback) {
    *VFS_OPEN_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS stat 回调
pub fn register_vfs_stat_callback(cb: VfsStatCallback) {
    *VFS_STAT_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS lseek 回调
pub fn register_vfs_lseek_callback(cb: VfsLseekCallback) {
    *VFS_LSEEK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 创建回调
pub fn register_vfs_create_callback(cb: VfsCreateCallback) {
    *VFS_CREATE_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 删除回调
pub fn register_vfs_unlink_callback(cb: VfsUnlinkCallback) {
    *VFS_UNLINK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 读取目录回调
pub fn register_vfs_readdir_callback(cb: VfsReaddirCallback) {
    *VFS_READDIR_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 截断回调
pub fn register_vfs_truncate_callback(cb: VfsTruncateCallback) {
    *VFS_TRUNCATE_CALLBACK.lock() = Some(cb);
}

// ============================================================================
// VFS 辅助函数
// ============================================================================

/// S_IFDIR 常量 - 目录类型标识
const S_IFDIR: u32 = 0o040000;
/// S_IFMT 常量 - 文件类型掩码
const S_IFMT: u32 = 0o170000;

/// 检查 mode 是否表示目录
#[inline]
fn is_directory_mode(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

/// 用户空间地址上界
///
/// x86_64 规范地址空间中，用户空间使用低半区（0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF）
/// 内核空间使用高半区（0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF）
const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

/// sys_exec 允许的最大 ELF 映像大小（16 MB）
///
/// 防止恶意用户请求过大的内存分配导致内核资源耗尽
const MAX_EXEC_IMAGE_SIZE: usize = 16 * 1024 * 1024;

// mmap 跟踪已移至 Process 结构体的 mmap_regions 和 next_mmap_addr 字段

/// 验证用户空间指针
///
/// 检查指针是否：
/// 1. 非空
/// 2. 长度有效（非零）
/// 3. 地址范围在用户空间内（不会访问内核内存）
/// 4. 不会发生地址回绕
///
/// # Arguments
/// * `ptr` - 用户提供的指针
/// * `len` - 要访问的字节数
///
/// # Returns
/// 如果指针有效返回 Ok(()), 否则返回 EFAULT 错误
fn validate_user_ptr(ptr: *const u8, len: usize) -> Result<(), SyscallError> {
    // 空指针检查
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 零长度检查
    if len == 0 {
        return Err(SyscallError::EFAULT);
    }

    let start = ptr as usize;

    // 地址回绕检查
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(SyscallError::EFAULT),
    };

    // 用户空间边界检查：确保整个缓冲区都在用户空间内
    if end > USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }

    Ok(())
}

/// 验证用户空间可写指针
///
/// 与 validate_user_ptr 相同的检查，用于写入操作
#[inline]
fn validate_user_ptr_mut(ptr: *mut u8, len: usize) -> Result<(), SyscallError> {
    validate_user_ptr(ptr as *const u8, len)
}

/// 验证用户空间地址是否已映射且具备所需权限
///
/// 通过页表遍历验证地址范围内的每一页都已映射且具有正确的权限标志。
/// 这比 validate_user_ptr 更严格，可以防止访问未映射内存导致的内核崩溃。
///
/// # Arguments
/// * `ptr` - 用户空间缓冲区起始地址
/// * `len` - 缓冲区长度
/// * `require_write` - 是否需要写入权限
///
/// # Returns
/// 如果所有页都已正确映射返回 Ok(()), 否则返回 EFAULT
fn verify_user_memory(ptr: *const u8, len: usize, require_write: bool) -> Result<(), SyscallError> {
    // 先进行基本的边界检查
    validate_user_ptr(ptr, len)?;

    if len == 0 {
        return Ok(());
    }

    let start = ptr as usize;
    let end = start.checked_add(len).ok_or(SyscallError::EFAULT)?;

    // 遍历页表验证映射
    unsafe {
        mm::page_table::with_current_manager(
            VirtAddr::new(0),
            |manager| -> Result<(), SyscallError> {
                let mut page_addr = start & !0xfff; // 对齐到页边界
                while page_addr < end {
                    // 查询页表获取映射信息和标志
                    let (_, flags) = manager
                        .translate_with_flags(VirtAddr::new(page_addr as u64))
                        .ok_or(SyscallError::EFAULT)?;

                    // 检查页是否存在且用户可访问
                    if !flags.contains(PageTableFlags::PRESENT)
                        || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
                    {
                        return Err(SyscallError::EFAULT);
                    }

                    // 如果需要写入权限，检查 WRITABLE 或 BIT_9 (COW) 标志
                    // COW 页面标记为只读但有 BIT_9，写入时会触发 #PF 并由 COW 处理器创建可写副本
                    // 真正的只读页面（如代码段）没有这两个标志，应该拒绝写入
                    if require_write
                        && !flags.contains(PageTableFlags::WRITABLE)
                        && !flags.contains(PageTableFlags::BIT_9)
                    {
                        return Err(SyscallError::EFAULT);
                    }

                    page_addr = page_addr.checked_add(0x1000).ok_or(SyscallError::EFAULT)?;
                }
                Ok(())
            },
        )
    }
}

/// 从用户态缓冲区安全复制数据到内核缓冲区
///
/// 使用容错拷贝机制：如果在拷贝过程中发生页错误，
/// 会返回 EFAULT 而非导致内核 panic（解决 TOCTOU 竞态条件）。
///
/// # Arguments
/// * `dest` - 内核缓冲区（目标）
/// * `user_src` - 用户空间缓冲区（源）
///
/// # Returns
/// 复制成功返回 Ok(()), 如果用户内存未映射返回 EFAULT
fn copy_from_user(dest: &mut [u8], user_src: *const u8) -> Result<(), SyscallError> {
    if dest.is_empty() {
        return Ok(());
    }

    // 先进行基本的边界检查（地址范围验证）
    validate_user_ptr(user_src, dest.len())?;

    // 使用容错拷贝：逐字节复制，页错误时返回 EFAULT
    crate::usercopy::copy_from_user_safe(dest, user_src).map_err(|_| SyscallError::EFAULT)
}

/// 将内核缓冲区的数据安全复制到用户态缓冲区
///
/// 使用容错拷贝机制：如果在拷贝过程中发生页错误，
/// 会返回 EFAULT 而非导致内核 panic（解决 TOCTOU 竞态条件）。
///
/// 注意：COW 页面会在写入时触发页错误，由 COW 处理器创建可写副本。
///
/// # Arguments
/// * `user_dst` - 用户空间缓冲区（目标）
/// * `src` - 内核缓冲区（源）
///
/// # Returns
/// 复制成功返回 Ok(()), 如果用户内存未映射或不可写返回 EFAULT
fn copy_to_user(user_dst: *mut u8, src: &[u8]) -> Result<(), SyscallError> {
    if src.is_empty() {
        return Ok(());
    }

    // 先进行基本的边界检查（地址范围验证）
    validate_user_ptr(user_dst as *const u8, src.len())?;

    // 使用容错拷贝：逐字节复制，页错误时返回 EFAULT
    // COW 页面会在 usercopy 过程中触发 #PF，由 COW 处理器处理
    crate::usercopy::copy_to_user_safe(user_dst, src).map_err(|_| SyscallError::EFAULT)
}

/// 从用户空间复制以 '\0' 结尾的 C 字符串到内核缓冲区
///
/// V-2 fix: 使用 usercopy 容错拷贝机制，防止 TOCTOU 攻击。
/// 如果用户在验证后取消映射内存，copy_from_user_safe 会安全返回错误
/// 而不是导致内核 panic。
///
/// 逐字节读取直到遇到 NUL 终止符，限制最大长度防止恶意无限字符串。
fn copy_user_cstring(ptr: *const u8) -> Result<Vec<u8>, SyscallError> {
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let mut buf = Vec::new();

    for i in 0..=MAX_ARG_STRLEN {
        // V-2 fix: 使用容错单字节拷贝
        // copy_from_user_safe 内部会：
        // 1. 创建 UserAccessGuard 处理 SMAP
        // 2. 创建 UserCopyGuard 登记 usercopy 状态
        // 3. 页错误时安全返回 Err 而非 panic
        let mut byte = [0u8; 1];
        crate::usercopy::copy_from_user_safe(&mut byte, unsafe { ptr.add(i) })
            .map_err(|_| SyscallError::EFAULT)?;

        if byte[0] == 0 {
            return Ok(buf);
        }
        buf.push(byte[0]);
    }

    // 字符串超过最大长度限制
    Err(SyscallError::E2BIG)
}

/// 将用户空间的字符串指针数组（以 NULL 结尾）复制到内核
///
/// V-2 fix: 使用 usercopy 容错拷贝机制读取指针数组，防止 TOCTOU 攻击。
///
/// 用于 exec 的 argv 和 envp 参数
fn copy_user_str_array(list_ptr: *const *const u8) -> Result<Vec<Vec<u8>>, SyscallError> {
    // NULL 指针表示空数组
    if list_ptr.is_null() {
        return Ok(Vec::new());
    }

    let word = mem::size_of::<usize>();
    let base = list_ptr as usize;
    let mut items: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;

    for idx in 0..MAX_ARG_COUNT {
        // 计算当前条目地址
        let entry_addr = base.checked_add(idx * word).ok_or(SyscallError::EFAULT)?;

        // V-2 fix: 使用容错拷贝读取指针值
        // 这确保了即使用户在我们读取时取消映射，也不会导致内核 panic
        let mut raw_ptr = [0u8; core::mem::size_of::<usize>()];
        crate::usercopy::copy_from_user_safe(&mut raw_ptr, entry_addr as *const u8)
            .map_err(|_| SyscallError::EFAULT)?;
        let entry = usize::from_ne_bytes(raw_ptr) as *const u8;

        if entry.is_null() {
            break; // NULL 终止
        }

        // 复制字符串内容（copy_user_cstring 现在也使用容错拷贝）
        let s = copy_user_cstring(entry)?;
        total = total
            .checked_add(s.len() + 1) // +1 for trailing '\0'
            .ok_or(SyscallError::E2BIG)?;
        if total > MAX_ARG_TOTAL {
            return Err(SyscallError::E2BIG);
        }

        items.push(s);
    }

    // 检查是否超过最大参数数量（没有遇到 NULL 终止）
    if items.len() == MAX_ARG_COUNT {
        return Err(SyscallError::E2BIG);
    }

    Ok(items)
}

/// 初始化系统调用处理器
pub fn init() {
    println!("Syscall handler initialized");
    println!("  Supported syscalls: exit, fork, getpid, read, write, yield");
}

/// Get audit subject from current process context
///
/// Returns AuditSubject with pid, uid, gid from current process credentials.
/// Falls back to kernel subject (pid 0) if no current process.
#[inline]
fn get_audit_subject() -> AuditSubject {
    if let Some(pid) = current_pid() {
        if let Some(creds) = crate::process::current_credentials() {
            AuditSubject::new(pid as u32, creds.euid, creds.egid, None)
        } else {
            // Process exists but credentials unavailable
            AuditSubject::new(pid as u32, 0, 0, None)
        }
    } else {
        AuditSubject::kernel()
    }
}

// ============================================================================
// LSM Integration Helpers
// ============================================================================

/// Map LSM errors to syscall errno values.
#[inline]
fn lsm_error_to_syscall(err: lsm::LsmError) -> SyscallError {
    match err {
        lsm::LsmError::Denied => SyscallError::EPERM,
        lsm::LsmError::Internal => SyscallError::EPERM,
    }
}

/// R26-6 FIX: Map capability errors to syscall errno values.
///
/// This ensures proper error reporting when capability operations fail,
/// rather than silently swallowing errors.
#[inline]
#[allow(dead_code)] // Will be used when capability syscalls are added
fn cap_error_to_syscall(err: cap::CapError) -> SyscallError {
    match err {
        cap::CapError::TableFull => SyscallError::EMFILE,
        cap::CapError::GenerationExhausted => SyscallError::ERANGE, // No EOVERFLOW, use ERANGE
        cap::CapError::InvalidCapId => SyscallError::EBADF,
        cap::CapError::DelegationDenied => SyscallError::EPERM,
        cap::CapError::InsufficientRights => SyscallError::EPERM,
        cap::CapError::InvalidOperation => SyscallError::EINVAL,
        cap::CapError::NoCurrentProcess => SyscallError::ESRCH,
    }
}

/// Build an LSM ProcessCtx from current process state.
/// Returns None if no current process is available.
#[inline]
fn lsm_current_process_ctx() -> Option<lsm::ProcessCtx> {
    lsm::ProcessCtx::from_current()
}

/// Build an LSM ProcessCtx from a locked Process struct.
#[inline]
fn lsm_process_ctx_from(proc: &crate::process::Process) -> lsm::ProcessCtx {
    lsm::ProcessCtx::new(
        proc.pid,
        proc.tgid,
        proc.uid,
        proc.gid,
        proc.euid,
        proc.egid,
    )
}

/// Enforce task_fork LSM hook after fork/clone succeeds.
/// On denial, cleans up the child process and returns EPERM.
fn enforce_lsm_task_fork(parent_pid: ProcessId, child_pid: ProcessId) -> Result<(), SyscallError> {
    let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;
    let child_arc = get_process(child_pid).ok_or(SyscallError::ESRCH)?;

    let (parent_ctx, child_ctx) = {
        let parent = parent_arc.lock();
        let child = child_arc.lock();
        (lsm_process_ctx_from(&parent), lsm_process_ctx_from(&child))
    };

    if let Err(err) = lsm::hook_task_fork(&parent_ctx, &child_ctx) {
        // Rollback: remove child from parent's children list and terminate
        if let Some(parent) = get_process(parent_pid) {
            let mut parent = parent.lock();
            parent.children.retain(|&pid| pid != child_pid);
        }
        // Use exit code 128 + signal (SIGSYS=31) to indicate security termination
        terminate_process(child_pid, 128 + 31);
        cleanup_zombie(child_pid);
        return Err(lsm_error_to_syscall(err));
    }

    Ok(())
}

/// 系统调用分发器
///
/// 根据系统调用号和参数执行相应的系统调用
///
/// # Audit Trail
///
/// All syscalls emit an audit event after completion with:
/// - Syscall number and up to 6 arguments
/// - Success/Error outcome
/// - Process context (pid, uid, gid)
///
/// 在返回前检查 NEED_RESCHED 标志，如果需要则执行调度。
/// 这是 NEED_RESCHED 的主要消费点，确保时间片到期后能在返回用户态前触发调度。
pub fn syscall_dispatcher(
    syscall_num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    // Capture timestamp at syscall entry
    let timestamp = crate::time::get_ticks();

    // Evaluate seccomp/pledge filters before dispatch
    let args = [arg0, arg1, arg2, arg3, arg4, arg5];
    let verdict = crate::process::evaluate_seccomp(syscall_num, &args);

    match verdict.action {
        seccomp::SeccompAction::Kill => {
            // R25-4 FIX: Kill process with SIGSYS semantics - audit and terminate
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                    // Actually terminate the process (SIGSYS exit code: 128 + 31)
                    crate::process::terminate_process(pid, 128 + 31);
                    crate::process::cleanup_zombie(pid);
                }
            }
            return SyscallError::EPERM as i64;
        }
        seccomp::SeccompAction::Trap => {
            // R25-4 FIX: Trap treated as fatal until SIGSYS delivery is implemented
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                    // Terminate with SIGSYS semantics until proper signal delivery exists
                    crate::process::terminate_process(pid, 128 + 31);
                    crate::process::cleanup_zombie(pid);
                }
            }
            return SyscallError::EPERM as i64;
        }
        seccomp::SeccompAction::Errno(e) => {
            // Return the error code - audit the violation
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                }
            }
            return -(e as i64);
        }
        seccomp::SeccompAction::Log => {
            // Log the violation but continue
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                }
            }
            // Fall through to dispatch
        }
        seccomp::SeccompAction::Allow => {
            // Continue to dispatch
        }
    }

    // LSM hook: check syscall entry with security policy
    // Build context before dispatch; on denial, return EPERM
    let lsm_ctx = lsm::SyscallCtx::from_current(syscall_num, &args);
    if let Some(ref ctx) = lsm_ctx {
        if let Err(err) = lsm::hook_syscall_enter(ctx) {
            // LSM denied the syscall - call exit hook and return error
            let errno = lsm_error_to_syscall(err);
            let ret = errno.as_i64();
            let _ = lsm::hook_syscall_exit(ctx, ret as isize);
            return ret;
        }
    }

    let result = match syscall_num {
        // 进程管理
        56 => sys_clone(arg0, arg1 as *mut u8, arg2 as *mut i32, arg3 as *mut i32, arg4),
        60 => sys_exit(arg0 as i32),
        231 => sys_exit_group(arg0 as i32),
        57 => sys_fork(),
        59 => sys_exec(
            arg0 as *const u8,
            arg1 as usize,
            arg2 as *const *const u8,
            arg3 as *const *const u8,
        ),
        61 => sys_wait(arg0 as *mut i32),
        39 => sys_getpid(),
        186 => sys_gettid(),
        110 => sys_getppid(),
        102 => sys_getuid(),
        107 => sys_geteuid(),
        104 => sys_getgid(),
        108 => sys_getegid(),
        218 => sys_set_tid_address(arg0 as *mut i32),
        273 => sys_set_robust_list(arg0 as *const u8, arg1 as usize),
        62 => sys_kill(arg0 as ProcessId, arg1 as i32),

        // 文件I/O
        0 => sys_read(arg0 as i32, arg1 as *mut u8, arg2 as usize),
        1 => sys_write(arg0 as i32, arg1 as *const u8, arg2 as usize),
        2 => sys_open(arg0 as *const u8, arg1 as i32, arg2 as u32),
        257 => sys_openat(arg0 as i32, arg1 as *const u8, arg2 as i32, arg3 as u32),
        3 => sys_close(arg0 as i32),
        4 => sys_stat(arg0 as *const u8, arg1 as *mut VfsStat),
        5 => sys_fstat(arg0 as i32, arg1 as *mut VfsStat),
        6 => sys_lstat(arg0 as *const u8, arg1 as *mut VfsStat),
        262 => sys_fstatat(arg0 as i32, arg1 as *const u8, arg2 as *mut VfsStat, arg3 as i32),
        8 => sys_lseek(arg0 as i32, arg1 as i64, arg2 as i32),
        16 => sys_ioctl(arg0 as i32, arg1, arg2),
        20 => sys_writev(arg0 as i32, arg1 as *const Iovec, arg2 as usize),
        22 => sys_pipe(arg0 as *mut i32),
        32 => sys_dup(arg0 as i32),
        33 => sys_dup2(arg0 as i32, arg1 as i32),
        292 => sys_dup3(arg0 as i32, arg1 as i32, arg2 as i32),
        77 => sys_ftruncate(arg0 as i32, arg1 as i64),
        217 => sys_getdents64(arg0 as i32, arg1 as *mut u8, arg2 as usize),

        // 文件系统操作
        21 => sys_access(arg0 as *const u8, arg1 as i32),
        79 => sys_getcwd(arg0 as *mut u8, arg1 as usize),
        80 => sys_chdir(arg0 as *const u8),
        83 => sys_mkdir(arg0 as *const u8, arg1 as u32),
        84 => sys_rmdir(arg0 as *const u8),
        87 => sys_unlink(arg0 as *const u8),
        90 => sys_chmod(arg0 as *const u8, arg1 as u32),
        91 => sys_fchmod(arg0 as i32, arg1 as u32),
        95 => sys_umask(arg0 as u32),

        // 内存管理
        12 => sys_brk(arg0 as usize),
        9 => sys_mmap(
            arg0 as usize,
            arg1 as usize,
            arg2 as i32,
            arg3 as i32,
            arg4 as i32,
            arg5 as i64,
        ),
        10 => sys_mprotect(arg0 as usize, arg1 as usize, arg2 as i32),
        11 => sys_munmap(arg0 as usize, arg1 as usize),

        // 架构相关
        158 => sys_arch_prctl(arg0 as i32, arg1 as u64),

        // Futex
        202 => sys_futex(arg0 as usize, arg1 as i32, arg2 as u32),

        // 安全/沙箱 (Seccomp/Prctl)
        157 => sys_prctl(arg0 as i32, arg1, arg2, arg3, arg4),
        317 => sys_seccomp(arg0 as u32, arg1 as u32, arg2),

        // 时间相关
        35 => sys_nanosleep(arg0 as *const TimeSpec, arg1 as *mut TimeSpec),
        96 => sys_gettimeofday(arg0 as *mut TimeVal, arg1 as usize),

        // 系统信息
        63 => sys_uname(arg0 as *mut UtsName),

        // 其他
        24 => sys_yield(),
        318 => sys_getrandom(arg0 as *mut u8, arg1 as usize, arg2 as u32),

        _ => Err(SyscallError::ENOSYS),
    };

    // Emit audit event for syscall completion
    // Note: This is after the syscall so we capture the outcome
    let (outcome, errno) = match &result {
        Ok(_) => (AuditOutcome::Success, 0),
        Err(e) => (AuditOutcome::Error, e.as_i64() as i32),
    };

    // Emit audit event (ignore errors - audit should never block syscalls)
    // Include all 6 arguments for syscalls like mmap that use all of them
    let _ = audit::emit(
        AuditKind::Syscall,
        outcome,
        get_audit_subject(),
        AuditObject::None,
        &[syscall_num, arg0, arg1, arg2, arg3, arg4, arg5],
        errno,
        timestamp,
    );

    // LSM hook: notify security policy of syscall exit
    if let Some(ref ctx) = lsm_ctx {
        let ret = match &result {
            Ok(val) => *val as isize,
            Err(e) => e.as_i64() as isize,
        };
        let _ = lsm::hook_syscall_exit(ctx, ret);
    }

    // 在返回用户态前检查是否需要调度
    // 这是定时器中断设置的 NEED_RESCHED 标志的主要消费点
    crate::reschedule_if_needed();

    match result {
        Ok(val) => val as i64,
        Err(err) => err.as_i64(),
    }
}

// ============================================================================
// 进程管理系统调用
// ============================================================================

/// sys_exit - 终止当前进程
fn sys_exit(exit_code: i32) -> SyscallResult {
    if let Some(pid) = current_pid() {
        // LSM hook: notify policy of process exit (informational, doesn't block)
        if let Some(exit_ctx) = lsm_current_process_ctx() {
            let _ = lsm::hook_task_exit(&exit_ctx, exit_code);
        }

        terminate_process(pid, exit_code);
        println!("Process {} exited with code {}", pid, exit_code);

        // 退出的进程不应继续运行，立即让出 CPU
        // 这也会触发等待中的父进程被调度
        crate::force_reschedule();

        // 如果调度器选择了其他进程，这里不会返回
        // 如果没有其他进程，系统会回到这里（但进程已是 Zombie 状态）
        // 在这种情况下，我们必须阻止返回到用户空间
        // 进入无限循环等待中断（其他进程可能会在定时器中断中被创建）
        println!("[sys_exit] No other process to run, entering idle loop");
        loop {
            x86_64::instructions::hlt();
        }
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_exit_group - 终止进程组
///
/// 在当前单进程实现中，语义等同于 sys_exit。
/// 完整实现应终止同一进程组内的所有线程。
fn sys_exit_group(exit_code: i32) -> SyscallResult {
    // 当前为单进程模型，直接委托给 sys_exit
    sys_exit(exit_code)
}

/// sys_fork - 创建子进程
fn sys_fork() -> SyscallResult {
    let parent_pid = current_pid().ok_or(SyscallError::ESRCH)?;

    // 调用真正的 fork 实现（包含 COW 支持）
    match crate::fork::sys_fork() {
        Ok(child_pid) => {
            // LSM hook: check if policy allows this fork
            enforce_lsm_task_fork(parent_pid, child_pid)?;
            Ok(child_pid)
        }
        Err(_) => Err(SyscallError::ENOMEM),
    }
}

// ============================================================================
// Clone Flags (Linux x86_64 ABI)
// ============================================================================

/// 共享虚拟内存空间
const CLONE_VM: u64 = 0x0000_0100;
/// 共享文件系统信息
const CLONE_FS: u64 = 0x0000_0200;
/// 共享文件描述符表
const CLONE_FILES: u64 = 0x0000_0400;
/// 共享信号处理器
const CLONE_SIGHAND: u64 = 0x0000_0800;
/// 加入同一线程组
const CLONE_THREAD: u64 = 0x0001_0000;
/// 设置 TLS
const CLONE_SETTLS: u64 = 0x0008_0000;
/// 在父进程写入子 TID
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
/// 子进程退出时清除 TID 并唤醒 futex
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// 在子进程写入 TID
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

/// sys_clone - 创建线程/轻量级进程
///
/// 根据 flags 创建新的执行上下文，支持共享地址空间（线程）或独立地址空间（进程）。
///
/// # Arguments (Linux x86_64 ABI)
///
/// * `flags` - clone 标志位组合
/// * `stack` - 子进程/线程的用户栈指针（可为 NULL 使用父栈）
/// * `parent_tid` - CLONE_PARENT_SETTID 时写入子 TID 的地址
/// * `child_tid` - CLONE_CHILD_SETTID/CLONE_CHILD_CLEARTID 时使用的地址
/// * `tls` - CLONE_SETTLS 时设置的 TLS base 地址
///
/// # Returns
///
/// * 父进程：返回子进程/线程的 TID
/// * 子进程/线程：返回 0（通过设置 context.rax = 0）
fn sys_clone(
    flags: u64,
    stack: *mut u8,
    parent_tid: *mut i32,
    child_tid: *mut i32,
    tls: u64,
) -> SyscallResult {
    println!(
        "[sys_clone] entry: flags=0x{:x}, stack=0x{:x}, tls=0x{:x}",
        flags, stack as u64, tls
    );

    let parent_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;

    // 支持的 flags
    let supported_flags = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID;

    // 检查不支持的 flags
    // 返回 EINVAL 而不是 ENOSYS，因为这是参数验证失败而非功能未实现
    if flags & !supported_flags != 0 {
        println!(
            "sys_clone: unsupported flags 0x{:x}",
            flags & !supported_flags
        );
        return Err(SyscallError::EINVAL);
    }

    // CLONE_THREAD 要求必须同时设置 CLONE_VM 和 CLONE_SIGHAND
    if flags & CLONE_THREAD != 0 {
        if flags & CLONE_VM == 0 || flags & CLONE_SIGHAND == 0 {
            return Err(SyscallError::EINVAL);
        }
    }

    // 验证 parent_tid 指针
    if flags & CLONE_PARENT_SETTID != 0 {
        if parent_tid.is_null() {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr_mut(parent_tid as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(parent_tid as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 验证 child_tid 指针
    if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 {
        if child_tid.is_null() {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr_mut(child_tid as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(child_tid as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 验证栈指针（如果提供）
    if !stack.is_null() {
        validate_user_ptr(stack as *const u8, 1)?;
    }

    // 从 MSR 读取当前 FS_BASE（TLS 基址）
    // musl 可能通过 wrfsbase 指令直接设置 FS base，绕过 arch_prctl
    // 因此 PCB 中的 fs_base 可能是 0，需要从硬件同步
    let current_fs_base = {
        use x86_64::registers::model_specific::Msr;
        const MSR_FS_BASE: u32 = 0xC000_0100;
        unsafe { Msr::new(MSR_FS_BASE).read() }
    };

    // 从父进程收集必要信息
    let (
        parent_space,
        parent_tgid,
        parent_mmap,
        parent_next_mmap,
        parent_brk_start,
        parent_brk,
        parent_name,
        parent_priority,
        parent_context,
        parent_user_stack,
        parent_fs_base,
        parent_gs_base,
        parent_uid,
        parent_gid,
        parent_euid,
        parent_egid,
        parent_umask,
        parent_seccomp_state,
        parent_pledge_state,
        parent_seccomp_installing,
    ) = {
        let mut parent = parent_arc.lock();
        // 始终从 MSR 同步 fs_base 到 PCB
        // 这确保即使进程通过 wrfsbase 指令修改了 TLS（绕过 arch_prctl），
        // 子进程也能继承正确的 TLS 基址
        if current_fs_base != 0 {
            parent.fs_base = current_fs_base;
        }
        (
            parent.memory_space,
            parent.tgid,
            parent.mmap_regions.clone(),
            parent.next_mmap_addr,
            parent.brk_start,
            parent.brk,
            parent.name.clone(),
            parent.priority,
            parent.context,
            parent.user_stack,
            parent.fs_base,
            parent.gs_base,
            parent.uid,
            parent.gid,
            parent.euid,
            parent.egid,
            parent.umask,
            parent.seccomp_state.clone(),
            parent.pledge_state.clone(),
            parent.seccomp_installing,
        )
    };

    // 决定使用的地址空间
    let (child_space, is_shared_space) = if flags & CLONE_VM != 0 {
        // CLONE_VM: 共享父进程的地址空间
        (parent_space, true)
    } else {
        // 不共享地址空间：使用 COW fork
        match crate::fork::sys_fork() {
            Ok(child_pid) => {
                // fork 成功，执行 LSM 检查
                // 这种情况很少见（clone 不带 CLONE_VM 通常就是 fork）
                enforce_lsm_task_fork(parent_pid, child_pid)?;
                return Ok(child_pid);
            }
            Err(_) => return Err(SyscallError::ENOMEM),
        }
    };

    // 创建子任务名称
    let child_name = if flags & CLONE_THREAD != 0 {
        alloc::format!("{}-thread", parent_name)
    } else {
        alloc::format!("{}-clone", parent_name)
    };

    // 创建新进程/线程
    let child_pid = create_process(child_name, parent_pid, parent_priority)
        .map_err(|_| SyscallError::ENOMEM)?;

    let child_arc = get_process(child_pid).ok_or(SyscallError::ESRCH)?;

    {
        let mut child = child_arc.lock();

        // 设置线程标识
        child.tid = child_pid; // tid == pid (Linux 语义)
        if flags & CLONE_THREAD != 0 {
            // R26-3 FIX: Reject thread creation if parent is installing seccomp filter
            // This prevents TOCTOU race where new thread escapes sandbox
            if parent_seccomp_installing {
                // Clean up: terminate the child process we just created
                child.state = ProcessState::Terminated;
                drop(child);
                crate::process::terminate_process(child_pid, -1);
                return Err(SyscallError::EBUSY);
            }
            child.tgid = parent_tgid; // 加入父进程的线程组
            child.is_thread = true;
        } else {
            child.tgid = child_pid; // 新线程组
            child.is_thread = false;
        }

        // 设置地址空间
        child.memory_space = child_space;
        if is_shared_space {
            // 共享地址空间时复制相关元数据
            child.mmap_regions = parent_mmap;
            child.next_mmap_addr = parent_next_mmap;
            child.brk_start = parent_brk_start;
            child.brk = parent_brk;
        }

        // 从当前 syscall 帧构建子进程上下文
        // 使用 syscall 帧而非 parent.context，因为后者是上次调度时的状态
        if let Some(frame) = get_current_syscall_frame() {
            // Debug: 打印 SyscallFrame 原始值
            println!(
                "[sys_clone] SyscallFrame: rcx(rip)=0x{:x}, rsp=0x{:x}, r9=0x{:x}",
                frame.rcx, frame.rsp, frame.r9
            );

            // 从 syscall 帧复制寄存器状态
            child.context.rax = 0; // 子进程 clone 返回值 = 0
            child.context.rbx = frame.rbx;
            child.context.rcx = frame.rcx; // 用户 RIP (SYSCALL 保存)
            child.context.rdx = frame.rdx;
            child.context.rsi = frame.rsi;
            child.context.rdi = frame.rdi;
            child.context.rbp = frame.rbp;
            child.context.r8 = frame.r8;
            child.context.r9 = frame.r9;
            child.context.r10 = frame.r10;
            child.context.r11 = frame.r11; // 用户 RFLAGS
            child.context.r12 = frame.r12;
            child.context.r13 = frame.r13;
            child.context.r14 = frame.r14;
            child.context.r15 = frame.r15;
            // RIP = RCX (syscall 保存的用户返回地址)
            child.context.rip = frame.rcx;
            // RFLAGS = R11 (syscall 保存的用户 RFLAGS)
            child.context.rflags = frame.r11;
            // 用户态段选择子
            child.context.cs = 0x23; // USER_CODE_SELECTOR
            child.context.ss = 0x1b; // USER_DATA_SELECTOR

            // 设置栈指针
            if !stack.is_null() {
                let sp = stack as u64;
                child.context.rsp = sp;
                child.context.rbp = sp; // 子线程清空 frame pointer
                child.user_stack = Some(VirtAddr::new(sp));
            } else {
                child.context.rsp = frame.rsp;
                child.user_stack = parent_user_stack;
            }
        } else {
            // 回退：使用 parent.context（不应该发生）
            println!("sys_clone: WARNING - syscall frame not available, using stale context");
            child.context = parent_context;
            child.context.rax = 0;
            if !stack.is_null() {
                let sp = stack as u64;
                child.context.rsp = sp;
                child.context.rbp = sp;
                child.user_stack = Some(VirtAddr::new(sp));
            } else {
                child.user_stack = parent_user_stack;
            }
        }

        // Debug: 打印子进程上下文关键寄存器
        println!(
            "[sys_clone] Child {} ctx: rax=0x{:x}, rip=0x{:x}, rsp=0x{:x}, r9=0x{:x}, rcx=0x{:x}",
            child_pid, child.context.rax, child.context.rip, child.context.rsp, child.context.r9, child.context.rcx
        );

        // 设置 TLS
        // R24-2 fix: 验证 TLS 基址是 canonical 且在用户空间范围内
        // 避免非法地址导致后续 WRMSR 时 #GP 内核崩溃
        if flags & CLONE_SETTLS != 0 {
            if !is_canonical(tls) || tls >= USER_SPACE_TOP as u64 {
                // 非法 TLS 地址：先释放child锁再清理，避免死锁
                // 标记进程为终止状态并清零共享地址空间引用
                child.state = ProcessState::Terminated;
                child.memory_space = 0; // 不释放共享地址空间
                drop(child);
                // 通过cleanup_zombie安全地从进程表移除
                // 但由于子进程还未设置为Zombie状态，我们直接使用terminate
                // 注意：此时子进程未被调度，terminate_process安全
                crate::process::terminate_process(child_pid, -1);
                return Err(SyscallError::EINVAL);
            }
            child.fs_base = tls;
        } else {
            child.fs_base = parent_fs_base;
        }
        child.gs_base = parent_gs_base;

        // Debug: 打印 TLS 信息
        println!(
            "[sys_clone] TLS: msr_fs=0x{:x}, parent_fs=0x{:x}, child_fs=0x{:x}",
            current_fs_base, parent_fs_base, child.fs_base
        );

        // 设置 tid 指针
        if flags & CLONE_CHILD_SETTID != 0 {
            child.set_child_tid = child_tid as u64;
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            child.clear_child_tid = child_tid as u64;
        }

        // 复制凭证
        child.uid = parent_uid;
        child.gid = parent_gid;
        child.euid = parent_euid;
        child.egid = parent_egid;
        child.umask = parent_umask;

        // 继承 Seccomp/Pledge 沙箱状态
        // - 过滤器栈通过 Arc 共享，父子进程共享同一过滤器对象
        // - no_new_privs 是粘滞标志，一旦设置无法清除
        // - pledge 状态包括当前 promises 和 exec_promises（exec 后生效）
        child.seccomp_state = parent_seccomp_state;
        child.pledge_state = parent_pledge_state;

        // 复制文件描述符表（CLONE_FILES 时理论上应共享，但当前架构暂用克隆）
        if flags & CLONE_FILES != 0 {
            let parent = parent_arc.lock();
            for (&fd, desc) in parent.fd_table.iter() {
                child.fd_table.insert(fd, desc.clone_box());
            }
        }

        // 克隆能力表（CLONE_THREAD 时共享，否则克隆并过滤 CLOFORK）
        //
        // 对于线程（CLONE_THREAD），共享父进程的能力表（通过 Arc）
        // 对于进程（无 CLONE_THREAD），使用 clone_for_fork() 过滤 CLOFORK 条目
        //
        // 注意：与 fd_table 不同，cap_table 使用 Arc 包装，天然支持共享
        if flags & CLONE_THREAD != 0 {
            // 线程：共享父进程的能力表
            let parent = parent_arc.lock();
            child.cap_table = parent.cap_table.clone();
        } else {
            // R25-8 FIX: 非线程情况（包括CLONE_FILES和默认进程语义）
            // 都必须继承能力表并过滤 CLOFORK 条目
            let parent = parent_arc.lock();
            child.cap_table = Arc::new(parent.cap_table.clone_for_fork());
        }

        // 设置进程状态为就绪
        child.state = ProcessState::Ready;
    }

    // 写入 parent_tid
    if flags & CLONE_PARENT_SETTID != 0 {
        let tid_bytes = (child_pid as i32).to_ne_bytes();
        copy_to_user(parent_tid as *mut u8, &tid_bytes)?;
    }

    // 写入 child_tid（在父进程的地址空间中，因为共享）
    if flags & CLONE_CHILD_SETTID != 0 {
        let tid_bytes = (child_pid as i32).to_ne_bytes();
        copy_to_user(child_tid as *mut u8, &tid_bytes)?;
    }

    // LSM hook: check if policy allows this fork/clone
    // Must be BEFORE scheduler notification to prevent denied child from running
    enforce_lsm_task_fork(parent_pid, child_pid)?;

    // 将子进程添加到调度器（通过回调，避免循环依赖）
    if let Some(child_arc) = get_process(child_pid) {
        crate::process::notify_scheduler_add_process(child_arc);
    }

    println!(
        "sys_clone: parent={}, child={}, flags=0x{:x}, is_thread={}",
        parent_pid,
        child_pid,
        flags,
        flags & CLONE_THREAD != 0
    );

    Ok(child_pid)
}

/// sys_exec - 执行新程序
///
/// 将当前进程的地址空间替换为新的 ELF 可执行映像
///
/// # Arguments
///
/// * `image` - 指向用户态 ELF 映像的指针
/// * `image_len` - ELF 映像长度（字节数）
/// * `argv` - 命令行参数数组（NULL 结尾）
/// * `envp` - 环境变量数组（NULL 结尾）
///
/// # Safety
///
/// 用户指针在切换 CR3 前必须先复制到内核堆，否则地址失效
fn sys_exec(
    image: *const u8,
    image_len: usize,
    argv: *const *const u8,
    envp: *const *const u8,
) -> SyscallResult {
    use crate::elf_loader::{load_elf, USER_STACK_SIZE};
    use crate::fork::create_fresh_address_space;
    use crate::process::{
        activate_memory_space, current_pid, free_address_space, get_process, ProcessState,
    };

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 验证参数：非空、合理大小
    if image.is_null() || image_len == 0 {
        return Err(SyscallError::EINVAL);
    }
    if image_len > MAX_EXEC_IMAGE_SIZE {
        println!(
            "sys_exec: ELF size {} exceeds limit {}",
            image_len, MAX_EXEC_IMAGE_SIZE
        );
        return Err(SyscallError::E2BIG);
    }

    // 【关键】在切换 CR3 前将用户数据复制到内核堆
    // 切换地址空间后原用户指针将失效
    let mut elf_data = vec![0u8; image_len];
    copy_from_user(&mut elf_data, image)?;

    // 复制 argv 和 envp 到内核
    let argv_vec = copy_user_str_array(argv)?;
    let envp_vec = copy_user_str_array(envp)?;

    // LSM hook: check if policy allows this exec
    // Use path hash from first argv element (program name) for policy check
    let path_hash = argv_vec
        .first()
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .map(|s| audit::hash_path(s))
        .unwrap_or(0);

    if let Some(exec_ctx) = lsm_current_process_ctx() {
        if let Err(err) = lsm::hook_task_exec(&exec_ctx, path_hash) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 创建新的地址空间
    let (_new_pml4_frame, new_memory_space) =
        create_fresh_address_space().map_err(|_| SyscallError::ENOMEM)?;

    // 保存旧地址空间以便失败时恢复或成功时释放
    let old_memory_space = {
        let proc = process.lock();
        proc.memory_space
    };

    // S-7 fix: RAII guard to rollback address space on error
    //
    // After switching CR3, any error must restore the old address space
    // and free the new one. This guard ensures automatic rollback.
    struct ExecSpaceGuard {
        old_space: usize,
        new_space: usize,
        committed: bool,
    }

    impl ExecSpaceGuard {
        fn new(old_space: usize, new_space: usize) -> Self {
            Self {
                old_space,
                new_space,
                committed: false,
            }
        }

        /// Mark the exec as successful, preventing rollback on drop
        fn commit(&mut self) {
            self.committed = true;
        }
    }

    impl Drop for ExecSpaceGuard {
        fn drop(&mut self) {
            if !self.committed {
                // Rollback: restore old address space and free new one
                crate::process::activate_memory_space(self.old_space);
                crate::process::free_address_space(self.new_space);
            }
        }
    }

    // Create the guard before switching CR3
    let mut space_guard = ExecSpaceGuard::new(old_memory_space, new_memory_space);

    // 切换到新地址空间
    activate_memory_space(new_memory_space);

    // 加载 ELF 映像
    // S-7 fix: Let the guard handle rollback on error
    let load_result = load_elf(&elf_data).map_err(|e| {
        println!("sys_exec: ELF load failed: {:?}", e);
        SyscallError::ENOEXEC
    })?;

    // =========================================================================
    // 构建符合 System V AMD64 ABI 的用户栈布局：
    //
    // 高地址 (栈顶方向)
    //   +------------------+
    //   | 字符串数据区      |  <- argv[0] 字符串, argv[1] 字符串, ..., envp[0], ...
    //   +------------------+
    //   | 16字节对齐填充    |
    //   +------------------+
    //   | NULL (envp终止)   |
    //   | envp[n-1] 指针    |
    //   | ...              |
    //   | envp[0] 指针      |
    //   | NULL (argv终止)   |
    //   | argv[n-1] 指针    |
    //   | ...              |
    //   | argv[0] 指针      |
    //   | argc             |  <- RSP 指向这里
    //   +------------------+
    // 低地址 (栈底方向)
    // =========================================================================

    let argc = argv_vec.len();
    let envc = envp_vec.len();
    let word = mem::size_of::<usize>();

    // 计算字符串总大小
    let string_bytes: usize = argv_vec
        .iter()
        .chain(envp_vec.iter())
        .map(|s| s.len() + 1) // +1 for '\0'
        .sum();

    // 指针区大小: argc + argv_ptrs + NULL + envp_ptrs + NULL
    let pointer_count = 1 + argc + 1 + envc + 1;
    let pointer_bytes = pointer_count * word;

    // 检查栈空间是否足够
    let stack_top = load_result.user_stack_top as usize;
    let stack_base = stack_top
        .checked_sub(USER_STACK_SIZE)
        .ok_or(SyscallError::EFAULT)?;

    // Allow supervisor access to user pages for stack construction when SMAP is enabled
    let _user_access = UserAccessGuard::new();

    let total_needed = string_bytes + pointer_bytes + 16; // +16 for alignment
    if total_needed > USER_STACK_SIZE {
        return Err(SyscallError::E2BIG);
    }

    let mut sp = stack_top;
    let mut argv_ptrs: Vec<usize> = Vec::with_capacity(argc);
    let mut envp_ptrs: Vec<usize> = Vec::with_capacity(envc);

    // 1. 复制 argv 字符串（从高地址向低地址生长）
    for s in argv_vec.iter().rev() {
        let len = s.len();
        sp = sp.checked_sub(len + 1).ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), sp as *mut u8, len);
            *((sp + len) as *mut u8) = 0; // NUL 终止
        }
        argv_ptrs.push(sp);
    }
    argv_ptrs.reverse(); // 恢复正序

    // 2. 复制 envp 字符串
    for s in envp_vec.iter().rev() {
        let len = s.len();
        sp = sp.checked_sub(len + 1).ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), sp as *mut u8, len);
            *((sp + len) as *mut u8) = 0;
        }
        envp_ptrs.push(sp);
    }
    envp_ptrs.reverse();

    // 3. 16 字节对齐
    sp &= !0xF;

    // 4. 检查指针区空间是否足够
    if sp < stack_base + pointer_bytes {
        return Err(SyscallError::E2BIG);
    }

    // 5. 确保最终 RSP 满足 SysV AMD64 ABI 要求
    // 进程入口点要求 (RSP % 16) == 8，这样第一个 PUSH 后 RSP 才是 16 字节对齐
    // 注意：直接跳转到 _start 不经过 CALL，所以 RSP 需要预留 8 字节偏移
    let final_sp = sp - pointer_bytes;
    if (final_sp & 0xF) == 0 {
        // 当前是 16 对齐，需要调整为 16+8
        sp -= word; // 添加填充使最终 RSP % 16 == 8
        unsafe {
            *(sp as *mut usize) = 0;
        }
    }

    // 6. 压入指针区（从高地址向低地址）
    unsafe {
        // envp NULL 终止
        sp -= word;
        *(sp as *mut usize) = 0;

        // envp 指针数组（逆序压入）
        for ptr in envp_ptrs.iter().rev() {
            sp -= word;
            *(sp as *mut usize) = *ptr;
        }

        // argv NULL 终止
        sp -= word;
        *(sp as *mut usize) = 0;

        // argv 指针数组（逆序压入）
        for ptr in argv_ptrs.iter().rev() {
            sp -= word;
            *(sp as *mut usize) = *ptr;
        }

        // argc
        sp -= word;
        *(sp as *mut usize) = argc;
    }

    let final_rsp = sp as u64;
    let argv_base = (sp + word) as u64; // argv[0] 的地址

    // 更新进程 PCB
    let old_space = {
        let mut proc = process.lock();

        let old_space = proc.memory_space;
        proc.memory_space = new_memory_space;
        proc.user_stack = Some(VirtAddr::new(load_result.user_stack_top));

        // 设置上下文
        proc.context.rip = load_result.entry;
        proc.context.rsp = final_rsp;
        proc.context.rbp = final_rsp;

        // 用户态段选择子（Ring 3）
        proc.context.cs = 0x1B;
        proc.context.ss = 0x23;
        proc.context.rflags = 0x202;

        // System V AMD64 调用约定：RDI = argc, RSI = argv
        proc.context.rdi = argc as u64;
        proc.context.rsi = argv_base;

        // 清零其他寄存器
        proc.context.rax = 0;
        proc.context.rbx = 0;
        proc.context.rcx = 0;
        proc.context.rdx = 0;
        proc.context.r8 = 0;
        proc.context.r9 = 0;
        proc.context.r10 = 0;
        proc.context.r11 = 0;
        proc.context.r12 = 0;
        proc.context.r13 = 0;
        proc.context.r14 = 0;
        proc.context.r15 = 0;

        proc.mmap_regions.clear();
        proc.next_mmap_addr = 0x4000_0000;

        // 初始化堆管理（brk）
        // brk_start 和 brk 初始化为 ELF 最高段末尾（页对齐）
        // 这确保 brk(0) 返回正确的初始值，malloc 才能正常工作
        proc.brk_start = load_result.brk_start;
        proc.brk = load_result.brk_start;

        // 重置 TLS 状态（新程序需要重新设置）
        proc.fs_base = 0;
        proc.gs_base = 0;

        // OpenBSD Pledge 语义：exec 后应用 exec_promises
        // 如果进程设置了 exec_promises，则在 exec 成功后将其替换为当前 promises
        // 这允许进程在 exec 前声明一组更宽松的权限（用于加载程序），
        // exec 后自动收紧到更严格的权限集
        if let Some(ref mut pledge) = proc.pledge_state {
            if let Some(exec_promises) = pledge.exec_promises.take() {
                pledge.promises = exec_promises;
            }
        }

        // Seccomp 过滤器在 exec 后保持不变（Linux 语义）
        // no_new_privs 仍然有效，防止特权提升

        // 应用 CLOEXEC 能力：撤销带有 CLOEXEC 标志的能力条目
        //
        // 新加载的程序不应继承标记为 CLOEXEC 的能力，这与文件描述符
        // 的 CLOEXEC 语义一致。apply_cloexec() 会将这些条目撤销并
        // 返回到空闲列表，同时递增生成计数器防止旧 CapId 被复用。
        proc.cap_table.apply_cloexec();

        proc.state = ProcessState::Ready;

        old_space
    };

    // S-7 fix: Commit the exec - prevent guard from rolling back
    // This must be called after all error-prone operations are complete.
    space_guard.commit();

    // 释放旧地址空间
    if old_space != 0 {
        free_address_space(old_space);
    }

    println!(
        "sys_exec: entry=0x{:x}, rsp=0x{:x}, argc={}",
        load_result.entry, final_rsp, argc
    );

    Ok(0)
}

/// sys_wait - 等待子进程
///
/// 阻塞当前进程直到一个子进程终止，然后收割该僵尸进程并返回其 PID 和退出码。
///
/// # Arguments
///
/// * `status` - 指向用户态 i32 的指针，用于存储子进程的退出码。可为 NULL。
///
/// # Returns
///
/// * 成功：返回已终止子进程的 PID
/// * ECHILD：当前进程没有子进程
/// * EFAULT：status 指针无效
fn sys_wait(status: *mut i32) -> SyscallResult {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent = get_process(pid).ok_or(SyscallError::ESRCH)?;

    loop {
        // 【关键修复】先标记为等待状态，再扫描子进程，避免 lost wake-up
        // 如果子进程在我们标记之后、扫描之前退出，terminate_process 会看到我们的等待状态
        // 如果子进程在我们扫描时/之后退出，我们会在扫描中发现它的 Zombie 状态
        let child_list = {
            let mut proc = parent.lock();
            if proc.children.is_empty() {
                return Err(SyscallError::ECHILD);
            }
            // 先标记为等待状态
            proc.state = ProcessState::Blocked;
            proc.waiting_child = Some(0); // 0 表示等待任意子进程
            proc.children.clone()
        };

        // 查找已终止的僵尸子进程
        let mut zombie_child: Option<(ProcessId, i32)> = None;
        let mut stale_pids: vec::Vec<ProcessId> = vec::Vec::new();

        for child_pid in child_list.iter() {
            match get_process(*child_pid) {
                Some(child_proc) => {
                    let child = child_proc.lock();
                    if child.state == ProcessState::Zombie {
                        zombie_child = Some((*child_pid, child.exit_code.unwrap_or(0)));
                        break;
                    }
                }
                None => {
                    // 子进程已被清理但仍在父进程列表中，标记为过期
                    stale_pids.push(*child_pid);
                }
            }
        }

        // 如果找到僵尸子进程，收割并返回
        if let Some((child_pid, exit_code)) = zombie_child {
            // 将退出码写入用户空间（如果提供了 status 指针）
            if !status.is_null() {
                let bytes = exit_code.to_ne_bytes();
                copy_to_user(status as *mut u8, &bytes)?;
            }

            // 从父进程的子进程列表中移除，并恢复 Ready 状态
            {
                let mut proc = parent.lock();
                proc.children.retain(|&c| c != child_pid);
                proc.waiting_child = None;
                proc.state = ProcessState::Ready;
            }

            // 清理僵尸进程资源
            cleanup_zombie(child_pid);

            println!(
                "sys_wait: reaped child {} with exit code {}",
                child_pid, exit_code
            );
            return Ok(child_pid);
        }

        // 清理过期的子进程 PID
        if !stale_pids.is_empty() {
            let mut proc = parent.lock();
            proc.children.retain(|pid| !stale_pids.contains(pid));
            // 如果清理后没有子进程了，恢复状态并返回 ECHILD
            if proc.children.is_empty() {
                proc.state = ProcessState::Ready;
                proc.waiting_child = None;
                return Err(SyscallError::ECHILD);
            }
        }

        // 没有找到僵尸子进程，让出 CPU 等待被唤醒
        // 状态已在循环开始时设为 Blocked，子进程退出时会将其设为 Ready
        crate::force_reschedule();

        // 被唤醒后继续循环，检查是否有僵尸子进程
        // 如果是被子进程退出唤醒的，循环会找到 zombie 并返回
        // 如果是误唤醒，循环会重新设置 Blocked 状态并继续等待
    }
}

/// sys_getpid - 获取当前进程ID
fn sys_getpid() -> SyscallResult {
    if let Some(pid) = current_pid() {
        Ok(pid)
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_getppid - 获取父进程ID
fn sys_getppid() -> SyscallResult {
    if let Some(pid) = current_pid() {
        if let Some(process) = get_process(pid) {
            let proc = process.lock();
            Ok(proc.ppid)
        } else {
            Err(SyscallError::ESRCH)
        }
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_gettid - 获取当前线程ID
///
/// 返回当前线程的 TID。对于主线程，TID == PID == TGID。
/// 对于子线程，TID 是线程的唯一标识，TGID 是所属进程组。
fn sys_gettid() -> SyscallResult {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let proc = process.lock();
    Ok(proc.tid)
}

/// sys_set_tid_address - 设置 clear_child_tid 指针
///
/// musl libc 在启动时调用此函数来注册 TID 清理指针。
/// 当线程退出时，内核应将 0 写入此地址并执行 futex_wake。
///
/// # Arguments
///
/// * `tidptr` - 指向用户空间 i32 的指针，可为 NULL
///
/// # Returns
///
/// 返回调用进程的 TID（当前等于 PID）
fn sys_set_tid_address(tidptr: *mut i32) -> SyscallResult {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 验证用户指针（如果非空）
    if !tidptr.is_null() {
        validate_user_ptr_mut(tidptr as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(tidptr as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 保存指针到进程控制块
    {
        let mut proc = process.lock();
        proc.clear_child_tid = tidptr as u64;
    }

    // 返回当前 TID
    Ok(pid)
}

/// sys_set_robust_list - 注册 robust_list 头指针
///
/// robust_list 用于跟踪进程持有的 robust futex，以便在进程异常退出时
/// 内核能够自动释放这些锁，防止死锁。
///
/// # Arguments
///
/// * `head` - 指向 robust_list_head 结构的用户空间指针
/// * `len` - robust_list_head 结构的大小（必须为 24）
///
/// # Returns
///
/// 成功返回 0
fn sys_set_robust_list(head: *const u8, len: usize) -> SyscallResult {
    /// Linux robust_list_head 结构大小
    /// struct robust_list_head {
    ///     struct robust_list *list;         // 8 bytes
    ///     long futex_offset;                // 8 bytes
    ///     struct robust_list *list_op_pending; // 8 bytes
    /// }
    const ROBUST_LIST_HEAD_SIZE: usize = 24;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 允许 NULL 指针（用于清除）
    if head.is_null() {
        let mut proc = process.lock();
        proc.robust_list_head = 0;
        proc.robust_list_len = 0;
        return Ok(0);
    }

    // Linux 要求 len 必须等于 sizeof(struct robust_list_head) == 24
    if len != ROBUST_LIST_HEAD_SIZE {
        return Err(SyscallError::EINVAL);
    }

    // 验证用户内存
    validate_user_ptr(head, len)?;
    verify_user_memory(head, len, false)?;

    // 保存到进程控制块
    let mut proc = process.lock();
    proc.robust_list_head = head as u64;
    proc.robust_list_len = len;

    Ok(0)
}

/// sys_kill - 发送信号给进程
///
/// # Arguments
///
/// * `pid` - 目标进程 ID
/// * `sig` - 信号编号（1-64）
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
///
/// # Permission Model (Z-9 fix: POSIX-compliant UID/EUID checks)
///
/// POSIX permission rules for kill():
/// - Root (euid == 0) 可以发信号给任何进程
/// - 进程可以向自己发送任意信号
/// - sender.uid == target.uid
/// - sender.euid == target.uid
/// - PID 1 (init) 受保护，只有自己能向自己发信号
fn sys_kill(pid: ProcessId, sig: i32) -> SyscallResult {
    use crate::signal::{send_signal, signal_name, Signal};

    // 【安全修复 Z-9】POSIX 权限检查（防御深度）
    // send_signal 也会进行相同检查，这里提前拒绝以提供更清晰的错误
    if let Some(self_pid) = current_pid() {
        // PID 1 保护：只有 init 自己能向自己发信号
        if pid == 1 && self_pid != 1 {
            return Err(SyscallError::EPERM);
        }

        // 非自己的进程需要进行 POSIX 权限检查
        if self_pid != pid {
            // 获取发送者凭证
            let sender_creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;

            // 获取目标进程凭证
            let target = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let target_uid = target.lock().uid;

            // POSIX 权限检查：
            // 1. Root (euid == 0) 可以发信号给任何进程
            // 2. sender.uid == target.uid
            // 3. sender.euid == target.uid
            let has_permission = sender_creds.euid == 0
                || sender_creds.uid == target_uid
                || sender_creds.euid == target_uid;

            if !has_permission {
                return Err(SyscallError::EPERM);
            }
        }
    }

    // 验证信号编号
    let signal = Signal::from_raw(sig)?;

    // 发送信号
    let action = send_signal(pid, signal)?;

    println!(
        "sys_kill: sent {} to PID {} (action: {:?})",
        signal_name(signal),
        pid,
        action
    );

    Ok(0)
}

// ============================================================================
// 文件I/O系统调用
// ============================================================================

/// sys_pipe - 创建匿名管道
///
/// 创建一个管道，返回两个文件描述符：
/// - fds[0]: 读端
/// - fds[1]: 写端
///
/// # Arguments
///
/// * `fds` - 指向用户空间的 i32[2] 数组，用于返回文件描述符
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
fn sys_pipe(fds: *mut i32) -> SyscallResult {
    // 验证用户指针
    if fds.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 预先验证用户缓冲区可写
    // 这避免了创建管道后因 copy_to_user 失败导致的 fd 泄漏
    validate_user_ptr(fds as *const u8, core::mem::size_of::<[i32; 2]>())?;
    verify_user_memory(fds as *const u8, core::mem::size_of::<[i32; 2]>(), true)?;

    // 获取回调函数指针并立即释放锁
    // 避免在持有锁时执行可能耗时的回调
    let create_fn = {
        let callback = PIPE_CREATE_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用管道创建回调
    let (read_fd, write_fd) = create_fn()?;

    // 将文件描述符写回用户空间
    let fd_array = [read_fd, write_fd];
    let bytes = unsafe {
        core::slice::from_raw_parts(
            fd_array.as_ptr() as *const u8,
            core::mem::size_of::<[i32; 2]>(),
        )
    };

    // copy_to_user 失败时回滚：关闭已创建的文件描述符
    if let Err(e) = copy_to_user(fds as *mut u8, bytes) {
        // 尝试关闭已分配的 fd（通过关闭回调）
        let close_fn = {
            let callback = FD_CLOSE_CALLBACK.lock();
            callback.as_ref().copied()
        };
        if let Some(close) = close_fn {
            let _ = close(read_fd);
            let _ = close(write_fd);
        }
        return Err(e);
    }

    Ok(0)
}

/// sys_read - 从文件描述符读取数据
///
/// # Security (X-2 fix)
///
/// 限制单次读取大小为 MAX_RW_SIZE (1MB)，防止用户请求超大 count
/// 导致内核堆耗尽。在分配缓冲区前先验证用户指针有效性。
///
/// # Security (Z-4 fix)
///
/// 回调返回的 bytes_read 必须 clamp 到请求的 count，防止恶意/错误回调
/// 返回超大值导致切片越界 panic。
fn sys_read(fd: i32, buf: *mut u8, count: usize) -> SyscallResult {
    // X-2 安全修复：限制大小并提前验证
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 预先验证用户缓冲区，避免在分配后发现指针无效
    validate_user_ptr_mut(buf, count)?;

    // stdin (fd 0): 从键盘缓冲区读取字符
    // R23-5 fix: 阻塞模式 - 如果没有输入则等待
    // 使用 prepare-check-finish 模式避免丢失唤醒竞态
    if fd == 0 {
        // Debug: print heap stats before allocation
        #[cfg(debug_assertions)]
        println!("[sys_read] fd=0 count={}", count);

        let mut tmp = vec![0u8; count];
        loop {
            // 先尝试读取
            let bytes_read = drivers::keyboard_read(&mut tmp);
            if bytes_read > 0 {
                copy_to_user(buf, &tmp[..bytes_read])?;
                return Ok(bytes_read);
            }

            // 无数据：先入队再检查（避免丢失唤醒）
            if !stdin_prepare_to_wait() {
                // 无当前进程，返回 0 (EOF)
                return Ok(0);
            }

            // 二次检查：入队后可能有新数据到达
            let bytes_read = drivers::keyboard_read(&mut tmp);
            if bytes_read > 0 {
                // 有数据了，取消等待并返回
                // 注意：我们已经在等待队列中，但进程已被标记为 Blocked
                // 下次唤醒会将我们设为 Ready，但我们不会真正睡眠
                // 这是安全的：最坏情况是多一次调度
                copy_to_user(buf, &tmp[..bytes_read])?;
                return Ok(bytes_read);
            }

            // 确实没有数据，完成等待（让出 CPU）
            stdin_finish_wait();
            // 被唤醒后继续循环尝试读取
        }
    }

    // stdout/stderr 不支持读取
    if fd == 1 || fd == 2 {
        return Err(SyscallError::EBADF);
    }

    // 获取回调函数指针并立即释放锁
    let read_fn = {
        let callback = FD_READ_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::EBADF)?
    };

    // 分配临时缓冲区并执行读取（在锁外）
    let mut tmp = vec![0u8; count];
    let bytes_read = read_fn(fd, &mut tmp)?;

    // Z-4 安全修复：将回调返回值 clamp 到请求的大小
    // 防止恶意/错误回调返回超大值导致切片越界 panic
    let bytes_read = bytes_read.min(count);

    // 复制到用户空间
    copy_to_user(buf, &tmp[..bytes_read])?;
    Ok(bytes_read)
}

/// sys_write - 向文件描述符写入数据
///
/// # Security (X-2 fix)
///
/// 限制单次写入大小为 MAX_RW_SIZE (1MB)，防止用户请求超大 count
/// 导致内核堆耗尽。在分配缓冲区前先验证用户指针有效性。
///
/// # Security (Z-4 fix)
///
/// 回调返回的 bytes_written 必须 clamp 到请求的 count，防止恶意/错误回调
/// 返回超大值。
fn sys_write(fd: i32, buf: *const u8, count: usize) -> SyscallResult {
    // X-2 安全修复：限制大小并提前验证
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 预先验证用户缓冲区，避免在分配后发现指针无效
    validate_user_ptr(buf, count)?;

    // 先复制到内核缓冲区，避免直接解引用用户指针
    let mut tmp = vec![0u8; count];
    copy_from_user(&mut tmp, buf)?;

    // stdout(1)/stderr(2): 直接打印
    if fd == 1 || fd == 2 {
        if let Ok(s) = core::str::from_utf8(&tmp) {
            print!("{}", s);
            Ok(tmp.len())
        } else {
            Err(SyscallError::EINVAL)
        }
    } else if fd == 0 {
        // stdin 不支持写入
        Err(SyscallError::EBADF)
    } else {
        // 获取回调函数指针并立即释放锁
        let write_fn = {
            let callback = FD_WRITE_CALLBACK.lock();
            *callback.as_ref().ok_or(SyscallError::EBADF)?
        };

        // 在锁外执行写入
        let bytes_written = write_fn(fd, &tmp)?;

        // Z-4 安全修复：将回调返回值 clamp 到请求的大小
        Ok(bytes_written.min(count))
    }
}

/// iovec 结构，用于 writev/readv 分散-聚集 I/O
#[repr(C)]
struct Iovec {
    /// 缓冲区起始地址
    iov_base: *const u8,
    /// 缓冲区长度
    iov_len: usize,
}

/// writev 最大 iovec 数量
const IOV_MAX: usize = 1024;

/// sys_writev - 分散写入多个缓冲区
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `iov` - iovec 数组指针
/// * `iovcnt` - iovec 数组元素个数
///
/// # Returns
/// 成功返回写入的总字节数，失败返回错误码
fn sys_writev(fd: i32, iov: *const Iovec, iovcnt: usize) -> SyscallResult {
    use crate::usercopy::{copy_from_user_safe, UserAccessGuard};

    // 验证 iovcnt
    if iovcnt == 0 {
        return Ok(0);
    }
    if iovcnt > IOV_MAX {
        return Err(SyscallError::EINVAL);
    }

    // 验证 iov 指针
    if iov.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let iov_size = iovcnt * mem::size_of::<Iovec>();
    validate_user_ptr(iov as *const u8, iov_size)?;

    // R24-11 fix: Copy iovec array using fault-tolerant usercopy
    // This prevents kernel panic if user unmaps iovec during copy
    let mut iov_array: Vec<Iovec> = Vec::with_capacity(iovcnt);
    {
        let _guard = UserAccessGuard::new();
        for i in 0..iovcnt {
            // Calculate offset for this iovec entry
            let entry_offset = i * mem::size_of::<Iovec>();
            let entry_ptr = (iov as usize + entry_offset) as *const u8;

            // Use fault-tolerant copy for each iovec entry
            let mut entry_bytes = [0u8; mem::size_of::<Iovec>()];
            if copy_from_user_safe(&mut entry_bytes, entry_ptr).is_err() {
                return Err(SyscallError::EFAULT);
            }

            // Safely transmute bytes to Iovec
            // SAFETY: Iovec is repr(C) and all byte patterns are valid
            let iov_entry: Iovec = unsafe { core::ptr::read(entry_bytes.as_ptr() as *const Iovec) };
            iov_array.push(iov_entry);
        }
    }

    // 逐个写入每个缓冲区
    let mut total_written: usize = 0;
    for entry in iov_array.iter() {
        if entry.iov_len == 0 {
            continue;
        }

        // 验证并写入单个缓冲区
        match sys_write(fd, entry.iov_base, entry.iov_len) {
            Ok(written) => {
                total_written += written;
            }
            Err(e) => {
                // 如果已写入部分数据，返回已写入的字节数
                if total_written > 0 {
                    return Ok(total_written);
                }
                return Err(e);
            }
        }
    }

    Ok(total_written)
}

/// sys_open - 打开文件
///
/// # Arguments
/// * `path` - 文件路径（用户空间指针）
/// * `flags` - 打开标志 (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - 创建文件时的权限模式
///
/// # Returns
/// 成功返回文件描述符，失败返回错误码
///
/// # Security (Z-3 fix)
/// 使用 fault-tolerant copy_user_cstring 复制用户路径，防止 TOCTOU 和内核 panic
fn sys_open(path: *const u8, flags: i32, mode: u32) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    // 验证路径指针
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 安全复制路径字符串 (Z-3 fix: fault-tolerant usercopy)
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        core::str::from_utf8(&path_bytes)
            .map_err(|_| SyscallError::EINVAL)?
            .to_string()
    };

    // LSM hook: check file create permission if O_CREAT is set
    let open_flags = flags as u32;
    let path_hash = audit::hash_path(&path_str);

    if let Some(proc_ctx) = lsm_current_process_ctx() {
        // Check create permission first (if O_CREAT)
        if open_flags & lsm::OpenFlags::O_CREAT != 0 {
            // Get parent directory inode and name hash
            let (parent_hash, name_hash) = match path_str.rfind('/') {
                Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
                Some(idx) => (
                    audit::hash_path(&path_str[..idx]),
                    audit::hash_path(&path_str[idx + 1..]),
                ),
                None => (audit::hash_path("."), path_hash),
            };

            if let Err(err) = lsm::hook_file_create(&proc_ctx, parent_hash, name_hash, mode & 0o7777) {
                return Err(lsm_error_to_syscall(err));
            }
        }
    }

    // 获取 VFS 回调
    let open_fn = {
        let callback = VFS_OPEN_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS 打开文件
    let file_ops = open_fn(&path_str, flags as u32, mode)?;

    // LSM hook: check file open permission
    // This is after VFS open to have file metadata, but before fd allocation
    // If denied, file_ops will be dropped (closed) automatically
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let file_ctx = lsm::FileCtx::new(path_hash, mode, path_hash);
        if let Err(err) = lsm::hook_file_open(&proc_ctx, path_hash, lsm::OpenFlags(open_flags), &file_ctx) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 分配文件描述符并存入 fd_table
    let fd = {
        let mut proc = process.lock();
        proc.allocate_fd(file_ops).ok_or(SyscallError::EMFILE)?
    };

    Ok(fd as usize)
}

/// sys_stat - 获取文件状态
///
/// # Arguments
/// * `path` - 文件路径（用户空间指针）
/// * `statbuf` - 指向用户空间 VfsStat 结构体的指针
///
/// # Returns
/// 成功返回 0，失败返回错误码
///
/// # Security (Z-3 fix)
/// 使用 fault-tolerant copy_user_cstring 复制用户路径，防止 TOCTOU 和内核 panic
fn sys_stat(path: *const u8, statbuf: *mut VfsStat) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    // 验证路径指针
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 验证 statbuf 指针
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 安全复制路径字符串 (Z-3 fix: fault-tolerant usercopy)
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        core::str::from_utf8(&path_bytes)
            .map_err(|_| SyscallError::EINVAL)?
            .to_string()
    };

    // 获取 VFS stat 回调
    let stat_fn = {
        let callback = VFS_STAT_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS stat
    let stat = stat_fn(&path_str)?;

    // 将结果写入用户空间
    let stat_bytes = unsafe {
        core::slice::from_raw_parts(
            &stat as *const VfsStat as *const u8,
            core::mem::size_of::<VfsStat>(),
        )
    };
    copy_to_user(statbuf as *mut u8, stat_bytes)?;

    Ok(0)
}

/// sys_fstat - 获取文件描述符状态
///
/// 为 musl libc 提供最小化实现，返回基本文件状态信息。
/// 标准流 (0/1/2) 返回字符设备模式，其他 fd 返回普通文件模式。
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `statbuf` - 指向用户空间 VfsStat 结构体的指针
///
/// # Returns
/// 成功返回 0，失败返回错误码
fn sys_fstat(fd: i32, statbuf: *mut VfsStat) -> SyscallResult {
    // 验证 statbuf 指针
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    validate_user_ptr(statbuf as *const u8, mem::size_of::<VfsStat>())?;
    verify_user_memory(statbuf as *const u8, mem::size_of::<VfsStat>(), true)?;

    // 负数 fd 无效
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }

    // 标准流始终有效，其他 fd 需要检查 fd_table
    if fd > 2 {
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = process.lock();
        if proc.get_fd(fd).is_none() {
            return Err(SyscallError::EBADF);
        }
    }

    // 构造 stat 结构
    // 标准流返回字符设备模式 (S_IFCHR | 0666)
    // 其他文件返回普通文件模式 (S_IFREG | 0644)
    let mode: u32 = if fd <= 2 {
        0o020000 | 0o666 // S_IFCHR | rw-rw-rw-
    } else {
        0o100000 | 0o644 // S_IFREG | rw-r--r--
    };

    let stat = VfsStat {
        dev: 0,
        ino: fd as u64,
        mode,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        size: 0,
        blksize: 4096,
        blocks: 0,
        atime_sec: 0,
        atime_nsec: 0,
        mtime_sec: 0,
        mtime_nsec: 0,
        ctime_sec: 0,
        ctime_nsec: 0,
    };

    // 将结果写入用户空间
    let stat_bytes = unsafe {
        core::slice::from_raw_parts(
            &stat as *const VfsStat as *const u8,
            mem::size_of::<VfsStat>(),
        )
    };
    copy_to_user(statbuf as *mut u8, stat_bytes)?;

    Ok(0)
}

/// sys_lseek - 移动文件读写偏移
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `offset` - 偏移量
/// * `whence` - 偏移起点：
///   - 0 (SEEK_SET): 从文件开头
///   - 1 (SEEK_CUR): 从当前位置
///   - 2 (SEEK_END): 从文件结尾
///
/// # Returns
/// 成功返回新的偏移位置，失败返回错误码
fn sys_lseek(fd: i32, offset: i64, whence: i32) -> SyscallResult {
    // 标准流不支持 seek
    if fd < 3 {
        return Err(SyscallError::EINVAL);
    }

    // 验证 whence 参数
    if whence < 0 || whence > 2 {
        return Err(SyscallError::EINVAL);
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 从 fd_table 获取文件描述符
    let proc = process.lock();
    let file_ops = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

    // 获取 lseek 回调函数
    let lseek_fn = {
        let callback = VFS_LSEEK_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::EINVAL)?
    };

    // 通过回调执行 seek 操作
    // 回调函数会尝试将 file_ops 向下转型到 FileHandle 并执行 seek
    match lseek_fn(file_ops.as_any(), offset, whence) {
        Ok(new_offset) => Ok(new_offset as usize),
        Err(e) => Err(e),
    }
}

/// sys_close - 关闭文件描述符
fn sys_close(fd: i32) -> SyscallResult {
    // 标准流不能关闭（简化实现）
    if fd <= 2 {
        return Err(SyscallError::EBADF);
    }

    // 获取回调函数指针并立即释放锁
    let close_fn = {
        let callback = FD_CLOSE_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::EBADF)?
    };

    // 在锁外执行关闭
    close_fn(fd)?;
    Ok(0)
}

/// sys_ioctl - I/O 控制
///
/// 为 musl libc 提供最小化 stub 实现。
/// musl 会在终端检测时调用 TCGETS 等 ioctl，返回 ENOTTY 表明不是终端。
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `cmd` - ioctl 命令码
/// * `arg` - 命令参数
///
/// # Returns
/// 当前始终返回 ENOTTY（不是终端设备）
fn sys_ioctl(fd: i32, cmd: u64, arg: u64) -> SyscallResult {
    // 标记参数为已使用，避免编译器警告
    let _ = (cmd, arg);

    // 验证 fd 有效性
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }

    // 标准流始终有效，其他 fd 需要检查
    if fd > 2 {
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = process.lock();
        if proc.get_fd(fd).is_none() {
            return Err(SyscallError::EBADF);
        }
    }

    // 当前不实现任何 ioctl 命令
    // 常见命令：
    // - TCGETS (0x5401): 获取终端属性
    // - TIOCGWINSZ (0x5413): 获取终端窗口大小
    // 返回 ENOTTY 告知 musl 这不是终端设备
    Err(SyscallError::ENOTTY)
}

// ============================================================================
// 内存管理系统调用
// ============================================================================

/// 页大小
const PAGE_SIZE: usize = 0x1000;

/// 页对齐向上取整
#[inline]
fn page_align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// sys_brk - 改变数据段大小（堆管理）
///
/// # Arguments
///
/// * `addr` - 新的 program break 地址，0 表示查询当前值
///
/// # Returns
///
/// 成功返回新的 brk 值，失败返回旧的 brk 值（符合 Linux 语义）
///
/// # Behavior
///
/// - brk(0) 返回当前 program break
/// - brk(addr < brk_start) 返回当前 brk（拒绝缩小到起始点以下）
/// - brk(addr > current) 扩展堆，分配匿名页
/// - brk(addr < current) 收缩堆，释放页面
fn sys_brk(addr: usize) -> SyscallResult {
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags};
    use x86_64::VirtAddr;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    let mut proc = process.lock();

    // 查询模式：返回当前 brk
    if addr == 0 {
        return Ok(proc.brk);
    }

    // 拒绝缩小到 brk_start 以下
    if addr < proc.brk_start {
        return Ok(proc.brk);
    }

    // 检查用户空间边界
    if addr >= USER_SPACE_TOP {
        return Ok(proc.brk);
    }

    let old_brk = proc.brk;
    let old_top = page_align_up(old_brk);
    let new_top = page_align_up(addr);

    // 堆扩展
    if new_top > old_top {
        let grow_size = new_top - old_top;

        // 检查与 mmap 区域冲突
        for (&region_base, &region_len) in proc.mmap_regions.iter() {
            let region_end = region_base.saturating_add(region_len);
            if old_top < region_end && new_top > region_base {
                // 有重叠，返回旧值
                return Ok(old_brk);
            }
        }

        // 释放锁后进行映射操作
        drop(proc);

        // 分配并映射新的堆页
        let map_result: Result<(), SyscallError> = unsafe {
            with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
                let mut frame_alloc = FrameAllocator::new();
                let flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::NO_EXECUTE;

                for offset in (0..grow_size).step_by(PAGE_SIZE) {
                    let vaddr = VirtAddr::new((old_top + offset) as u64);
                    let page = Page::containing_address(vaddr);

                    // 检查页面是否已映射
                    if manager.translate_addr(vaddr).is_some() {
                        continue;
                    }

                    // 分配物理帧
                    let frame = frame_alloc
                        .allocate_frame()
                        .ok_or(SyscallError::ENOMEM)?;

                    // 清零新分配的帧
                    let virt = mm::phys_to_virt(frame.start_address());
                    core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, PAGE_SIZE);

                    // 映射页
                    manager
                        .map_page(page, frame, flags, &mut frame_alloc)
                        .map_err(|_| SyscallError::ENOMEM)?;
                }
                Ok(())
            })
        };

        if map_result.is_err() {
            // 分配失败，返回旧值
            return Ok(old_brk);
        }

        // 更新进程 brk
        let mut proc = process.lock();
        proc.brk = addr;
        Ok(addr)
    }
    // 堆收缩
    else if new_top < old_top {
        // 释放锁后进行解映射操作
        drop(proc);

        // 解映射页面
        unsafe {
            with_current_manager(VirtAddr::new(0), |manager| {
                let mut frame_alloc = FrameAllocator::new();

                for offset in (0..(old_top - new_top)).step_by(PAGE_SIZE) {
                    let vaddr = VirtAddr::new((new_top + offset) as u64);
                    let page = Page::containing_address(vaddr);

                    // 解映射并释放帧
                    if let Ok(frame) = manager.unmap_page(page) {
                        frame_alloc.deallocate_frame(frame);
                    }
                }
            });
        }

        // 更新进程 brk
        let mut proc = process.lock();
        proc.brk = addr;
        Ok(addr)
    }
    // 同一页内调整，只更新 brk 值
    else {
        proc.brk = addr;
        Ok(addr)
    }
}

/// sys_mmap - 内存映射
///
/// 使用当前进程的地址空间进行映射，确保进程隔离
fn sys_mmap(
    addr: usize,
    length: usize,
    prot: i32,
    _flags: i32,
    fd: i32,
    _offset: i64,
) -> SyscallResult {
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags};
    use x86_64::VirtAddr;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 验证参数
    if length == 0 {
        return Err(SyscallError::EINVAL);
    }

    // 文件映射暂不支持
    if fd >= 0 {
        return Err(SyscallError::ENOSYS);
    }

    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    // 构建页表标志
    let mut page_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

    // PROT_WRITE
    if prot & 0x2 != 0 {
        page_flags |= PageTableFlags::WRITABLE;
    }

    // PROT_EXEC (x86_64使用NX位表示不可执行)
    if prot & 0x4 == 0 {
        page_flags |= PageTableFlags::NO_EXECUTE;
    }

    // 从进程 PCB 中选择地址并检查重叠
    let (base, end, update_next) = {
        let proc = process.lock();

        // 选择起始虚拟地址（使用 checked_add 防止溢出）
        let chosen_base = if addr == 0 {
            proc.next_mmap_addr
                .checked_add(0xfff)
                .ok_or(SyscallError::EINVAL)?
                & !0xfff
        } else {
            addr
        };

        // 检查地址对齐
        if chosen_base & 0xfff != 0 {
            return Err(SyscallError::EINVAL);
        }

        // 计算结束地址并检查用户空间边界
        let end = chosen_base
            .checked_add(length_aligned)
            .ok_or(SyscallError::EFAULT)?;

        if end > USER_SPACE_TOP {
            return Err(SyscallError::EFAULT);
        }

        // 检查与现有映射的重叠
        for (&region_base, &region_len) in proc.mmap_regions.iter() {
            let region_end = region_base
                .checked_add(region_len)
                .ok_or(SyscallError::EFAULT)?;
            if chosen_base < region_end && end > region_base {
                return Err(SyscallError::EINVAL);
            }
        }

        (chosen_base, end, addr == 0)
    };

    // 使用基于当前 CR3 的页表管理器进行映射
    // 使用 tracked vector 记录已映射的页，确保失败时完整回滚，避免帧泄漏
    let map_result: Result<(), SyscallError> = unsafe {
        use x86_64::structures::paging::PhysFrame;

        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            let mut frame_alloc = FrameAllocator::new();
            // 跟踪已成功映射的 (page, frame) 对，用于失败时回滚
            let mut mapped: vec::Vec<(Page, PhysFrame)> = vec::Vec::new();

            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((base + offset) as u64));

                // 分配物理帧，失败时回滚所有已映射的页
                let frame = match frame_alloc.allocate_frame() {
                    Some(f) => f,
                    None => {
                        // 回滚：释放所有已映射的页和帧
                        // 只有在 unmap 成功时才释放帧，避免 UAF
                        for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                            if manager.unmap_page(cleanup_page).is_ok() {
                                frame_alloc.deallocate_frame(cleanup_frame);
                            }
                            // unmap 失败时不释放帧，因为映射可能仍然存在
                            // 这会导致帧泄漏，但比 UAF 更安全
                        }
                        return Err(SyscallError::ENOMEM);
                    }
                };

                // 安全：清零新分配的帧，防止泄漏其他进程的数据
                // 使用高半区直映访问物理内存
                let virt = mm::phys_to_virt(frame.start_address());
                core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 0x1000);

                // 映射页，失败时回滚
                if let Err(_) = manager.map_page(page, frame, page_flags, &mut frame_alloc) {
                    // 释放当前分配但未映射的帧
                    frame_alloc.deallocate_frame(frame);
                    // 回滚：释放所有已映射的页和帧
                    // 只有在 unmap 成功时才释放帧，避免 UAF
                    for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                        if manager.unmap_page(cleanup_page).is_ok() {
                            frame_alloc.deallocate_frame(cleanup_frame);
                        }
                        // unmap 失败时不释放帧，因为映射可能仍然存在
                    }
                    return Err(SyscallError::ENOMEM);
                }

                // 记录成功映射的页
                mapped.push((page, frame));
            }

            Ok(())
        })
    };

    map_result?;

    // 记录映射到进程 PCB
    {
        let mut proc = process.lock();
        proc.mmap_regions.insert(base, length_aligned);
        if update_next {
            proc.next_mmap_addr = end;
        } else if proc.next_mmap_addr < end {
            proc.next_mmap_addr = end;
        }
    }

    println!(
        "sys_mmap: pid={}, mapped {} bytes at 0x{:x}",
        pid, length_aligned, base
    );

    Ok(base)
}

/// sys_munmap - 取消内存映射
///
/// 使用当前进程的地址空间进行取消映射，确保进程隔离
fn sys_munmap(addr: usize, length: usize) -> SyscallResult {
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::Page;
    use x86_64::VirtAddr;

    // 验证参数
    if addr & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }

    if length == 0 {
        return Err(SyscallError::EINVAL);
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    // 检查该区域是否在进程的 mmap 记录中
    let recorded_length = {
        let proc = process.lock();
        *proc.mmap_regions.get(&addr).ok_or(SyscallError::EINVAL)?
    };

    // 验证长度匹配
    if recorded_length != length_aligned {
        return Err(SyscallError::EINVAL);
    }

    // 使用基于当前 CR3 的页表管理器进行取消映射
    // R23-3 fix: 使用两阶段方法 - 先收集帧、做 TLB shootdown、再释放
    let unmap_result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            use alloc::vec::Vec;
            use x86_64::structures::paging::PhysFrame;

            let mut frame_alloc = FrameAllocator::new();
            let mut frames_to_free: Vec<PhysFrame> = Vec::new();

            // 阶段 1: 取消映射并收集需要释放的帧
            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((addr + offset) as u64));
                if let Ok(frame) = manager.unmap_page(page) {
                    let phys_addr = frame.start_address().as_u64() as usize;

                    // 检查是否为 COW 共享页
                    // 如果有引用计数，递减；只有当引用计数为 0 时才释放
                    let should_free = if PAGE_REF_COUNT.get(phys_addr) > 0 {
                        PAGE_REF_COUNT.decrement(phys_addr) == 0
                    } else {
                        // 没有引用计数记录，说明不是 COW 页，可以直接释放
                        true
                    };

                    if should_free {
                        frames_to_free.push(frame);
                    }
                }
            }

            // 阶段 2: R23-3 fix - TLB shootdown
            // 在释放物理帧之前，确保所有 CPU 都已清除 stale TLB 条目
            // 当前单核模式下，只做本地 flush；SMP 时需要 IPI
            mm::flush_current_as_range(VirtAddr::new(addr as u64), length_aligned);

            // 阶段 3: 释放物理帧（此时 TLB 已清除，安全释放）
            for frame in frames_to_free {
                frame_alloc.deallocate_frame(frame);
            }

            Ok(())
        })
    };

    unmap_result?;

    // 从进程 PCB 中移除映射记录
    {
        let mut proc = process.lock();
        proc.mmap_regions.remove(&addr);
    }

    println!(
        "sys_munmap: pid={}, unmapped {} bytes at 0x{:x}",
        pid, length_aligned, addr
    );

    Ok(0)
}

/// mprotect 保护标志
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;
const PROT_NONE: i32 = 0x0;

/// sys_mprotect - 设置内存区域保护属性
///
/// # Arguments
/// * `addr` - 起始地址（必须页对齐）
/// * `len` - 区域长度
/// * `prot` - 保护标志 (PROT_READ, PROT_WRITE, PROT_EXEC)
///
/// # Returns
/// 成功返回 0，失败返回错误码
fn sys_mprotect(addr: usize, len: usize, prot: i32) -> SyscallResult {
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::Page;
    use x86_64::VirtAddr;

    // 验证地址页对齐
    if addr & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 长度为 0 时直接返回成功
    if len == 0 {
        return Ok(0);
    }

    // 对齐长度到页边界
    let len_aligned = len
        .checked_add(0xfff)
        .ok_or(SyscallError::EINVAL)?
        & !0xfff;

    // R28-7 Fix: Validate that addr + len_aligned doesn't overflow or exceed user space
    let end = addr.checked_add(len_aligned).ok_or(SyscallError::EINVAL)?;
    if end > USER_SPACE_TOP {
        return Err(SyscallError::EINVAL);
    }

    // W^X 安全检查：禁止同时可写可执行
    if (prot & PROT_WRITE != 0) && (prot & PROT_EXEC != 0) {
        return Err(SyscallError::EPERM);
    }

    // 构建页表标志
    // R24-4 fix: PROT_NONE 需要清除 PRESENT 标志，使页面不可访问
    let flags = if prot == PROT_NONE {
        // 不可访问：清除 PRESENT，页存在但任何访问都会触发 #PF
        PageTableFlags::empty()
    } else {
        let mut f = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if prot & PROT_WRITE != 0 {
            f |= PageTableFlags::WRITABLE;
        }
        if prot & PROT_EXEC == 0 {
            // 如果没有 EXEC 权限，设置 NX 位
            f |= PageTableFlags::NO_EXECUTE;
        }
        f
    };

    // 更新页表项
    let result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            for offset in (0..len_aligned).step_by(0x1000) {
                let page_addr = addr + offset;
                let page = Page::containing_address(VirtAddr::new(page_addr as u64));

                // 尝试更新页的保护属性
                // 如果页不存在，跳过（mprotect 只修改已存在的映射）
                if let Err(e) = manager.update_flags(page, flags) {
                    // 忽略页不存在的错误，这是正常的
                    // 其他错误则返回
                    if !matches!(e, mm::page_table::UpdateFlagsError::PageNotMapped) {
                        return Err(SyscallError::EFAULT);
                    }
                }
            }
            Ok(())
        })
    };

    result?;

    // 刷新 TLB
    mm::flush_current_as_range(VirtAddr::new(addr as u64), len_aligned);

    Ok(0)
}

// ============================================================================
// Seccomp/Prctl 系统调用
// ============================================================================

// R26-3: Helper functions to manage seccomp installation state
//
// These functions set/clear the `seccomp_installing` flag to prevent TOCTOU
// race conditions between seccomp filter installation and thread creation.
// The flag must be manually cleared after installation completes or on error.

/// Convert seccomp error to syscall error
fn seccomp_error_to_syscall(err: seccomp::SeccompError) -> SyscallError {
    match err {
        seccomp::SeccompError::Fault => SyscallError::EFAULT,
        seccomp::SeccompError::NotPermitted => SyscallError::EPERM,
        seccomp::SeccompError::ProgramTooLong => SyscallError::E2BIG,
        _ => SyscallError::EINVAL,
    }
}

/// Decode user-space action code to SeccompAction
fn decode_user_action(code: u32, aux: u64) -> Result<seccomp::SeccompAction, SyscallError> {
    match code {
        SECCOMP_USER_ACTION_ALLOW => Ok(seccomp::SeccompAction::Allow),
        SECCOMP_USER_ACTION_LOG => Ok(seccomp::SeccompAction::Log),
        SECCOMP_USER_ACTION_ERRNO => {
            if aux > i32::MAX as u64 {
                return Err(SyscallError::EINVAL);
            }
            Ok(seccomp::SeccompAction::Errno(aux as i32))
        }
        SECCOMP_USER_ACTION_TRAP => Ok(seccomp::SeccompAction::Trap),
        SECCOMP_USER_ACTION_KILL => Ok(seccomp::SeccompAction::Kill),
        _ => Err(SyscallError::EINVAL),
    }
}

/// Convert u64 to u8 with bounds check
#[inline]
fn to_u8_checked(val: u64) -> Result<u8, SyscallError> {
    if val > u8::MAX as u64 {
        return Err(SyscallError::EINVAL);
    }
    Ok(val as u8)
}

/// Translate user-space instruction to kernel SeccompInsn
fn translate_user_insn(insn: &UserSeccompInsn) -> Result<seccomp::SeccompInsn, SyscallError> {
    match insn.op {
        SECCOMP_USER_OP_LD_NR => Ok(seccomp::SeccompInsn::LdSyscallNr),
        SECCOMP_USER_OP_LD_ARG => {
            let idx = to_u8_checked(insn.arg0)?;
            if idx >= 6 {
                return Err(SyscallError::EINVAL);
            }
            Ok(seccomp::SeccompInsn::LdArg(idx))
        }
        SECCOMP_USER_OP_LD_CONST => Ok(seccomp::SeccompInsn::LdConst(insn.arg0)),
        SECCOMP_USER_OP_AND => Ok(seccomp::SeccompInsn::And(insn.arg0)),
        SECCOMP_USER_OP_OR => Ok(seccomp::SeccompInsn::Or(insn.arg0)),
        SECCOMP_USER_OP_SHR => Ok(seccomp::SeccompInsn::Shr(to_u8_checked(insn.arg0)?)),
        SECCOMP_USER_OP_JMP_EQ => Ok(seccomp::SeccompInsn::JmpEq(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_NE => Ok(seccomp::SeccompInsn::JmpNe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_LT => Ok(seccomp::SeccompInsn::JmpLt(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_LE => Ok(seccomp::SeccompInsn::JmpLe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_GT => Ok(seccomp::SeccompInsn::JmpGt(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_GE => Ok(seccomp::SeccompInsn::JmpGe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP => Ok(seccomp::SeccompInsn::Jmp(to_u8_checked(insn.arg0)?)),
        SECCOMP_USER_OP_RET => {
            let action = decode_user_action(insn.arg0 as u32, insn.arg1)?;
            Ok(seccomp::SeccompInsn::Ret(action))
        }
        _ => Err(SyscallError::EINVAL),
    }
}

/// Load and validate a seccomp filter from userspace
fn load_user_seccomp_filter(flags: u32, args: u64) -> Result<seccomp::SeccompFilter, SyscallError> {
    // Validate flags - reject TSYNC since we don't implement thread synchronization
    // Silently accepting TSYNC would leave sibling threads unsandboxed (security gap)
    if flags & seccomp::SeccompFlags::TSYNC.bits() != 0 {
        println!("[sys_seccomp] TSYNC not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    // R28-8 Fix: Reject NEW_THREADS flag since we don't implement per-new-thread filtering
    // Accepting this flag would make callers believe new threads are sandboxed when they're not.
    if flags & seccomp::SeccompFlags::NEW_THREADS.bits() != 0 {
        println!("[sys_seccomp] NEW_THREADS not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    let filter_flags = seccomp::SeccompFlags::from_bits(flags).ok_or(SyscallError::EINVAL)?;

    // Read program header from userspace
    let mut prog = UserSeccompProg::default();
    let prog_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut prog as *mut _ as *mut u8,
            mem::size_of::<UserSeccompProg>(),
        )
    };
    copy_from_user(prog_bytes, args as *const u8)?;

    // Validate program length
    let len = prog.len as usize;
    if len == 0 || len > seccomp::MAX_INSNS {
        return Err(SyscallError::EINVAL);
    }

    // Validate filter pointer
    let insn_ptr = prog.filter as *const UserSeccompInsn;
    if insn_ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // Calculate total size and validate
    let insn_size = mem::size_of::<UserSeccompInsn>();
    let total = insn_size.checked_mul(len).ok_or(SyscallError::EFAULT)?;
    validate_user_ptr(insn_ptr as *const u8, total)?;

    // Read instructions from userspace
    let mut raw_insns = vec![UserSeccompInsn::default(); len];
    let raw_bytes = unsafe {
        core::slice::from_raw_parts_mut(raw_insns.as_mut_ptr() as *mut u8, total)
    };
    copy_from_user(raw_bytes, insn_ptr as *const u8)?;

    // Decode default action
    let default_action = decode_user_action(prog.default_action, 0)?;

    // Translate all instructions
    let mut program = Vec::with_capacity(len);
    for insn in raw_insns.iter() {
        program.push(translate_user_insn(insn)?);
    }

    // Create and validate filter
    seccomp::SeccompFilter::new(program, default_action, filter_flags)
        .map_err(seccomp_error_to_syscall)
}

/// Get current seccomp mode for PR_GET_SECCOMP
fn current_seccomp_mode(state: &seccomp::SeccompState) -> usize {
    if state.filters.is_empty() {
        return SECCOMP_MODE_DISABLED;
    }

    // Check if it's strict mode (only the strict filter installed)
    let strict_id = seccomp::strict_filter().id;
    if state.filters.len() == 1 {
        if let Some(filter) = state.filters.first() {
            if filter.id == strict_id {
                return SECCOMP_MODE_STRICT;
            }
        }
    }

    SECCOMP_MODE_FILTER
}

/// sys_seccomp - Install seccomp filter or strict mode
///
/// # Arguments
/// * `op` - Operation (SECCOMP_SET_MODE_STRICT or SECCOMP_SET_MODE_FILTER)
/// * `flags` - Filter flags (SeccompFlags bits)
/// * `args` - For FILTER mode, pointer to UserSeccompProg
///
/// # Security
/// - Filters can only be added, never removed (one-way sandboxing)
/// - Installing a filter automatically sets no_new_privs
/// - Filters are inherited across fork/clone
fn sys_seccomp(op: u32, flags: u32, args: u64) -> SyscallResult {
    match op {
        SECCOMP_SET_MODE_STRICT => {
            // Strict mode requires no flags or args
            if flags != 0 || args != 0 {
                return Err(SyscallError::EINVAL);
            }

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let filter = seccomp::strict_filter();

            let mut proc = proc_arc.lock();

            // R26-3 FIX: Check if another thread is already installing
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // Installing any filter sets no_new_privs (sticky, one-way)
            proc.seccomp_state.no_new_privs = true;
            proc.seccomp_state.add_filter(filter);

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            println!("[sys_seccomp] PID={} installed STRICT mode", pid);
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => {
            // Load and validate the filter from userspace
            let filter = load_user_seccomp_filter(flags, args)?;

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let mut proc = proc_arc.lock();

            // R26-3 FIX: Check if another thread is already installing
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // R25-6 FIX: Reject seccomp in multi-threaded processes without TSYNC
            // This prevents security bypass where only one thread is sandboxed
            let thread_count = crate::process::thread_group_size(proc.tgid);
            let tsync_requested = flags & seccomp::SeccompFlags::TSYNC.bits() != 0;
            if thread_count > 1 && !tsync_requested {
                // Multi-threaded but TSYNC not requested - refuse partial sandboxing
                println!(
                    "[sys_seccomp] PID={} REJECTED: {} threads but TSYNC not requested",
                    pid, thread_count
                );
                return Err(SyscallError::EPERM);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // Installing filter sets no_new_privs (sticky, one-way)
            proc.seccomp_state.no_new_privs = true;

            // If LOG flag is set, enable violation logging
            if filter.flags.contains(seccomp::SeccompFlags::LOG) {
                proc.seccomp_state.log_violations = true;
            }

            proc.seccomp_state.add_filter(filter);

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            println!(
                "[sys_seccomp] PID={} installed FILTER mode (total filters: {})",
                pid,
                proc.seccomp_state.filters.len()
            );
            Ok(0)
        }
        _ => Err(SyscallError::EINVAL),
    }
}

/// sys_prctl - Process control operations
///
/// Implements seccomp and no_new_privs related prctl operations:
/// - PR_SET_NO_NEW_PRIVS: Set the sticky no_new_privs flag
/// - PR_GET_NO_NEW_PRIVS: Check if no_new_privs is set
/// - PR_GET_SECCOMP: Get current seccomp mode
/// - PR_SET_SECCOMP: Set seccomp mode (alternative to sys_seccomp)
///
/// # Arguments
/// * `option` - prctl operation code
/// * `arg2-arg5` - Operation-specific arguments
fn sys_prctl(option: i32, arg2: u64, arg3: u64, _arg4: u64, _arg5: u64) -> SyscallResult {
    match option {
        PR_SET_NO_NEW_PRIVS => {
            // arg2 must be 1 to set, 0 is invalid (can't unset)
            if arg2 != 1 {
                return Err(SyscallError::EINVAL);
            }

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let mut proc = proc_arc.lock();
            proc.seccomp_state.no_new_privs = true;

            println!("[sys_prctl] PID={} set NO_NEW_PRIVS", pid);
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            Ok(proc.seccomp_state.no_new_privs as usize)
        }
        PR_GET_SECCOMP => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            Ok(current_seccomp_mode(&proc.seccomp_state))
        }
        PR_SET_SECCOMP => {
            // prctl(PR_SET_SECCOMP, mode, filter_ptr, 0, 0)
            // Extra args (arg4/arg5) must be zero
            if _arg4 != 0 || _arg5 != 0 {
                return Err(SyscallError::EINVAL);
            }

            // Delegate to sys_seccomp based on mode
            // Note: prctl doesn't support flags, so we always pass 0
            let mode = arg2 as u32;
            match mode {
                SECCOMP_SET_MODE_STRICT => {
                    // Strict mode requires arg3=0
                    if arg3 != 0 {
                        return Err(SyscallError::EINVAL);
                    }
                    sys_seccomp(SECCOMP_SET_MODE_STRICT, 0, 0)
                }
                SECCOMP_SET_MODE_FILTER => {
                    // arg3 is pointer to filter prog
                    // prctl interface doesn't support flags (use sys_seccomp directly for flags)
                    sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, arg3)
                }
                _ => Err(SyscallError::EINVAL),
            }
        }
        _ => {
            // Other prctl options not implemented
            Err(SyscallError::EINVAL)
        }
    }
}

// ============================================================================
// 架构相关系统调用
// ============================================================================

/// arch_prctl 操作码
const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;
const ARCH_GET_GS: i32 = 0x1004;

/// 检查地址是否为 canonical 形式（x86_64）
///
/// 在 x86_64 中，虚拟地址必须是 48 位有效，高 16 位必须等于第 47 位的符号扩展。
/// 即：地址的高 17 位要么全为 0，要么全为 1。
#[inline]
fn is_canonical(addr: u64) -> bool {
    // 有效用户空间：0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF
    // 有效内核空间：0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
    // 非 canonical 区域：0x0000_8000_0000_0000 - 0xFFFF_7FFF_FFFF_FFFF
    let sign_extended = ((addr as i64) >> 47) as u64;
    sign_extended == 0 || sign_extended == 0x1FFFF
}

/// sys_arch_prctl - 设置/获取架构相关的线程状态
///
/// 主要用于 TLS (Thread Local Storage) 支持，设置 FS/GS segment base。
///
/// # Arguments
///
/// * `code` - 操作码 (ARCH_SET_FS, ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS)
/// * `addr` - SET: 要设置的 base 地址；GET: 存储结果的用户空间指针
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
fn sys_arch_prctl(code: i32, addr: u64) -> SyscallResult {
    use x86_64::registers::model_specific::Msr;

    // MSR 寄存器常量
    const MSR_FS_BASE: u32 = 0xC000_0100;
    const MSR_GS_BASE: u32 = 0xC000_0101;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    match code {
        ARCH_SET_FS => {
            // 验证地址是 canonical
            if !is_canonical(addr) {
                return Err(SyscallError::EINVAL);
            }

            // Debug: 打印 ARCH_SET_FS 调用
            println!("[arch_prctl] PID={} ARCH_SET_FS addr=0x{:x}", pid, addr);

            // 更新进程 PCB 中的 fs_base
            {
                let mut proc = process.lock();
                proc.fs_base = addr;
            }

            // 立即更新 MSR（当前进程正在运行）
            unsafe {
                let mut msr = Msr::new(MSR_FS_BASE);
                msr.write(addr);
            }

            Ok(0)
        }

        ARCH_GET_FS => {
            // 验证用户空间指针
            if addr == 0 || addr >= USER_SPACE_TOP as u64 {
                return Err(SyscallError::EFAULT);
            }

            // 从 PCB 获取 fs_base
            let fs_base = {
                let proc = process.lock();
                proc.fs_base
            };

            // 写回用户空间
            let result = copy_to_user(addr as *mut u8, &fs_base.to_ne_bytes());
            if result.is_err() {
                return Err(SyscallError::EFAULT);
            }

            Ok(0)
        }

        ARCH_SET_GS => {
            // 验证地址是 canonical
            if !is_canonical(addr) {
                return Err(SyscallError::EINVAL);
            }

            // 更新进程 PCB 中的 gs_base
            {
                let mut proc = process.lock();
                proc.gs_base = addr;
            }

            // 立即更新 MSR
            unsafe {
                let mut msr = Msr::new(MSR_GS_BASE);
                msr.write(addr);
            }

            Ok(0)
        }

        ARCH_GET_GS => {
            // 验证用户空间指针
            if addr == 0 || addr >= USER_SPACE_TOP as u64 {
                return Err(SyscallError::EFAULT);
            }

            // 从 PCB 获取 gs_base
            let gs_base = {
                let proc = process.lock();
                proc.gs_base
            };

            // 写回用户空间
            let result = copy_to_user(addr as *mut u8, &gs_base.to_ne_bytes());
            if result.is_err() {
                return Err(SyscallError::EFAULT);
            }

            Ok(0)
        }

        _ => Err(SyscallError::EINVAL),
    }
}

// ============================================================================
// Futex 系统调用
// ============================================================================

/// sys_futex - 快速用户空间互斥锁操作
///
/// 实现 FUTEX_WAIT 和 FUTEX_WAKE 操作，用于用户空间高效同步。
///
/// # Arguments
///
/// * `uaddr` - 用户空间 futex 地址（指向 u32）
/// * `op` - 操作码：0=FUTEX_WAIT, 1=FUTEX_WAKE
/// * `val` - FUTEX_WAIT: 期望值；FUTEX_WAKE: 最大唤醒数量
///
/// # Returns
///
/// * FUTEX_WAIT: 成功阻塞并被唤醒返回 0，值不匹配返回 EAGAIN
/// * FUTEX_WAKE: 返回实际唤醒的进程数量
fn sys_futex(uaddr: usize, op: i32, val: u32) -> SyscallResult {
    const FUTEX_WAIT: i32 = 0;
    const FUTEX_WAKE: i32 = 1;

    // 验证用户指针
    if uaddr == 0 {
        return Err(SyscallError::EFAULT);
    }

    // 检查地址对齐（u32 需要 4 字节对齐）
    if uaddr % 4 != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 验证用户内存可访问
    verify_user_memory(
        uaddr as *const u8,
        core::mem::size_of::<u32>(),
        op == FUTEX_WAIT,
    )?;

    // 获取回调函数
    let futex_fn = {
        let callback = FUTEX_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 对于 FUTEX_WAIT，需要先读取当前值
    let current_value = if op == FUTEX_WAIT {
        // 读取 futex 字（安全：已验证用户内存）
        let mut value_bytes = [0u8; 4];
        copy_from_user(&mut value_bytes, uaddr as *const u8)?;
        u32::from_ne_bytes(value_bytes)
    } else {
        0 // FUTEX_WAKE 不需要当前值
    };

    // 调用 IPC 模块的 futex 实现
    futex_fn(uaddr, op, val, current_value)
}

// ============================================================================
// 其他系统调用
// ============================================================================

/// sys_yield - 主动让出CPU
fn sys_yield() -> SyscallResult {
    // 将当前进程状态设置为Ready
    if let Some(pid) = current_pid() {
        if let Some(process) = get_process(pid) {
            let mut proc = process.lock();
            proc.state = crate::process::ProcessState::Ready;
        }
    }

    // 强制触发重调度，立即执行上下文切换
    // 注意：force_reschedule() 可能不会返回（如果切换到其他进程）
    // 当本进程再次被调度时，会从这里继续执行
    crate::force_reschedule();

    Ok(0)
}

/// sys_getrandom - 获取随机字节
///
/// 为 musl libc 提供随机数生成支持。
/// 使用 RDRAND 指令（如果 CPU 支持）混合时间戳生成随机数。
///
/// # Arguments
/// * `buf` - 用户空间缓冲区指针
/// * `len` - 请求的字节数
/// * `flags` - 标志位 (GRND_NONBLOCK=0x1, GRND_RANDOM=0x2)
///
/// # Returns
/// 成功返回写入的字节数，失败返回错误码
fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> SyscallResult {
    /// GRND_NONBLOCK - 非阻塞模式
    const GRND_NONBLOCK: u32 = 0x1;
    /// GRND_RANDOM - 使用 /dev/random 语义（当前忽略）
    const GRND_RANDOM: u32 = 0x2;

    // 验证 flags 有效性
    if flags & !(GRND_NONBLOCK | GRND_RANDOM) != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 处理边界情况
    let count = match len {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 验证用户缓冲区
    validate_user_ptr_mut(buf, count)?;
    verify_user_memory(buf as *const u8, count, true)?;

    // 生成随机数据到临时缓冲区
    let mut tmp = vec![0u8; count];
    let mut offset = 0usize;

    while offset < count {
        // 混合时间戳和 RDRAND（如果可用）
        let mut word = crate::time::get_ticks() as u64;

        // 尝试使用 RDRAND 指令（需要 CPUID 检查）
        #[cfg(target_arch = "x86_64")]
        {
            // 检查 CPU 是否支持 RDRAND (CPUID.01H:ECX.RDRAND[bit 30])
            // 注意：RBX 被 LLVM 保留，需要手动保存/恢复
            let rdrand_supported: bool = {
                let ecx: u32;
                unsafe {
                    core::arch::asm!(
                        "push rbx",      // 保存 RBX
                        "mov eax, 1",
                        "cpuid",
                        "mov {0:e}, ecx",
                        "pop rbx",       // 恢复 RBX
                        out(reg) ecx,
                        out("eax") _,
                        out("ecx") _,
                        out("edx") _,
                        options(nostack),
                    );
                }
                (ecx & (1 << 30)) != 0
            };

            if rdrand_supported {
                let rand_result: u64;
                let success: u8;
                unsafe {
                    core::arch::asm!(
                        "rdrand {0}",
                        "setc {1}",
                        out(reg) rand_result,
                        out(reg_byte) success,
                        options(nostack, nomem),
                    );
                }
                if success != 0 {
                    word ^= rand_result;
                }
            }
        }

        // 将 word 拆分为字节并填充缓冲区
        let bytes = word.to_ne_bytes();
        let chunk = core::cmp::min(bytes.len(), count - offset);
        tmp[offset..offset + chunk].copy_from_slice(&bytes[..chunk]);
        offset += chunk;
    }

    // 复制到用户空间
    copy_to_user(buf, &tmp)?;

    Ok(count)
}

// ============================================================================
// 用户/组ID系统调用
// ============================================================================

/// sys_getuid - 获取真实用户ID
fn sys_getuid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.uid as usize)
}

/// sys_geteuid - 获取有效用户ID
fn sys_geteuid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.euid as usize)
}

/// sys_getgid - 获取真实组ID
fn sys_getgid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.gid as usize)
}

/// sys_getegid - 获取有效组ID
fn sys_getegid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.egid as usize)
}

// ============================================================================
// 文件系统附加系统调用
// ============================================================================

/// sys_getcwd - 获取当前工作目录
///
/// 当前实现返回固定值"/"，因为PCB未跟踪工作目录。
fn sys_getcwd(buf: *mut u8, size: usize) -> SyscallResult {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if size < 2 {
        return Err(SyscallError::ERANGE);
    }

    // 当前工作目录固定为根目录
    let cwd = b"/\0";
    copy_to_user(buf, cwd)?;
    Ok(cwd.len())
}

/// sys_chdir - 更改当前工作目录
///
/// 当前实现仅验证路径存在，但不真正更改工作目录。
fn sys_chdir(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 复制路径
    let path_bytes = crate::usercopy::copy_user_cstring(path)
        .map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes)
        .map_err(|_| SyscallError::EINVAL)?;

    // 通过回调获取stat并验证路径存在且是目录
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let stat = stat_fn(path_str)?;
    if !is_directory_mode(stat.mode) {
        return Err(SyscallError::ENOTDIR);
    }

    // TODO: 将cwd存储在PCB中
    Ok(0)
}

/// sys_mkdir - 创建目录
fn sys_mkdir(path: *const u8, mode: u32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path)
        .map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes)
        .map_err(|_| SyscallError::EINVAL)?;

    // LSM hook: check mkdir permission
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let (parent_hash, name_hash) = match path_str.rfind('/') {
            Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
            Some(idx) => (
                audit::hash_path(&path_str[..idx]),
                audit::hash_path(&path_str[idx + 1..]),
            ),
            None => (audit::hash_path("."), audit::hash_path(path_str)),
        };
        if let Err(err) = lsm::hook_file_mkdir(&proc_ctx, parent_hash, name_hash, mode & 0o7777) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 通过回调创建目录
    let create_fn = VFS_CREATE_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    create_fn(path_str, mode & 0o7777, true)?;
    Ok(0)
}

/// sys_rmdir - 删除空目录
fn sys_rmdir(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path)
        .map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes)
        .map_err(|_| SyscallError::EINVAL)?;

    // 通过回调检查是否为目录
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let stat = stat_fn(path_str)?;
    if !is_directory_mode(stat.mode) {
        return Err(SyscallError::ENOTDIR);
    }

    // LSM hook: check rmdir permission
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let (parent_hash, name_hash) = match path_str.rfind('/') {
            Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
            Some(idx) => (
                audit::hash_path(&path_str[..idx]),
                audit::hash_path(&path_str[idx + 1..]),
            ),
            None => (audit::hash_path("."), audit::hash_path(path_str)),
        };
        if let Err(err) = lsm::hook_file_rmdir(&proc_ctx, parent_hash, name_hash) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 通过回调删除目录
    let unlink_fn = VFS_UNLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    unlink_fn(path_str)?;
    Ok(0)
}

/// sys_unlink - 删除文件
fn sys_unlink(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path)
        .map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes)
        .map_err(|_| SyscallError::EINVAL)?;

    // 不允许删除目录 (应使用rmdir)
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    if let Ok(stat) = stat_fn(path_str) {
        if is_directory_mode(stat.mode) {
            return Err(SyscallError::EISDIR);
        }
    }

    // LSM hook: check unlink permission
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let (parent_hash, name_hash) = match path_str.rfind('/') {
            Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
            Some(idx) => (
                audit::hash_path(&path_str[..idx]),
                audit::hash_path(&path_str[idx + 1..]),
            ),
            None => (audit::hash_path("."), audit::hash_path(path_str)),
        };
        if let Err(err) = lsm::hook_file_unlink(&proc_ctx, parent_hash, name_hash) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 通过回调删除文件
    let unlink_fn = VFS_UNLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    unlink_fn(path_str)?;
    Ok(0)
}

/// sys_access - 检查文件访问权限
///
/// mode: R_OK(4) | W_OK(2) | X_OK(1) | F_OK(0)
fn sys_access(path: *const u8, mode: i32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path)
        .map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes)
        .map_err(|_| SyscallError::EINVAL)?;

    // 通过回调获取文件状态
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let stat = stat_fn(path_str)?;

    // F_OK(0) - 仅检查文件是否存在
    if mode == 0 {
        return Ok(0);
    }

    // 获取当前进程凭证
    let euid = crate::current_euid().unwrap_or(0);
    let egid = crate::current_egid().unwrap_or(0);
    let sup_groups = crate::current_supplementary_groups().unwrap_or_default();

    // root用户拥有所有权限
    if euid == 0 {
        return Ok(0);
    }

    // 计算权限位
    let perm_bits = if euid == stat.uid {
        (stat.mode >> 6) & 0o7
    } else if egid == stat.gid || sup_groups.iter().any(|&g| g == stat.gid) {
        (stat.mode >> 3) & 0o7
    } else {
        stat.mode & 0o7
    };

    let need_read = (mode & 4) != 0;
    let need_write = (mode & 2) != 0;
    let need_exec = (mode & 1) != 0;

    let ok = (!need_read || (perm_bits & 0o4) != 0)
        && (!need_write || (perm_bits & 0o2) != 0)
        && (!need_exec || (perm_bits & 0o1) != 0);

    if ok {
        Ok(0)
    } else {
        Err(SyscallError::EACCES)
    }
}

/// sys_lstat - 获取符号链接状态
///
/// 当前VFS不支持符号链接，等同于stat。
fn sys_lstat(path: *const u8, statbuf: *mut VfsStat) -> SyscallResult {
    sys_stat(path, statbuf)
}

/// sys_fstatat - 相对路径stat
///
/// 当前仅支持AT_FDCWD或绝对路径。
fn sys_fstatat(dirfd: i32, path: *const u8, statbuf: *mut VfsStat, _flags: i32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 检查路径是否为绝对路径
    let first_byte = unsafe { *path };

    if dirfd != AT_FDCWD && first_byte != b'/' {
        // 相对路径 + 非AT_FDCWD: 暂不支持
        return Err(SyscallError::ENOSYS);
    }

    sys_stat(path, statbuf)
}

/// sys_openat - 相对路径打开文件
///
/// 当前仅支持AT_FDCWD或绝对路径。
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let first_byte = unsafe { *path };

    if dirfd != AT_FDCWD && first_byte != b'/' {
        return Err(SyscallError::ENOSYS);
    }

    sys_open(path, flags, mode)
}

// ============================================================================
// 文件描述符操作系统调用
// ============================================================================

/// sys_dup - 复制文件描述符
fn sys_dup(oldfd: i32) -> SyscallResult {
    if oldfd < 0 {
        return Err(SyscallError::EBADF);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();

    let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
    let cloned = src.clone_box();

    let newfd = proc.allocate_fd(cloned).ok_or(SyscallError::EMFILE)?;
    Ok(newfd as usize)
}

/// sys_dup2 - 复制文件描述符到指定位置
fn sys_dup2(oldfd: i32, newfd: i32) -> SyscallResult {
    if oldfd < 0 || newfd < 0 {
        return Err(SyscallError::EBADF);
    }

    if oldfd == newfd {
        // 验证oldfd有效
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
        return Ok(newfd as usize);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();

    let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
    let cloned = src.clone_box();

    // 如果newfd已打开，先关闭它
    proc.fd_table.remove(&newfd);
    proc.fd_table.insert(newfd, cloned);

    Ok(newfd as usize)
}

/// sys_dup3 - 复制文件描述符(带flags)
///
/// flags: O_CLOEXEC(0x80000)
fn sys_dup3(oldfd: i32, newfd: i32, flags: i32) -> SyscallResult {
    if oldfd < 0 || newfd < 0 {
        return Err(SyscallError::EBADF);
    }

    if oldfd == newfd {
        return Err(SyscallError::EINVAL);
    }

    // 仅接受O_CLOEXEC标志
    const O_CLOEXEC: i32 = 0x80000;
    if flags & !O_CLOEXEC != 0 {
        return Err(SyscallError::EINVAL);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();

    let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
    let cloned = src.clone_box();

    proc.fd_table.remove(&newfd);
    proc.fd_table.insert(newfd, cloned);

    // TODO: 如果flags包含O_CLOEXEC，标记fd为close-on-exec

    Ok(newfd as usize)
}

/// sys_ftruncate - 截断文件
fn sys_ftruncate(fd: i32, length: i64) -> SyscallResult {
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }
    if length < 0 {
        return Err(SyscallError::EINVAL);
    }

    // 通过回调执行截断
    let truncate_fn = VFS_TRUNCATE_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    truncate_fn(fd, length as u64)?;
    Ok(0)
}

/// sys_chmod - 修改文件权限
///
/// 当前VFS不支持chmod操作。
fn sys_chmod(_path: *const u8, _mode: u32) -> SyscallResult {
    // VFS trait未提供chmod方法
    Err(SyscallError::ENOSYS)
}

/// sys_fchmod - 修改文件权限(通过fd)
///
/// 当前VFS不支持chmod操作。
fn sys_fchmod(_fd: i32, _mode: u32) -> SyscallResult {
    Err(SyscallError::ENOSYS)
}

/// sys_umask - 设置文件创建掩码
fn sys_umask(mask: u32) -> SyscallResult {
    let old = crate::set_current_umask((mask & 0o777) as u16)
        .ok_or(SyscallError::ESRCH)?;
    Ok(old as usize)
}

/// sys_getdents64 - 读取目录项
fn sys_getdents64(fd: i32, dirp: *mut u8, count: usize) -> SyscallResult {
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }
    if dirp.is_null() || count == 0 {
        return Err(SyscallError::EINVAL);
    }

    // 通过回调读取目录项
    let readdir_fn = VFS_READDIR_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let entries = readdir_fn(fd)?;

    // 构建dirent64结构
    let mut written = 0usize;
    let header_size = core::mem::size_of::<LinuxDirent64>();

    for entry in entries {
        let name_bytes = entry.name.as_bytes();
        let reclen = ((header_size + name_bytes.len() + 1 + 7) / 8) * 8; // 8字节对齐

        if written + reclen > count {
            break;
        }

        let d_type = match entry.file_type {
            FileType::Regular => 8,     // DT_REG
            FileType::Directory => 4,   // DT_DIR
            FileType::CharDevice => 2,  // DT_CHR
            FileType::BlockDevice => 6, // DT_BLK
            FileType::Symlink => 10,    // DT_LNK
            FileType::Fifo => 1,        // DT_FIFO
            FileType::Socket => 12,     // DT_SOCK
        };

        // 构建dirent结构到临时缓冲区
        let mut buf = vec![0u8; reclen];
        let dirent = LinuxDirent64 {
            d_ino: entry.ino,
            d_off: (written + reclen) as i64,
            d_reclen: reclen as u16,
            d_type,
        };

        // 复制header
        unsafe {
            core::ptr::copy_nonoverlapping(
                &dirent as *const _ as *const u8,
                buf.as_mut_ptr(),
                header_size,
            );
        }

        // 复制文件名
        buf[header_size..header_size + name_bytes.len()].copy_from_slice(name_bytes);
        buf[header_size + name_bytes.len()] = 0; // NUL terminator

        // 复制到用户空间
        copy_to_user(unsafe { dirp.add(written) }, &buf)?;
        written += reclen;
    }

    Ok(written)
}

// ============================================================================
// 时间系统调用
// ============================================================================

/// sys_nanosleep - 高精度睡眠
///
/// 当前使用忙等待实现，未来应使用定时器。
fn sys_nanosleep(req: *const TimeSpec, rem: *mut TimeSpec) -> SyscallResult {
    if req.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let mut ts = TimeSpec::default();
    let ts_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut ts as *mut TimeSpec as *mut u8,
            core::mem::size_of::<TimeSpec>(),
        )
    };
    crate::usercopy::copy_from_user_safe(ts_bytes, req as *const u8)
        .map_err(|_| SyscallError::EFAULT)?;

    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(SyscallError::EINVAL);
    }

    // 计算睡眠时间(毫秒)
    let total_ms = (ts.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((ts.tv_nsec / 1_000_000) as u64);

    // 忙等待实现
    let start = crate::time::get_ticks();
    while crate::time::get_ticks().saturating_sub(start) < total_ms {
        core::hint::spin_loop();
    }

    // 如果提供了rem，设置为0
    if !rem.is_null() {
        let zero = TimeSpec { tv_sec: 0, tv_nsec: 0 };
        let zero_bytes = unsafe {
            core::slice::from_raw_parts(
                &zero as *const TimeSpec as *const u8,
                core::mem::size_of::<TimeSpec>(),
            )
        };
        crate::usercopy::copy_to_user_safe(rem as *mut u8, zero_bytes)
            .map_err(|_| SyscallError::EFAULT)?;
    }

    Ok(0)
}

/// sys_gettimeofday - 获取当前时间
fn sys_gettimeofday(tv: *mut TimeVal, _tz: usize) -> SyscallResult {
    if tv.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let ms = crate::time::current_timestamp_ms();
    let timeval = TimeVal {
        tv_sec: (ms / 1000) as i64,
        tv_usec: ((ms % 1000) * 1000) as i64,
    };

    let tv_bytes = unsafe {
        core::slice::from_raw_parts(
            &timeval as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    crate::usercopy::copy_to_user_safe(tv as *mut u8, tv_bytes)
        .map_err(|_| SyscallError::EFAULT)?;

    Ok(0)
}

// ============================================================================
// 系统信息系统调用
// ============================================================================

/// sys_uname - 获取系统信息
fn sys_uname(buf: *mut UtsName) -> SyscallResult {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    fn fill_field(target: &mut [u8; 65], src: &str) {
        let bytes = src.as_bytes();
        let len = bytes.len().min(64);
        target[..len].copy_from_slice(&bytes[..len]);
        target[len] = 0;
    }

    let mut uts = UtsName::default();
    fill_field(&mut uts.sysname, "Zero-OS");
    fill_field(&mut uts.nodename, "zero-node");
    fill_field(&mut uts.release, "0.6.5");
    fill_field(&mut uts.version, "Security Foundation Phase A");
    fill_field(&mut uts.machine, "x86_64");

    let uts_bytes = unsafe {
        core::slice::from_raw_parts(
            &uts as *const UtsName as *const u8,
            core::mem::size_of::<UtsName>(),
        )
    };
    crate::usercopy::copy_to_user_safe(buf as *mut u8, uts_bytes)
        .map_err(|_| SyscallError::EFAULT)?;

    Ok(0)
}

/// 系统调用统计
pub struct SyscallStats {
    pub total_calls: u64,
    pub exit_calls: u64,
    pub fork_calls: u64,
    pub read_calls: u64,
    pub write_calls: u64,
    pub failed_calls: u64,
}

impl SyscallStats {
    pub fn new() -> Self {
        SyscallStats {
            total_calls: 0,
            exit_calls: 0,
            fork_calls: 0,
            read_calls: 0,
            write_calls: 0,
            failed_calls: 0,
        }
    }

    pub fn print(&self) {
        println!("=== Syscall Statistics ===");
        println!("Total calls:  {}", self.total_calls);
        println!("Exit calls:   {}", self.exit_calls);
        println!("Fork calls:   {}", self.fork_calls);
        println!("Read calls:   {}", self.read_calls);
        println!("Write calls:  {}", self.write_calls);
        println!("Failed calls: {}", self.failed_calls);
    }
}
