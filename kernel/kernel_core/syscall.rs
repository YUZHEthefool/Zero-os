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
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

// Audit integration for syscall security monitoring
use audit::{AuditKind, AuditObject, AuditOutcome, AuditSubject};

/// 最大参数数量（防止恶意用户传递过多参数）
const MAX_ARG_COUNT: usize = 256;

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
    Exit = 60,     // 退出进程
    Fork = 57,     // 创建子进程
    Exec = 59,     // 执行程序
    Wait = 61,     // 等待子进程
    GetPid = 39,   // 获取进程ID
    GetPPid = 110, // 获取父进程ID
    Kill = 62,     // 发送信号

    // 文件I/O
    Read = 0,  // 读取文件
    Write = 1, // 写入文件
    Open = 2,  // 打开文件
    Close = 3, // 关闭文件
    Stat = 4,  // 获取文件状态
    Lseek = 8, // 移动文件指针

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
    Yield = 24,  // 主动让出CPU
    GetCwd = 79, // 获取当前工作目录
    Chdir = 80,  // 改变当前工作目录
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
    EPIPE = -32,   // 管道破裂
    ENOSYS = -38,  // 功能未实现
}

impl SyscallError {
    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

/// 系统调用结果类型
pub type SyscallResult = Result<usize, SyscallError>;

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

    let result = match syscall_num {
        // 进程管理
        60 => sys_exit(arg0 as i32),
        57 => sys_fork(),
        59 => sys_exec(
            arg0 as *const u8,
            arg1 as usize,
            arg2 as *const *const u8,
            arg3 as *const *const u8,
        ),
        61 => sys_wait(arg0 as *mut i32),
        39 => sys_getpid(),
        110 => sys_getppid(),
        62 => sys_kill(arg0 as ProcessId, arg1 as i32),

        // 文件I/O
        0 => sys_read(arg0 as i32, arg1 as *mut u8, arg2 as usize),
        1 => sys_write(arg0 as i32, arg1 as *const u8, arg2 as usize),
        2 => sys_open(arg0 as *const u8, arg1 as i32, arg2 as u32),
        3 => sys_close(arg0 as i32),
        4 => sys_stat(arg0 as *const u8, arg1 as *mut VfsStat),
        8 => sys_lseek(arg0 as i32, arg1 as i64, arg2 as i32),
        22 => sys_pipe(arg0 as *mut i32),

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
        11 => sys_munmap(arg0 as usize, arg1 as usize),

        // Futex
        202 => sys_futex(arg0 as usize, arg1 as i32, arg2 as u32),

        // 其他
        24 => sys_yield(),

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

/// sys_fork - 创建子进程
fn sys_fork() -> SyscallResult {
    if current_pid().is_none() {
        return Err(SyscallError::ESRCH);
    }
    // 调用真正的 fork 实现（包含 COW 支持）
    match crate::fork::sys_fork() {
        Ok(child_pid) => Ok(child_pid),
        Err(_) => Err(SyscallError::ENOMEM),
    }
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

    // 获取 VFS 回调
    let open_fn = {
        let callback = VFS_OPEN_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS 打开文件
    let file_ops = open_fn(&path_str, flags as u32, mode)?;

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

// ============================================================================
// 内存管理系统调用
// ============================================================================

/// sys_brk - 改变数据段大小
fn sys_brk(_addr: usize) -> SyscallResult {
    // TODO: 实现堆管理
    println!("sys_brk: not implemented yet");
    Err(SyscallError::ENOSYS)
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
    let unmap_result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            let mut frame_alloc = FrameAllocator::new();

            // 取消映射并根据引用计数决定是否释放物理帧
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
                        frame_alloc.deallocate_frame(frame);
                    }
                }
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
