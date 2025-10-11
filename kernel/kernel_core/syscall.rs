//! 系统调用接口
//! 
//! 实现类POSIX系统调用，提供用户程序与内核交互的接口

use alloc::string::String;
use alloc::vec::Vec;
use crate::process::{ProcessId, terminate_process, create_process, current_pid, get_process};

/// 系统调用号定义（参考Linux系统调用表）
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // 进程管理
    Exit = 60,          // 退出进程
    Fork = 57,          // 创建子进程
    Exec = 59,          // 执行程序
    Wait = 61,          // 等待子进程
    GetPid = 39,        // 获取进程ID
    GetPPid = 110,      // 获取父进程ID
    Kill = 62,          // 发送信号
    
    // 文件I/O
    Read = 0,           // 读取文件
    Write = 1,          // 写入文件
    Open = 2,           // 打开文件
    Close = 3,          // 关闭文件
    Stat = 4,           // 获取文件状态
    Lseek = 8,          // 移动文件指针
    
    // 内存管理
    Brk = 12,           // 改变数据段大小
    Mmap = 9,           // 内存映射
    Munmap = 11,        // 取消内存映射
    Mprotect = 10,      // 设置内存保护
    
    // 进程间通信
    Pipe = 22,          // 创建管道
    Dup = 32,           // 复制文件描述符
    Dup2 = 33,          // 复制文件描述符到指定位置
    
    // 时间相关
    Time = 201,         // 获取时间
    Sleep = 35,         // 睡眠
    
    // 其他
    Yield = 24,         // 主动让出CPU
    GetCwd = 79,        // 获取当前工作目录
    Chdir = 80,         // 改变当前工作目录
}

/// 系统调用错误码
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    Success = 0,        // 成功
    EPERM = -1,         // 操作不允许
    ENOENT = -2,        // 文件或目录不存在
    ESRCH = -3,         // 进程不存在
    EINTR = -4,         // 系统调用被中断
    EIO = -5,           // I/O错误
    ENXIO = -6,         // 设备不存在
    E2BIG = -7,         // 参数列表过长
    ENOEXEC = -8,       // 执行格式错误
    EBADF = -9,         // 文件描述符错误
    ECHILD = -10,       // 没有子进程
    EAGAIN = -11,       // 资源暂时不可用
    ENOMEM = -12,       // 内存不足
    EACCES = -13,       // 权限不足
    EFAULT = -14,       // 地址错误
    EBUSY = -16,        // 设备或资源忙
    EEXIST = -17,       // 文件已存在
    ENOTDIR = -20,      // 不是目录
    EISDIR = -21,       // 是目录
    EINVAL = -22,       // 无效参数
    ENFILE = -23,       // 系统打开文件过多
    EMFILE = -24,       // 进程打开文件过多
    ENOSYS = -38,       // 功能未实现
}

impl SyscallError {
    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

/// 系统调用结果类型
pub type SyscallResult = Result<usize, SyscallError>;

/// 初始化系统调用处理器
pub fn init() {
    println!("Syscall handler initialized");
    println!("  Supported syscalls: exit, fork, getpid, read, write, yield");
}

/// 系统调用分发器
/// 
/// 根据系统调用号和参数执行相应的系统调用
pub fn syscall_dispatcher(
    syscall_num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    let result = match syscall_num {
        // 进程管理
        60 => sys_exit(arg0 as i32),
        57 => sys_fork(),
        59 => sys_exec(arg0 as *const u8, arg1 as *const *const u8),
        61 => sys_wait(arg0 as *mut i32),
        39 => sys_getpid(),
        110 => sys_getppid(),
        62 => sys_kill(arg0 as ProcessId, arg1 as i32),
        
        // 文件I/O
        0 => sys_read(arg0 as i32, arg1 as *mut u8, arg2 as usize),
        1 => sys_write(arg0 as i32, arg1 as *const u8, arg2 as usize),
        2 => sys_open(arg0 as *const u8, arg1 as i32, arg2 as u32),
        3 => sys_close(arg0 as i32),
        
        // 内存管理
        12 => sys_brk(arg0 as usize),
        9 => sys_mmap(arg0 as usize, arg1 as usize, arg2 as i32, arg3 as i32, arg4 as i32, arg5 as i64),
        11 => sys_munmap(arg0 as usize, arg1 as usize),
        
        // 其他
        24 => sys_yield(),
        
        _ => Err(SyscallError::ENOSYS),
    };
    
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
        Ok(0)
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_fork - 创建子进程
fn sys_fork() -> SyscallResult {
    if let Some(parent_pid) = current_pid() {
        // 创建子进程（简化版本，实际需要复制父进程的地址空间）
        let child_pid = create_process("child".into(), parent_pid, 100);
        
        println!("Fork: parent={}, child={}", parent_pid, child_pid);
        
        // 父进程返回子进程PID，子进程返回0
        // 这里简化处理，只返回子进程PID
        Ok(child_pid)
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_exec - 执行新程序
fn sys_exec(_path: *const u8, _argv: *const *const u8) -> SyscallResult {
    // TODO: 实现程序加载和执行
    println!("sys_exec: not implemented yet");
    Err(SyscallError::ENOSYS)
}

/// sys_wait - 等待子进程
fn sys_wait(_status: *mut i32) -> SyscallResult {
    // TODO: 实现等待子进程
    println!("sys_wait: not implemented yet");
    Err(SyscallError::ENOSYS)
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
fn sys_kill(_pid: ProcessId, _sig: i32) -> SyscallResult {
    // TODO: 实现信号发送
    println!("sys_kill: not implemented yet");
    Err(SyscallError::ENOSYS)
}

// ============================================================================
// 文件I/O系统调用
// ============================================================================

/// sys_read - 从文件描述符读取数据
fn sys_read(fd: i32, buf: *mut u8, count: usize) -> SyscallResult {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    
    // TODO: 实现实际的文件读取
    println!("sys_read: fd={}, count={}", fd, count);
    
    // 简化实现：返回0表示EOF
    Ok(0)
}

/// sys_write - 向文件描述符写入数据
fn sys_write(fd: i32, buf: *const u8, count: usize) -> SyscallResult {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    
    // 简化实现：只支持stdout(1)和stderr(2)
    if fd == 1 || fd == 2 {
        unsafe {
            let slice = core::slice::from_raw_parts(buf, count);
            if let Ok(s) = core::str::from_utf8(slice) {
                print!("{}", s);
                Ok(count)
            } else {
                Err(SyscallError::EINVAL)
            }
        }
    } else {
        println!("sys_write: fd={} not supported", fd);
        Err(SyscallError::EBADF)
    }
}

/// sys_open - 打开文件
fn sys_open(_path: *const u8, _flags: i32, _mode: u32) -> SyscallResult {
    // TODO: 实现文件打开
    println!("sys_open: not implemented yet");
    Err(SyscallError::ENOSYS)
}

/// sys_close - 关闭文件描述符
fn sys_close(_fd: i32) -> SyscallResult {
    // TODO: 实现文件关闭
    println!("sys_close: not implemented yet");
    Err(SyscallError::ENOSYS)
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
fn sys_mmap(
    addr: usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> SyscallResult {
    use x86_64::{VirtAddr, PhysAddr};
    use x86_64::structures::paging::{PageTableFlags, Page, PhysFrame, Size4KiB};
    
    // 验证参数
    if length == 0 {
        return Err(SyscallError::EINVAL);
    }
    
    // 对齐到页边界
    let length_aligned = (length + 0xfff) & !0xfff;
    
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
    
    println!("sys_mmap: addr=0x{:x}, len=0x{:x}, prot=0x{:x}, flags=0x{:x}",
             addr, length_aligned, prot, flags);
    
    // 简化实现：分配物理内存并映射
    // 在实际实现中，需要：
    // 1. 查找可用的虚拟地址空间
    // 2. 分配物理页帧
    // 3. 建立映射关系
    // 4. 如果是文件映射，还需要从文件读取数据
    
    if fd >= 0 {
        // 文件映射暂不支持
        return Err(SyscallError::ENOSYS);
    }
    
    // 匿名映射：分配新的虚拟地址空间
    // 这里简化处理，实际需要维护进程的虚拟地址空间管理器
    let virt_addr = if addr == 0 {
        // 内核分配地址（简化：使用固定范围）
        0x40000000usize
    } else {
        addr
    };
    
    println!("  Mapped at virtual address: 0x{:x}", virt_addr);
    
    // TODO: 实际建立页表映射
    // 需要调用页表管理器的map_range函数
    
    Ok(virt_addr)
}

/// sys_munmap - 取消内存映射
fn sys_munmap(addr: usize, length: usize) -> SyscallResult {
    if addr & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }
    
    if length == 0 {
        return Err(SyscallError::EINVAL);
    }
    
    let length_aligned = (length + 0xfff) & !0xfff;
    
    println!("sys_munmap: addr=0x{:x}, len=0x{:x}", addr, length_aligned);
    
    // TODO: 实际取消页表映射并释放物理内存
    // 需要调用页表管理器的unmap_range函数
    
    Ok(0)
}

// ============================================================================
// 其他系统调用
// ============================================================================

/// sys_yield - 主动让出CPU
fn sys_yield() -> SyscallResult {
    // 触发调度器重新调度
    // 注意：实际的调度会在返回用户态时由内核主循环处理
    println!("Process yielding CPU");
    
    // 将当前进程状态设置为Ready，让调度器选择其他进程
    if let Some(pid) = current_pid() {
        if let Some(process) = get_process(pid) {
            let mut proc = process.lock();
            proc.state = crate::process::ProcessState::Ready;
        }
    }
    
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
