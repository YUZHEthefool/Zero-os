//! 系统调用接口
//!
//! 实现类POSIX系统调用，提供用户程序与内核交互的接口

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

/// 用户空间地址上界
///
/// x86_64 规范地址空间中，用户空间使用低半区（0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF）
/// 内核空间使用高半区（0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF）
const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

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
    // 验证用户缓冲区
    validate_user_ptr_mut(buf, count)?;

    // TODO: 实现实际的文件读取
    println!("sys_read: fd={}, count={}", fd, count);

    // 简化实现：返回0表示EOF
    Ok(0)
}

/// sys_write - 向文件描述符写入数据
fn sys_write(fd: i32, buf: *const u8, count: usize) -> SyscallResult {
    // 验证用户缓冲区
    validate_user_ptr(buf, count)?;

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
    use x86_64::VirtAddr;
    use x86_64::structures::paging::{PageTableFlags, Page};
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;

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

    // 从进程 PCB 中选择地址并检查重叠
    let (base, end, update_next) = {
        let proc = process.lock();

        // 选择起始虚拟地址
        let chosen_base = if addr == 0 {
            (proc.next_mmap_addr + 0xfff) & !0xfff
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
    let map_result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            let mut frame_alloc = FrameAllocator::new();

            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((base + offset) as u64));
                let frame = frame_alloc.allocate_frame().ok_or(SyscallError::ENOMEM)?;

                // 安全：清零新分配的帧，防止泄漏其他进程的数据
                core::ptr::write_bytes(frame.start_address().as_u64() as *mut u8, 0, 0x1000);

                if let Err(_) = manager.map_page(page, frame, page_flags, &mut frame_alloc) {
                    // 映射失败，清理已分配的页
                    for cleanup_offset in (0..offset).step_by(0x1000) {
                        let cleanup_page = Page::containing_address(VirtAddr::new((base + cleanup_offset) as u64));
                        if let Ok(cleanup_frame) = manager.unmap_page(cleanup_page) {
                            frame_alloc.deallocate_frame(cleanup_frame);
                        }
                    }
                    return Err(SyscallError::ENOMEM);
                }
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

    println!("sys_mmap: pid={}, mapped {} bytes at 0x{:x}", pid, length_aligned, base);

    Ok(base)
}

/// sys_munmap - 取消内存映射
///
/// 使用当前进程的地址空间进行取消映射，确保进程隔离
fn sys_munmap(addr: usize, length: usize) -> SyscallResult {
    use x86_64::VirtAddr;
    use x86_64::structures::paging::Page;
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;

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
    let length_aligned = (length + 0xfff) & !0xfff;

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

            // 取消映射并释放物理帧
            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((addr + offset) as u64));
                if let Ok(frame) = manager.unmap_page(page) {
                    frame_alloc.deallocate_frame(frame);
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

    println!("sys_munmap: pid={}, unmapped {} bytes at 0x{:x}", pid, length_aligned, addr);

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
