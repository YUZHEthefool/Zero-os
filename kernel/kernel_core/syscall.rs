//! 系统调用接口
//!
//! 实现类POSIX系统调用，提供用户程序与内核交互的接口

use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use crate::fork::PAGE_REF_COUNT;
use crate::process::{ProcessId, ProcessState, terminate_process, cleanup_zombie, create_process, current_pid, get_process};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

/// 最大参数数量（防止恶意用户传递过多参数）
const MAX_ARG_COUNT: usize = 256;

/// 最大参数总字节数（argv + envp 字符串总大小上限）
const MAX_ARG_TOTAL: usize = 128 * 1024;

/// 单个参数最大长度
const MAX_ARG_STRLEN: usize = 4096;

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
        mm::page_table::with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
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
        })
    }
}

/// 从用户态缓冲区安全复制数据到内核缓冲区
///
/// 先验证用户空间内存映射，然后执行复制。
/// 这可以防止访问未映射内存导致的内核崩溃。
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

    // 验证用户内存已映射且可读
    verify_user_memory(user_src, dest.len(), false)?;

    // 安全复制数据
    unsafe {
        core::ptr::copy_nonoverlapping(user_src, dest.as_mut_ptr(), dest.len());
    }
    Ok(())
}

/// 将内核缓冲区的数据安全复制到用户态缓冲区
///
/// 先验证用户空间内存映射和写入权限，然后执行复制。
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

    // 验证用户内存已映射且可写入
    // require_write=true 会检查 WRITABLE 或 BIT_9 (COW) 标志
    // - WRITABLE: 直接可写
    // - BIT_9 (COW): 写入时触发 #PF，由 COW 处理器创建可写副本
    // - 两者都没有: 真正的只读页面（如代码段），返回 EFAULT
    verify_user_memory(user_dst as *const u8, src.len(), true)?;

    // 安全复制数据
    // 如果是 COW 页面，这里会触发 #PF，COW 处理器会处理
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), user_dst, src.len());
    }
    Ok(())
}

/// 从用户空间复制以 '\0' 结尾的 C 字符串到内核缓冲区
///
/// 逐字节读取直到遇到 NUL 终止符，限制最大长度防止恶意无限字符串
fn copy_user_cstring(ptr: *const u8) -> Result<Vec<u8>, SyscallError> {
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let mut buf = Vec::new();

    for i in 0..=MAX_ARG_STRLEN {
        // 每次只验证 1 字节，避免跨页访问未映射内存
        verify_user_memory(unsafe { ptr.add(i) }, 1, false)?;
        let byte = unsafe { *ptr.add(i) };
        if byte == 0 {
            return Ok(buf);
        }
        buf.push(byte);
    }

    // 字符串超过最大长度限制
    Err(SyscallError::E2BIG)
}

/// 将用户空间的字符串指针数组（以 NULL 结尾）复制到内核
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
        let entry_addr = base
            .checked_add(idx * word)
            .ok_or(SyscallError::EFAULT)?;

        // 验证指针地址可读
        verify_user_memory(entry_addr as *const u8, word, false)?;

        // 读取指针值
        let entry = unsafe { *(entry_addr as *const *const u8) };
        if entry.is_null() {
            break;  // NULL 终止
        }

        // 复制字符串内容
        let s = copy_user_cstring(entry)?;
        total = total
            .checked_add(s.len() + 1)  // +1 for trailing '\0'
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

/// 系统调用分发器
///
/// 根据系统调用号和参数执行相应的系统调用
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
    let result = match syscall_num {
        // 进程管理
        60 => sys_exit(arg0 as i32),
        57 => sys_fork(),
        59 => sys_exec(arg0 as *const u8, arg1 as usize, arg2 as *const *const u8, arg3 as *const *const u8),
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
    use crate::fork::create_fresh_address_space;
    use crate::elf_loader::{load_elf, USER_STACK_SIZE};
    use crate::process::{get_process, current_pid, activate_memory_space, ProcessState, free_address_space};

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 验证参数：非空、合理大小
    if image.is_null() || image_len == 0 {
        return Err(SyscallError::EINVAL);
    }
    if image_len > MAX_EXEC_IMAGE_SIZE {
        println!("sys_exec: ELF size {} exceeds limit {}", image_len, MAX_EXEC_IMAGE_SIZE);
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
    let (_new_pml4_frame, new_memory_space) = create_fresh_address_space()
        .map_err(|_| SyscallError::ENOMEM)?;

    // 保存旧地址空间以便失败时恢复或成功时释放
    let old_memory_space = {
        let proc = process.lock();
        proc.memory_space
    };

    // 切换到新地址空间
    activate_memory_space(new_memory_space);

    // 加载 ELF 映像
    let load_result = match load_elf(&elf_data) {
        Ok(result) => result,
        Err(e) => {
            // 加载失败，恢复旧地址空间
            activate_memory_space(old_memory_space);
            free_address_space(new_memory_space);
            println!("sys_exec: ELF load failed: {:?}", e);
            return Err(SyscallError::ENOEXEC);
        }
    };

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
    let string_bytes: usize = argv_vec.iter()
        .chain(envp_vec.iter())
        .map(|s| s.len() + 1)  // +1 for '\0'
        .sum();

    // 指针区大小: argc + argv_ptrs + NULL + envp_ptrs + NULL
    let pointer_count = 1 + argc + 1 + envc + 1;
    let pointer_bytes = pointer_count * word;

    // 检查栈空间是否足够
    let stack_top = load_result.user_stack_top as usize;
    let stack_base = stack_top.checked_sub(USER_STACK_SIZE).ok_or(SyscallError::EFAULT)?;

    let total_needed = string_bytes + pointer_bytes + 16;  // +16 for alignment
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
            *((sp + len) as *mut u8) = 0;  // NUL 终止
        }
        argv_ptrs.push(sp);
    }
    argv_ptrs.reverse();  // 恢复正序

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
        sp -= word;  // 添加填充使最终 RSP % 16 == 8
        unsafe { *(sp as *mut usize) = 0; }
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
    let argv_base = (sp + word) as u64;  // argv[0] 的地址

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

    // 释放旧地址空间
    if old_space != 0 {
        free_address_space(old_space);
    }

    println!("sys_exec: entry=0x{:x}, rsp=0x{:x}, argc={}",
             load_result.entry, final_rsp, argc);

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
            proc.waiting_child = Some(0);  // 0 表示等待任意子进程
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

            println!("sys_wait: reaped child {} with exit code {}", child_pid, exit_code);
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
    if count == 0 {
        return Ok(0);
    }

    // TODO: 实现实际的文件读取
    println!("sys_read: fd={}, count={}", fd, count);

    // 简化实现：填充零数据，主要用于测试用户缓冲区访问路径
    // 注意：使用 copy_to_user 进行安全复制，验证用户缓冲区映射
    let data = vec![0u8; count];
    copy_to_user(buf, &data)?;
    Ok(data.len())
}

/// sys_write - 向文件描述符写入数据
fn sys_write(fd: i32, buf: *const u8, count: usize) -> SyscallResult {
    if count == 0 {
        return Ok(0);
    }

    // 先复制到内核缓冲区，避免直接解引用用户指针
    // 这可以防止用户传递未映射地址导致的内核崩溃
    let mut tmp = vec![0u8; count];
    copy_from_user(&mut tmp, buf)?;

    // 简化实现：只支持stdout(1)和stderr(2)
    if fd == 1 || fd == 2 {
        if let Ok(s) = core::str::from_utf8(&tmp) {
            print!("{}", s);
            Ok(tmp.len())
        } else {
            Err(SyscallError::EINVAL)
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

    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length
        .checked_add(0xfff)
        .ok_or(SyscallError::EINVAL)?
        & !0xfff;

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
    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length
        .checked_add(0xfff)
        .ok_or(SyscallError::EINVAL)?
        & !0xfff;

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

    println!("sys_munmap: pid={}, unmapped {} bytes at 0x{:x}", pid, length_aligned, addr);

    Ok(0)
}

// ============================================================================
// 其他系统调用
// ============================================================================

/// sys_yield - 主动让出CPU
fn sys_yield() -> SyscallResult {
    println!("Process yielding CPU");

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
