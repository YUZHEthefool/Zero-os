use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec, string::String, sync::Arc};
use core::any::Any;
use spin::Mutex;
use x86_64::{
    PhysAddr, VirtAddr,
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB},
};
use crate::fork::PAGE_REF_COUNT;
use crate::signal::PendingSignals;
use crate::time;
use mm::memory::FrameAllocator;
use mm::page_table;

/// 进程ID类型
pub type ProcessId = usize;

/// 进程优先级（0-139，数值越小优先级越高）
pub type Priority = u8;

/// mmap 默认起始地址
const DEFAULT_MMAP_BASE: usize = 0x4000_0000;

/// 页大小
const PAGE_SIZE: u64 = 0x1000;

/// 每进程内核栈基址（PML4[511]/PDPT[508]，在共享内核空间内）
pub const KSTACK_BASE: u64 = 0xFFFF_FFFF_0000_0000;

/// 每进程内核栈步长（16KB 栈 + 4KB 守护页 = 20KB）
pub const KSTACK_STRIDE: u64 = 0x5000;

/// 内核栈页数（16KB = 4 页）
const KSTACK_PAGES: usize = 4;

/// 守护页数
const KSTACK_GUARD_PAGES: usize = 1;

/// 调度器清理回调类型
type SchedulerCleanupCallback = fn(ProcessId);

/// IPC清理回调类型
type IpcCleanupCallback = fn(ProcessId);

/// 最大文件描述符数量（每进程）
pub const MAX_FD: i32 = 256;

/// 文件操作 trait
///
/// 定义文件描述符必须实现的操作，支持：
/// - 克隆（用于 fork）
/// - 向下转型（用于类型特定操作）
/// - 调试输出
///
/// 由于循环依赖限制，kernel_core 定义此 trait，具体类型（如 PipeHandle）
/// 在各自的 crate（如 ipc）中实现。
pub trait FileOps: Send + Sync {
    /// 克隆此文件描述符（用于 fork）
    fn clone_box(&self) -> Box<dyn FileOps>;

    /// 获取 Any 引用用于向下转型
    fn as_any(&self) -> &dyn Any;

    /// 获取类型名称（用于调试）
    fn type_name(&self) -> &'static str;
}

impl core::fmt::Debug for dyn FileOps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FileOps({})", self.type_name())
    }
}

/// 文件描述符类型
pub type FileDescriptor = Box<dyn FileOps>;

/// 内核栈分配错误
#[derive(Debug, Clone, Copy)]
pub enum KernelStackError {
    /// 栈地址已被映射（PID 复用时可能发生）
    AlreadyMapped,
    /// 物理内存分配失败
    AllocationFailed,
    /// 页表映射失败
    MapFailed,
}

/// 进程创建错误
///
/// SECURITY FIX Z-7: 进程创建失败时必须正确报告错误，而非静默回退
#[derive(Debug, Clone, Copy)]
pub enum ProcessCreateError {
    /// 内核栈分配失败
    KernelStackAllocFailed(KernelStackError),
}

/// 计算指定 PID 的内核栈虚拟地址范围
///
/// 返回 (栈底, 栈顶)，栈向下生长，栈顶用于 TSS.rsp0
#[inline]
pub fn kernel_stack_slot(pid: ProcessId) -> (VirtAddr, VirtAddr) {
    let guard_base = VirtAddr::new(KSTACK_BASE + pid as u64 * KSTACK_STRIDE);
    let stack_base = guard_base + (KSTACK_GUARD_PAGES as u64 * PAGE_SIZE);
    let stack_top = stack_base + (KSTACK_PAGES as u64 * PAGE_SIZE);
    (stack_base, stack_top)
}

/// 为指定 PID 分配并映射带守护页的内核栈
///
/// 在共享的内核页表上映射，所有进程地址空间均可见。
/// 守护页不映射物理帧，访问时会触发页错误。
///
/// # Returns
///
/// 成功返回 (栈底, 栈顶)，失败返回错误
pub fn allocate_kernel_stack(pid: ProcessId) -> Result<(VirtAddr, VirtAddr), KernelStackError> {
    let (stack_base, stack_top) = kernel_stack_slot(pid);
    let guard_base = VirtAddr::new(KSTACK_BASE + pid as u64 * KSTACK_STRIDE);

    let mut frame_alloc = FrameAllocator::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            // 检查整个 slot（守护页 + 栈页）是否已被映射
            let total_pages = KSTACK_PAGES + KSTACK_GUARD_PAGES;
            for i in 0..total_pages {
                let addr = guard_base + (i as u64 * PAGE_SIZE);
                if mgr.translate_addr(addr).is_some() {
                    return Err(KernelStackError::AlreadyMapped);
                }
            }

            // 分配连续物理帧
            let phys_start = frame_alloc
                .allocate_contiguous_frames(KSTACK_PAGES)
                .ok_or(KernelStackError::AllocationFailed)?
                .start_address();

            // 内核栈页标志：可写、不可执行、全局（跨 CR3 有效）
            let flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::GLOBAL;

            // 映射栈页（守护页不映射，自动触发页错误）
            let stack_size = (KSTACK_PAGES as u64 * PAGE_SIZE) as usize;
            mgr.map_range(stack_base, phys_start, stack_size, flags, &mut frame_alloc)
                .map_err(|_| KernelStackError::MapFailed)?;

            // 清零栈区域
            core::ptr::write_bytes(stack_base.as_mut_ptr::<u8>(), 0, stack_size);

            Ok((stack_base, stack_top))
        })
    }
}

/// 进程状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// 就绪状态，等待被调度
    Ready,
    /// 运行状态
    Running,
    /// 阻塞状态（等待I/O或其他事件）
    Blocked,
    /// 暂停状态（如 SIGSTOP）
    Stopped,
    /// 睡眠状态
    Sleeping,
    /// 僵尸状态（已终止但未被父进程回收）
    Zombie,
    /// 已终止
    Terminated,
}

/// FXSAVE 区域大小（512 字节）
const FXSAVE_SIZE: usize = 512;

/// 512 字节的 FXSAVE/FXRSTOR 区域
/// 按 64 字节对齐以兼容 XSAVE 路径
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FxSaveArea {
    pub data: [u8; FXSAVE_SIZE],
}

impl core::fmt::Debug for FxSaveArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FxSaveArea").finish_non_exhaustive()
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

/// CPU上下文（用于进程切换）
///
/// 包含通用寄存器和 FPU/SIMD 状态，与 arch::Context 布局一致
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
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

    // 指令指针和标志 (偏移 0x80 - 0x8F)
    pub rip: u64,
    pub rflags: u64,

    // 段寄存器 (偏移 0x90 - 0x9F)
    pub cs: u64,
    pub ss: u64,

    // 填充以对齐 FxSaveArea 到 64 字节边界 (偏移 0xA0 - 0xBF)
    _padding: [u64; 4],

    /// FPU/SIMD 保存区 (偏移 0xC0)
    pub fx: FxSaveArea,
}

impl Default for Context {
    fn default() -> Self {
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
            fx: FxSaveArea::default(),
        }
    }
}

/// 进程控制块（PCB）
///
/// 注意：Process 不实现 Clone，因为 fd_table 包含不可克隆的 Box<dyn FileOps>。
/// 进程复制（fork）通过手动字段复制和 clone_box() 实现。
#[derive(Debug)]
pub struct Process {
    /// 进程ID
    pub pid: ProcessId,
    
    /// 父进程ID
    pub ppid: ProcessId,
    
    /// 进程名称
    pub name: String,
    
    /// 进程状态
    pub state: ProcessState,

    /// 挂起的信号位图（1-64）
    pub pending_signals: PendingSignals,

    /// 进程优先级（静态优先级）
    pub priority: Priority,
    
    /// 动态优先级（用于调度）
    pub dynamic_priority: Priority,
    
    /// 时间片（剩余时间片，单位：毫秒）
    pub time_slice: u32,
    
    /// CPU上下文
    pub context: Context,
    
    /// 内核栈指针（栈底）
    pub kernel_stack: VirtAddr,

    /// 内核栈顶（用于 TSS.rsp0）
    pub kernel_stack_top: VirtAddr,

    /// 用户栈指针（如果是用户进程）
    pub user_stack: Option<VirtAddr>,
    
    /// 内存空间（页表基址）
    pub memory_space: usize,

    /// mmap 区域跟踪 (起始地址 -> 长度)
    pub mmap_regions: BTreeMap<usize, usize>,

    /// 下一个自动分配的 mmap 起始地址
    pub next_mmap_addr: usize,

    /// 文件描述符表（fd -> 描述符）
    ///
    /// fd 0/1/2 分别保留给 stdin/stdout/stderr，新分配从 3 开始
    pub fd_table: BTreeMap<i32, FileDescriptor>,

    /// 退出码
    pub exit_code: Option<i32>,

    /// 等待的子进程（Some(0) 表示等待任意子进程，Some(pid) 表示等待特定子进程）
    pub waiting_child: Option<ProcessId>,

    /// 子进程列表
    pub children: Vec<ProcessId>,

    /// CPU时间统计（毫秒）
    pub cpu_time: u64,

    /// 创建时间戳
    pub created_at: u64,

    // ========== 进程凭证 (DAC支持) ==========

    /// 真实用户ID (uid)
    pub uid: u32,

    /// 真实组ID (gid)
    pub gid: u32,

    /// 有效用户ID (euid) - 用于权限检查
    pub euid: u32,

    /// 有效组ID (egid) - 用于权限检查
    pub egid: u32,

    /// 附属组ID列表 (supplementary groups)
    /// 用于扩展组权限检查，进程可以属于多个组
    pub supplementary_groups: Vec<u32>,

    /// 文件创建掩码 (umask)
    /// 新建文件的权限 = mode & !umask
    pub umask: u16,
}

impl Process {
    /// 创建新进程
    ///
    /// 默认以root权限运行（uid=0, gid=0），umask为标准0o022
    pub fn new(pid: ProcessId, ppid: ProcessId, name: String, priority: Priority) -> Self {
        Process {
            pid,
            ppid,
            name,
            state: ProcessState::Ready,
            pending_signals: PendingSignals::new(),
            priority,
            dynamic_priority: priority,
            time_slice: calculate_time_slice(priority),
            context: Context::default(),
            kernel_stack: VirtAddr::new(0),
            kernel_stack_top: VirtAddr::new(0),
            user_stack: None,
            memory_space: 0,
            mmap_regions: BTreeMap::new(),
            next_mmap_addr: DEFAULT_MMAP_BASE,
            fd_table: BTreeMap::new(),
            exit_code: None,
            waiting_child: None,
            children: Vec::new(),
            cpu_time: 0,
            created_at: time::current_timestamp_ms(),
            // 默认以root运行，标准umask
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            supplementary_groups: Vec::new(),
            umask: 0o022,
        }
    }

    /// 分配新的文件描述符
    ///
    /// fd 0/1/2 保留给标准输入/输出/错误，新分配从 3 开始
    ///
    /// # Returns
    ///
    /// 成功返回分配的 fd，失败（达到上限）返回 None
    pub fn allocate_fd(&mut self, desc: FileDescriptor) -> Option<i32> {
        let fd = self.next_available_fd()?;
        self.fd_table.insert(fd, desc);
        Some(fd)
    }

    /// 获取指定 fd 对应的描述符引用
    pub fn get_fd(&self, fd: i32) -> Option<&FileDescriptor> {
        if fd < 0 {
            return None;
        }
        self.fd_table.get(&fd)
    }

    /// 移除并返回指定 fd 的描述符
    ///
    /// 关闭文件描述符时使用，描述符的 Drop 会自动处理资源清理
    pub fn remove_fd(&mut self, fd: i32) -> Option<FileDescriptor> {
        if fd < 0 {
            return None;
        }
        self.fd_table.remove(&fd)
    }

    /// 查找下一个可用的 fd（从 3 开始）
    fn next_available_fd(&self) -> Option<i32> {
        // 从 3 开始，因为 0/1/2 保留给标准流
        let mut fd: i32 = 3;
        while fd < MAX_FD {
            if !self.fd_table.contains_key(&fd) {
                return Some(fd);
            }
            fd = fd.checked_add(1)?;
        }
        None // 已达到 fd 上限
    }

    /// 重置时间片
    pub fn reset_time_slice(&mut self) {
        self.time_slice = calculate_time_slice(self.dynamic_priority);
    }
    
    /// 更新动态优先级（用于公平调度）
    pub fn update_dynamic_priority(&mut self) {
        // 简单的优先级提升策略
        if self.dynamic_priority > 0 {
            self.dynamic_priority -= 1;
        }
    }
    
    /// 降低动态优先级（惩罚CPU密集型进程）
    pub fn decrease_dynamic_priority(&mut self) {
        if self.dynamic_priority < 139 {
            self.dynamic_priority += 1;
        }
    }
    
    /// 恢复静态优先级
    pub fn restore_static_priority(&mut self) {
        self.dynamic_priority = self.priority;
    }
}

/// 根据优先级计算时间片（毫秒）
fn calculate_time_slice(priority: Priority) -> u32 {
    // 优先级越高，时间片越长
    // 优先级0-99: 100-200ms
    // 优先级100-139: 10-100ms
    if priority < 100 {
        200 - priority as u32
    } else {
        140 - priority as u32
    }
}

/// 全局进程表
///
/// 使用 Option<Arc<Mutex<Process>>> 以支持 PID 作为直接索引。
/// 索引 0 保留为空（PID 从 1 开始），实际进程存储在其 PID 对应的索引位置。
lazy_static::lazy_static! {
    pub static ref PROCESS_TABLE: Mutex<Vec<Option<Arc<Mutex<Process>>>>> = Mutex::new(vec![None]); // 索引0预留
    static ref SCHEDULER_CLEANUP: Mutex<Option<SchedulerCleanupCallback>> = Mutex::new(None);
    static ref IPC_CLEANUP: Mutex<Option<IpcCleanupCallback>> = Mutex::new(None);
    /// 缓存引导时的 CR3 值，用于内核进程或 memory_space == 0 的情况
    static ref BOOT_CR3: (PhysFrame<Size4KiB>, Cr3Flags) = Cr3::read();
}

/// 当前运行的进程ID
static CURRENT_PID: Mutex<Option<ProcessId>> = Mutex::new(None);

/// 下一个可用的PID
static NEXT_PID: Mutex<ProcessId> = Mutex::new(1);

/// 初始化进程子系统
///
/// 必须在任何进程创建或调度之前调用，以确保 BOOT_CR3 捕获正确的引导页表值。
pub fn init() {
    // 强制 BOOT_CR3 lazy_static 初始化，确保捕获当前（引导）CR3
    let _ = *BOOT_CR3;
    println!("  Process subsystem initialized (boot CR3 cached)");
}

/// 创建新进程
///
/// # Arguments
/// * `name` - 进程名称
/// * `ppid` - 父进程 ID（0 表示无父进程）
/// * `priority` - 进程优先级
///
/// # Returns
/// 成功返回新创建进程的 PID，失败返回错误
///
/// # Security Fix Z-7
/// 内核栈分配失败时必须返回错误终止进程创建，绝不能共享内核栈
pub fn create_process(name: String, ppid: ProcessId, priority: Priority) -> Result<ProcessId, ProcessCreateError> {
    // 先尝试分配内核栈，失败则直接返回错误（不分配 PID）
    let mut next_pid_guard = NEXT_PID.lock();
    let pid = *next_pid_guard;

    // 为进程分配内核栈 - SECURITY FIX Z-7: 失败时必须返回错误
    let (stack_base, stack_top) = match allocate_kernel_stack(pid) {
        Ok((base, top)) => (base, top),
        Err(e) => {
            println!("Error: Failed to allocate kernel stack for PID {}: {:?}", pid, e);
            return Err(ProcessCreateError::KernelStackAllocFailed(e));
        }
    };

    // 栈分配成功后才递增 PID 计数器，避免 PID 泄漏
    *next_pid_guard += 1;
    drop(next_pid_guard);

    let process = Arc::new(Mutex::new(Process::new(pid, ppid, name.clone(), priority)));

    // 设置已分配的内核栈
    {
        let mut proc = process.lock();
        proc.kernel_stack = stack_base;
        proc.kernel_stack_top = stack_top;
    }

    let mut table = PROCESS_TABLE.lock();

    // 确保进程表有足够的空间存储新进程
    // PID 直接作为索引使用，因此表长度需要 >= pid + 1
    while table.len() <= pid {
        table.push(None);
    }

    // 将新进程存储在其 PID 对应的索引位置
    table[pid] = Some(process.clone());

    // 如果有父进程，将此进程添加到父进程的子进程列表
    if ppid > 0 {
        if let Some(Some(parent)) = table.get(ppid) {
            parent.lock().children.push(pid);
        }
    }

    println!("Created process: PID={}, Name={}, Priority={}", pid, name, priority);

    Ok(pid)
}

/// 获取当前进程ID
pub fn current_pid() -> Option<ProcessId> {
    *CURRENT_PID.lock()
}

/// 设置当前进程ID
pub fn set_current_pid(pid: Option<ProcessId>) {
    *CURRENT_PID.lock() = pid;
}

// ========== 进程凭证访问 (DAC支持) ==========

/// 进程凭证结构
#[derive(Debug, Clone)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub supplementary_groups: Vec<u32>,
}

/// 获取当前进程的凭证
///
/// 返回 None 如果没有当前进程
pub fn current_credentials() -> Option<Credentials> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(Credentials {
        uid: proc.uid,
        gid: proc.gid,
        euid: proc.euid,
        egid: proc.egid,
        supplementary_groups: proc.supplementary_groups.clone(),
    })
}

/// 获取当前进程的有效用户ID
pub fn current_euid() -> Option<u32> {
    current_credentials().map(|c| c.euid)
}

/// 获取当前进程的有效组ID
pub fn current_egid() -> Option<u32> {
    current_credentials().map(|c| c.egid)
}

/// 获取当前进程的附属组列表
///
/// 返回附属组ID的克隆列表，如果没有当前进程则返回 None
pub fn current_supplementary_groups() -> Option<Vec<u32>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.supplementary_groups.clone())
}

/// Maximum number of supplementary groups per process
///
/// This limit prevents memory exhaustion and keeps permission check performance reasonable.
/// Linux uses NGROUPS_MAX (typically 65536), but we use a smaller value for kernel simplicity.
pub const NGROUPS_MAX: usize = 256;

/// 设置当前进程的附属组列表
///
/// 会自动去重并排序，方便后续查找。
/// 最多保留 NGROUPS_MAX 个组以防止资源耗尽。
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以修改附属组列表。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `groups` - 新的附属组列表
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn set_current_supplementary_groups(groups: &[u32]) -> Option<()> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let mut proc = slot.as_ref()?.lock();

    // Security: Only root can modify supplementary groups
    if proc.euid != 0 {
        return None;
    }

    proc.supplementary_groups.clear();
    // Take only up to NGROUPS_MAX groups to prevent DoS
    let limit = groups.len().min(NGROUPS_MAX);
    proc.supplementary_groups.extend(groups[..limit].iter().copied());
    proc.supplementary_groups.sort_unstable();
    proc.supplementary_groups.dedup();
    Some(())
}

/// 向当前进程添加一个附属组
///
/// 如果该组已存在则不会重复添加。
/// 如果已达到 NGROUPS_MAX 上限，添加操作被忽略。
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以添加附属组。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `gid` - 要添加的组ID
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn add_supplementary_group(gid: u32) -> Option<()> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let mut proc = slot.as_ref()?.lock();

    // Security: Only root can modify supplementary groups
    if proc.euid != 0 {
        return None;
    }

    if !proc.supplementary_groups.contains(&gid) {
        // Enforce NGROUPS_MAX limit
        if proc.supplementary_groups.len() < NGROUPS_MAX {
            proc.supplementary_groups.push(gid);
        }
    }
    Some(())
}

/// 从当前进程移除一个附属组
///
/// 如果该组不存在则无操作
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以移除附属组。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `gid` - 要移除的组ID
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn remove_supplementary_group(gid: u32) -> Option<()> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let mut proc = slot.as_ref()?.lock();

    // Security: Only root can modify supplementary groups
    if proc.euid != 0 {
        return None;
    }

    proc.supplementary_groups.retain(|&g| g != gid);
    Some(())
}

/// 获取当前进程的umask
pub fn current_umask() -> Option<u16> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.umask)
}

/// 设置当前进程的umask，返回旧的umask
pub fn set_current_umask(new_mask: u16) -> Option<u16> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let mut proc = slot.as_ref()?.lock();
    let old = proc.umask;
    proc.umask = new_mask & 0o777; // 只保留权限位
    Some(old)
}

/// 激活指定的地址空间
///
/// 切换到进程的页表。memory_space 为 0 时使用引导时的页表（内核共享页表）。
/// 调用 Cr3::write 会刷新 TLB，确保新地址空间立即生效。
///
/// # Arguments
/// * `memory_space` - 进程的 PML4 物理地址，0 表示使用引导页表
///
/// # Safety
/// 这个函数会修改 CR3 寄存器，调用者必须确保：
/// - memory_space 指向有效的 PML4 页表
/// - 内核代码和数据在新旧页表中都有正确映射
pub fn activate_memory_space(memory_space: usize) {
    let (boot_frame, boot_flags) = *BOOT_CR3;
    let (current_frame, _) = Cr3::read();

    let (target_frame, target_flags) = if memory_space == 0 {
        // 使用引导页表（内核进程或尚未分配独立页表的进程）
        (boot_frame, boot_flags)
    } else {
        // 使用进程的独立页表
        (
            PhysFrame::containing_address(PhysAddr::new(memory_space as u64)),
            boot_flags, // 使用相同的 CR3 标志
        )
    };

    // 只有当目标页表与当前不同时才切换（避免不必要的 TLB 刷新）
    if target_frame != current_frame {
        unsafe { Cr3::write(target_frame, target_flags) };
    }
}

/// 获取进程
///
/// # Arguments
/// * `pid` - 进程 ID
///
/// # Returns
/// 如果进程存在，返回进程的 Arc 引用；否则返回 None
pub fn get_process(pid: ProcessId) -> Option<Arc<Mutex<Process>>> {
    let table = PROCESS_TABLE.lock();
    table.get(pid).and_then(|slot| slot.clone())
}

/// 注册调度器的清理回调，用于在 PCB 删除时同步调度器状态
pub fn register_cleanup_notifier(callback: SchedulerCleanupCallback) {
    *SCHEDULER_CLEANUP.lock() = Some(callback);
}

/// 注册IPC清理回调，用于在进程退出时清理其端点
pub fn register_ipc_cleanup(callback: IpcCleanupCallback) {
    *IPC_CLEANUP.lock() = Some(callback);
}

/// 通知调度器进程已被移除
fn notify_scheduler_process_removed(pid: ProcessId) {
    let callback = *SCHEDULER_CLEANUP.lock();
    if let Some(cb) = callback {
        cb(pid);
    }
}

/// 通知IPC子系统清理进程端点
fn notify_ipc_process_cleanup(pid: ProcessId) {
    let callback = *IPC_CLEANUP.lock();
    if let Some(cb) = callback {
        cb(pid);
    }
}

/// 终止进程
pub fn terminate_process(pid: ProcessId, exit_code: i32) {
    if let Some(process) = get_process(pid) {
        let children_to_reparent: Vec<ProcessId>;
        let parent_pid: ProcessId;

        {
            let mut proc = process.lock();
            proc.state = ProcessState::Zombie;
            proc.exit_code = Some(exit_code);
            parent_pid = proc.ppid;
            children_to_reparent = proc.children.clone();
            proc.children.clear();
        }

        println!("Process {} terminated with exit code {}", pid, exit_code);

        // 将孤儿进程重新分配给 init 进程 (PID 1)
        if !children_to_reparent.is_empty() {
            reparent_orphans(&children_to_reparent);
        }

        // 唤醒等待此进程的父进程
        let mut wake_parent = false;

        if parent_pid > 0 {
            if let Some(parent) = get_process(parent_pid) {
                let mut parent_proc = parent.lock();
                let waiting = parent_proc.waiting_child;
                // 父进程正在等待，且等待的是任意子进程(0)或此特定子进程
                if parent_proc.state == ProcessState::Blocked
                    && (waiting == Some(0) || waiting == Some(pid))
                {
                    parent_proc.state = ProcessState::Ready;
                    parent_proc.waiting_child = None;
                    wake_parent = true;
                }
            }
        }

        // 在释放锁后触发调度，让被唤醒的父进程有机会运行
        if wake_parent {
            crate::force_reschedule();
        }
    }
}

/// 将孤儿进程重新分配给 init 进程 (PID 1)
fn reparent_orphans(orphans: &[ProcessId]) {
    const INIT_PID: ProcessId = 1;

    // 获取 init 进程
    if let Some(init_process) = get_process(INIT_PID) {
        let mut init_proc = init_process.lock();

        for &child_pid in orphans {
            // 更新子进程的 ppid
            if let Some(child_process) = get_process(child_pid) {
                let mut child = child_process.lock();
                child.ppid = INIT_PID;
            }

            // 将子进程添加到 init 的 children 列表
            if !init_proc.children.contains(&child_pid) {
                init_proc.children.push(child_pid);
            }
        }

        if !orphans.is_empty() {
            println!("Reparented {} orphan process(es) to init (PID 1)", orphans.len());
        }
    } else {
        // init 进程不存在（早期启动阶段），静默忽略
    }
}

/// 等待子进程
pub fn wait_process(pid: ProcessId) -> Option<i32> {
    if let Some(process) = get_process(pid) {
        let proc = process.lock();
        if proc.state == ProcessState::Zombie {
            return proc.exit_code;
        }
    }
    None
}

/// 清理僵尸进程
///
/// 完全移除进程：
/// 1. 释放进程持有的内存资源（mmap 区域）
/// 2. 从 PROCESS_TABLE 中移除
/// 3. 通知调度器移除该进程
pub fn cleanup_zombie(pid: ProcessId) {
    let removed = {
        let mut table = PROCESS_TABLE.lock();
        if let Some(slot) = table.get_mut(pid) {
            if let Some(process) = slot {
                let mut proc = process.lock();
                if proc.state == ProcessState::Zombie {
                    // 释放进程持有的内存资源
                    free_process_resources(&mut proc);
                    proc.state = ProcessState::Terminated;
                    drop(proc);
                    *slot = None;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    };

    if removed {
        notify_scheduler_process_removed(pid);
        println!("Cleaned up zombie process {}", pid);
    }
}

/// 释放进程持有的内核资源
///
/// - 释放 per-process 内核栈（取消映射并归还物理帧）
/// - 清理 mmap 区域跟踪信息
/// - 如果进程拥有独立页表（memory_space != 0），直接遍历该页表：
///   * 仅处理用户空间 PML4 条目 0-255
///   * 对叶子页减少 COW 引用计数并在归零时释放物理帧
///   * 递归释放中间页表帧，最后释放 PML4 帧本身
///
/// 恒等映射 0-4GB 允许将物理地址当作虚拟地址解引用。
///
/// # 当前限制
///
/// - **HUGE_PAGE**: 用户空间应仅使用 4KB 页面。若存在 2MB/1GB 大页映射，
///   当前实现会跳过以避免 buddy allocator 损坏。
fn free_process_resources(proc: &mut Process) {
    let region_count = proc.mmap_regions.len();
    let total_size: usize = proc.mmap_regions.values().sum();

    // 释放 per-process 内核栈
    if proc.kernel_stack.as_u64() != 0 {
        free_kernel_stack(proc.pid, proc.kernel_stack);
        proc.kernel_stack = VirtAddr::new(0);
        proc.kernel_stack_top = VirtAddr::new(0);
    }

    // 清理 mmap 区域跟踪
    proc.mmap_regions.clear();

    // 关闭并清理所有文件描述符
    // 通过 clear() 触发每个 FileDescriptor 的 Drop，自动释放管道等资源
    let fd_count = proc.fd_table.len();
    proc.fd_table.clear();
    if fd_count > 0 {
        println!("  Closed {} file descriptors for process {}", fd_count, proc.pid);
    }

    // 如果进程拥有独立的页表（memory_space != 0），释放页表及其管理的物理帧
    if proc.memory_space != 0 {
        free_address_space(proc.memory_space);
        println!("  Released page table hierarchy for process {} (root=0x{:x})",
            proc.pid, proc.memory_space);
        proc.memory_space = 0;
    }

    // 通知 IPC 子系统清理进程端点（通过回调避免循环依赖）
    notify_ipc_process_cleanup(proc.pid);

    if region_count > 0 {
        println!("  Cleared {} mmap regions ({} KB) for process {}",
            region_count, total_size / 1024, proc.pid);
    }
}

/// 释放指定进程的内核栈
///
/// 取消内核栈页面的映射并归还物理帧。守护页从未映射故无需处理。
///
/// # Arguments
///
/// * `pid` - 进程 ID（用于日志）
/// * `stack_base` - 内核栈底地址
///
/// # Safety Notes
///
/// 如果当前 CPU 正在使用该栈，则跳过释放以避免自踩栈导致崩溃
pub fn free_kernel_stack(pid: ProcessId, stack_base: VirtAddr) {
    use core::arch::asm;
    use x86_64::structures::paging::Page;

    // 【关键修复】检查当前 CPU 是否正在使用该栈
    let current_rsp: u64;
    unsafe { asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, preserves_flags)); }

    let stack_bottom = stack_base.as_u64();
    let stack_top = stack_bottom + (KSTACK_PAGES as u64 * PAGE_SIZE);

    if current_rsp >= stack_bottom && current_rsp < stack_top {
        // 当前 CPU 正在使用此栈，不能释放（会导致自踩栈崩溃）
        // 这种情况不应该发生（进程应在不同栈上清理自己的栈），但防御性编程
        println!("  WARNING: Skip releasing kernel stack for PID {} (in use by current CPU, RSP=0x{:x})",
            pid, current_rsp);
        return;
    }

    let mut frame_alloc = FrameAllocator::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            for i in 0..KSTACK_PAGES {
                let addr = stack_base + (i as u64 * PAGE_SIZE);
                let page = Page::containing_address(addr);

                if let Ok(frame) = mgr.unmap_page(page) {
                    frame_alloc.deallocate_frame(frame);
                }
            }
        });
    }

    println!("  Released kernel stack for PID {} at 0x{:x}", pid, stack_base.as_u64());
}

/// 释放独立用户地址空间（PML4 物理地址）
///
/// - 仅遍历用户空间映射 (PML4[0..255])
/// - 使用 COW 引用计数安全地释放叶子页
/// - 最后释放 PML4 帧本身
///
/// 调用者必须确保该地址空间不再被任何 CPU 使用。
pub fn free_address_space(memory_space: usize) {
    if memory_space == 0 {
        return;
    }

    unsafe {
        let mut frame_alloc = FrameAllocator::new();
        let root_frame: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(memory_space as u64));
        let root_table = phys_to_virt_table(root_frame.start_address());

        // 只遍历用户空间映射 (PML4 index 0-255)，内核高半区 (256-511) 共享无需处理
        free_page_table_level(root_table, 4, &mut frame_alloc);

        // 释放 PML4 帧本身
        frame_alloc.deallocate_frame(root_frame);
    }
}

/// 递归释放页表层级
///
/// level: 4=PML4, 3=PDPT, 2=PD, 1=PT
///
/// 直接使用 memory_space 的物理地址，通过恒等映射访问页表，避免依赖当前 CR3。
///
/// # Safety
///
/// 调用者必须确保 `table` 指向有效的页表，且页表不再被任何进程使用。
unsafe fn free_page_table_level(
    table: &mut PageTable,
    level: u8,
    frame_alloc: &mut FrameAllocator,
) {
    // PML4 只处理用户空间条目 (0-255)，其他层级处理全部 512 条目
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut table[idx];
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }

        let entry_phys = entry.addr();

        // 检查是否是大页 (2MB 或 1GB)
        // 用户空间通常不使用大页，但为安全起见跳过处理
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 大页：当前 buddy allocator 仅支持 4KB 帧，跳过以避免损坏
            // 注：若用户空间需要大页支持，需扩展此逻辑
            continue;
        }

        if level == 1 {
            // PT 层级的叶子节点：释放 4KB 物理帧
            free_leaf_frame(entry_phys, frame_alloc);
        } else {
            // 中间节点：递归处理子页表
            let next_table = phys_to_virt_table(entry_phys);
            free_page_table_level(next_table, level - 1, frame_alloc);

            // 释放子页表帧本身
            let next_frame: PhysFrame<Size4KiB> =
                PhysFrame::containing_address(entry_phys);
            frame_alloc.deallocate_frame(next_frame);
        }
    }
}

/// 释放叶子页物理帧
///
/// 使用 COW 引用计数管理：减少引用计数，当计数归零时释放物理帧。
/// 对于未被 COW 跟踪的页面（refcount=0），直接释放。
fn free_leaf_frame(phys: PhysAddr, frame_alloc: &mut FrameAllocator) {
    let phys_usize = phys.as_u64() as usize;

    // 检查是否在 COW 跟踪中
    let current_count = PAGE_REF_COUNT.get(phys_usize);

    if current_count > 0 {
        // COW 页面：减少引用计数
        let remaining = PAGE_REF_COUNT.decrement(phys_usize);
        if remaining == 0 {
            // 最后一个引用，释放物理帧
            let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(phys);
            frame_alloc.deallocate_frame(frame);
        }
    } else {
        // 未被 COW 跟踪的独占页面，直接释放
        let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(phys);
        frame_alloc.deallocate_frame(frame);
    }
}

/// 将物理地址转换为页表引用（使用高半区直映）
///
/// # Safety
///
/// 调用者必须确保：
/// - 物理地址指向有效的页表
/// - 物理地址在 0-1GB 范围内（高半区直映覆盖的范围）
unsafe fn phys_to_virt_table(phys: PhysAddr) -> &'static mut PageTable {
    let virt = mm::phys_to_virt(phys);
    let ptr = virt.as_mut_ptr::<PageTable>();
    &mut *ptr
}

/// 获取进程统计信息
pub fn get_process_stats() -> ProcessStats {
    let table = PROCESS_TABLE.lock();
    let mut stats = ProcessStats::default();

    // 遍历进程表，跳过 None 值
    for slot in table.iter() {
        if let Some(process) = slot {
            stats.total += 1;
            let proc = process.lock();
            match proc.state {
                ProcessState::Ready => stats.ready += 1,
                ProcessState::Running => stats.running += 1,
                ProcessState::Stopped => stats.stopped += 1,
                ProcessState::Blocked => stats.blocked += 1,
                ProcessState::Sleeping => stats.sleeping += 1,
                ProcessState::Zombie => stats.zombie += 1,
                ProcessState::Terminated => stats.terminated += 1,
            }
        }
    }

    stats
}

/// 进程统计信息
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessStats {
    pub total: usize,
    pub ready: usize,
    pub running: usize,
    pub stopped: usize,
    pub blocked: usize,
    pub sleeping: usize,
    pub zombie: usize,
    pub terminated: usize,
}

impl ProcessStats {
    pub fn print(&self) {
        println!("=== Process Statistics ===");
        println!("Total:      {}", self.total);
        println!("Ready:      {}", self.ready);
        println!("Running:    {}", self.running);
        println!("Stopped:    {}", self.stopped);
        println!("Blocked:    {}", self.blocked);
        println!("Sleeping:   {}", self.sleeping);
        println!("Zombie:     {}", self.zombie);
        println!("Terminated: {}", self.terminated);
    }
}
