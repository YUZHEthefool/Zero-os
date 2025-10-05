use alloc::{vec::Vec, string::String, sync::Arc};
use spin::Mutex;
use x86_64::VirtAddr;

/// 进程ID类型
pub type ProcessId = usize;

/// 进程优先级（0-139，数值越小优先级越高）
pub type Priority = u8;

/// 进程状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// 就绪状态，等待被调度
    Ready,
    /// 运行状态
    Running,
    /// 阻塞状态（等待I/O或其他事件）
    Blocked,
    /// 睡眠状态
    Sleeping,
    /// 僵尸状态（已终止但未被父进程回收）
    Zombie,
    /// 已终止
    Terminated,
}

/// CPU上下文（用于进程切换）
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
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
    
    // 指令指针和标志
    pub rip: u64,
    pub rflags: u64,
    
    // 段寄存器
    pub cs: u64,
    pub ss: u64,
}

/// 进程控制块（PCB）
#[derive(Debug, Clone)]
pub struct Process {
    /// 进程ID
    pub pid: ProcessId,
    
    /// 父进程ID
    pub ppid: ProcessId,
    
    /// 进程名称
    pub name: String,
    
    /// 进程状态
    pub state: ProcessState,
    
    /// 进程优先级（静态优先级）
    pub priority: Priority,
    
    /// 动态优先级（用于调度）
    pub dynamic_priority: Priority,
    
    /// 时间片（剩余时间片，单位：毫秒）
    pub time_slice: u32,
    
    /// CPU上下文
    pub context: Context,
    
    /// 内核栈指针
    pub kernel_stack: VirtAddr,
    
    /// 用户栈指针（如果是用户进程）
    pub user_stack: Option<VirtAddr>,
    
    /// 内存空间（页表基址）
    pub memory_space: usize,
    
    /// 退出码
    pub exit_code: Option<i32>,
    
    /// 子进程列表
    pub children: Vec<ProcessId>,
    
    /// CPU时间统计（毫秒）
    pub cpu_time: u64,
    
    /// 创建时间戳
    pub created_at: u64,
}

impl Process {
    /// 创建新进程
    pub fn new(pid: ProcessId, ppid: ProcessId, name: String, priority: Priority) -> Self {
        Process {
            pid,
            ppid,
            name,
            state: ProcessState::Ready,
            priority,
            dynamic_priority: priority,
            time_slice: calculate_time_slice(priority),
            context: Context::default(),
            kernel_stack: VirtAddr::new(0),
            user_stack: None,
            memory_space: 0,
            exit_code: None,
            children: Vec::new(),
            cpu_time: 0,
            created_at: 0, // TODO: 实现时间戳
        }
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
lazy_static::lazy_static! {
    pub static ref PROCESS_TABLE: Mutex<Vec<Arc<Mutex<Process>>>> = Mutex::new(Vec::new());
}

/// 当前运行的进程ID
static CURRENT_PID: Mutex<Option<ProcessId>> = Mutex::new(None);

/// 下一个可用的PID
static NEXT_PID: Mutex<ProcessId> = Mutex::new(1);

/// 创建新进程
pub fn create_process(name: String, ppid: ProcessId, priority: Priority) -> ProcessId {
    let mut next_pid = NEXT_PID.lock();
    let pid = *next_pid;
    *next_pid += 1;
    drop(next_pid);
    
    let process = Arc::new(Mutex::new(Process::new(pid, ppid, name, priority)));
    
    let mut table = PROCESS_TABLE.lock();
    
    // 如果有父进程，将此进程添加到父进程的子进程列表
    if ppid > 0 && ppid < table.len() {
        if let Some(parent) = table.get(ppid) {
            parent.lock().children.push(pid);
        }
    }
    
    table.push(process);
    
    println!("Created process: PID={}, Name={}, Priority={}", pid, 
             table[pid].lock().name, priority);
    
    pid
}

/// 获取当前进程ID
pub fn current_pid() -> Option<ProcessId> {
    *CURRENT_PID.lock()
}

/// 设置当前进程ID
pub fn set_current_pid(pid: Option<ProcessId>) {
    *CURRENT_PID.lock() = pid;
}

/// 获取进程
pub fn get_process(pid: ProcessId) -> Option<Arc<Mutex<Process>>> {
    let table = PROCESS_TABLE.lock();
    table.get(pid).cloned()
}

/// 终止进程
pub fn terminate_process(pid: ProcessId, exit_code: i32) {
    if let Some(process) = get_process(pid) {
        let mut proc = process.lock();
        proc.state = ProcessState::Zombie;
        proc.exit_code = Some(exit_code);
        
        println!("Process {} terminated with exit code {}", pid, exit_code);
        
        // TODO: 唤醒等待此进程的父进程
        // TODO: 将孤儿进程重新分配给init进程
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
pub fn cleanup_zombie(pid: ProcessId) {
    if let Some(process) = get_process(pid) {
        let mut proc = process.lock();
        if proc.state == ProcessState::Zombie {
            proc.state = ProcessState::Terminated;
            println!("Cleaned up zombie process {}", pid);
        }
    }
}

/// 获取进程统计信息
pub fn get_process_stats() -> ProcessStats {
    let table = PROCESS_TABLE.lock();
    let mut stats = ProcessStats::default();
    
    stats.total = table.len();
    
    for process in table.iter() {
        let proc = process.lock();
        match proc.state {
            ProcessState::Ready => stats.ready += 1,
            ProcessState::Running => stats.running += 1,
            ProcessState::Blocked => stats.blocked += 1,
            ProcessState::Sleeping => stats.sleeping += 1,
            ProcessState::Zombie => stats.zombie += 1,
            ProcessState::Terminated => stats.terminated += 1,
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
        println!("Blocked:    {}", self.blocked);
        println!("Sleeping:   {}", self.sleeping);
        println!("Zombie:     {}", self.zombie);
        println!("Terminated: {}", self.terminated);
    }
}
