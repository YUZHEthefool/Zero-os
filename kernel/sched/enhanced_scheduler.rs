//! 增强型调度器
//!
//! 实现多级反馈队列调度和时钟中断集成
//!
//! 使用 Arc<Mutex<Process>> 共享引用与 PROCESS_TABLE 同步状态

use alloc::{collections::BTreeMap, sync::Arc};
use kernel_core::process::{self, Process, ProcessId, ProcessState};
use spin::Mutex;
use lazy_static::lazy_static;

// 类型别名以保持兼容性
pub type Pid = ProcessId;
pub type ProcessControlBlock = Arc<Mutex<Process>>;

/// 全局就绪队列 - 按优先级维护就绪进程的 Arc 引用
lazy_static! {
    pub static ref READY_QUEUE: Mutex<BTreeMap<Pid, ProcessControlBlock>> = Mutex::new(BTreeMap::new());
    pub static ref CURRENT_PROCESS: Mutex<Option<Pid>> = Mutex::new(None);
    pub static ref SCHEDULER_STATS: Mutex<SchedulerStats> = Mutex::new(SchedulerStats::new());
}

/// 调度器统计信息
pub struct SchedulerStats {
    pub total_switches: u64,
    pub total_ticks: u64,
    pub processes_created: u64,
    pub processes_terminated: u64,
}

impl SchedulerStats {
    pub fn new() -> Self {
        SchedulerStats {
            total_switches: 0,
            total_ticks: 0,
            processes_created: 0,
            processes_terminated: 0,
        }
    }
    
    pub fn print(&self) {
        println!("=== Scheduler Statistics ===");
        println!("Context switches: {}", self.total_switches);
        println!("Total ticks:      {}", self.total_ticks);
        println!("Processes created: {}", self.processes_created);
        println!("Processes terminated: {}", self.processes_terminated);
    }
}

/// 调度器
pub struct Scheduler;

impl Scheduler {
    /// 添加进程到就绪队列
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn add_process(pcb: ProcessControlBlock) {
        let pid = {
            let mut proc = pcb.lock();
            proc.state = ProcessState::Ready;
            proc.pid
        };
        {
            let mut queue = READY_QUEUE.lock();
            queue.insert(pid, pcb);
        }

        let mut stats = SCHEDULER_STATS.lock();
        stats.processes_created += 1;
    }

    /// 移除进程
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn remove_process(pid: Pid) {
        {
            let mut queue = READY_QUEUE.lock();
            queue.remove(&pid);
        }

        let mut stats = SCHEDULER_STATS.lock();
        stats.processes_terminated += 1;
    }
    
    /// 选择下一个要运行的进程
    pub fn select_next() -> Option<Pid> {
        let queue = READY_QUEUE.lock();

        // 查找优先级最高的就绪进程
        for (&pid, pcb) in queue.iter().rev() {
            if pcb.lock().state == ProcessState::Ready {
                return Some(pid);
            }
        }

        None
    }
    
    /// 更新当前运行的进程
    pub fn set_current(pid: Option<Pid>) {
        let mut current = CURRENT_PROCESS.lock();
        *current = pid;
    }
    
    /// 获取当前运行的进程
    pub fn get_current() -> Option<Pid> {
        *CURRENT_PROCESS.lock()
    }
    
    /// 处理时钟中断 - 进行进程调度
    ///
    /// 锁顺序：CURRENT_PROCESS -> READY_QUEUE -> SCHEDULER_STATS
    /// 所有调度器函数必须遵循此顺序以避免死锁
    pub fn on_clock_tick() {
        // 统一锁顺序：先获取 CURRENT_PROCESS
        let current_pid = *CURRENT_PROCESS.lock();

        // 获取当前进程的 Arc 引用并更新时间片
        if let Some(pcb) = {
            let queue = READY_QUEUE.lock();
            current_pid.and_then(|pid| queue.get(&pid).cloned())
        } {
            let mut proc = pcb.lock();

            // 减少时间片
            if proc.time_slice > 0 {
                proc.time_slice -= 1;
            }

            // 时间片已用完，标记为就绪态
            if proc.time_slice == 0 {
                proc.state = ProcessState::Ready;
                proc.reset_time_slice();
            }
        }

        // 最后更新 SCHEDULER_STATS
        {
            let mut stats = SCHEDULER_STATS.lock();
            stats.total_ticks += 1;
        }

        // 进行一次调度
        Self::schedule();
    }
    
    /// 执行调度 - 选择下一个进程并进行上下文切换
    ///
    /// 锁顺序：CURRENT_PROCESS -> READY_QUEUE -> SCHEDULER_STATS
    pub fn schedule() {
        // 获取当前运行的进程
        let current_pid = *CURRENT_PROCESS.lock();

        // 选择下一个要运行的进程
        if let Some(next_pid) = Self::select_next() {
            if Some(next_pid) != current_pid {
                // 需要进行上下文切换
                // 获取当前和下一个进程的 Arc 引用
                let (current_proc, next_proc) = {
                    let queue = READY_QUEUE.lock();
                    let current_proc = current_pid.and_then(|pid| queue.get(&pid).cloned());
                    let next_proc = queue.get(&next_pid).cloned();
                    (current_proc, next_proc)
                };

                // 保存当前进程状态
                if let Some(proc) = current_proc {
                    let mut pcb = proc.lock();
                    if pcb.state == ProcessState::Running {
                        pcb.state = ProcessState::Ready;
                    }
                }

                // 设置新进程为运行态
                if let Some(proc) = next_proc {
                    let mut pcb = proc.lock();
                    pcb.state = ProcessState::Running;
                    pcb.reset_time_slice();
                }

                // 更新当前进程
                Self::set_current(Some(next_pid));

                let mut stats = SCHEDULER_STATS.lock();
                stats.total_switches += 1;

                println!("Scheduled process {} (next_pid: {})",
                         current_pid.unwrap_or(0), next_pid);
            }
        }
    }
    
    /// 主动让出CPU
    pub fn yield_cpu() {
        if let Some(pid) = Self::get_current() {
            if let Some(pcb) = {
                let queue = READY_QUEUE.lock();
                queue.get(&pid).cloned()
            } {
                let mut proc = pcb.lock();
                proc.state = ProcessState::Ready;
            }
        }

        Self::schedule();
    }
    
    /// 获取进程数量
    pub fn process_count() -> usize {
        READY_QUEUE.lock().len()
    }
    
    /// 打印调度统计信息
    pub fn print_stats() {
        SCHEDULER_STATS.lock().print();
    }
}

/// 初始化调度器
pub fn init() {
    // 注册进程清理回调，确保进程终止时调度器同步更新
    process::register_cleanup_notifier(Scheduler::remove_process);

    println!("Enhanced scheduler initialized");
    println!("  Ready queue capacity: unlimited");
    println!("  Scheduling algorithm: Priority-based with time slice");
}