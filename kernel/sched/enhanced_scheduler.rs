//! 增强型调度器
//!
//! 实现多级反馈队列调度和时钟中断集成
//!
//! 使用 Arc<Mutex<Process>> 共享引用与 PROCESS_TABLE 同步状态
//!
//! 就绪队列使用优先级分桶：BTreeMap<Priority, BTreeMap<Pid, PCB>>
//! - 外层按优先级排序（数值越小优先级越高）
//! - 内层按 PID 排序实现同优先级的 FIFO

use alloc::{collections::BTreeMap, sync::Arc};
use kernel_core::process::{self, Process, ProcessId, ProcessState, Priority};
use spin::Mutex;
use lazy_static::lazy_static;

// 类型别名以保持兼容性
pub type Pid = ProcessId;
pub type ProcessControlBlock = Arc<Mutex<Process>>;

/// 优先级分桶的就绪队列类型
///
/// 结构: Priority -> (Pid -> ProcessControlBlock)
/// - 按优先级从低到高排序（优先级数值越小越优先）
/// - 同优先级内按 PID 先入先出
type ReadyQueues = BTreeMap<Priority, BTreeMap<Pid, ProcessControlBlock>>;

/// 全局就绪队列 - 按优先级分桶维护就绪进程
lazy_static! {
    pub static ref READY_QUEUE: Mutex<ReadyQueues> = Mutex::new(BTreeMap::new());
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
    // ========================================================================
    // 内部辅助函数
    // ========================================================================

    /// 在优先级分桶中查找指定 PID 的进程
    fn find_pcb(queue: &ReadyQueues, pid: Pid) -> Option<ProcessControlBlock> {
        for bucket in queue.values() {
            if let Some(pcb) = bucket.get(&pid) {
                return Some(pcb.clone());
            }
        }
        None
    }

    /// 选择优先级最高的就绪进程（内部实现，需要队列锁）
    fn select_next_locked(queue: &ReadyQueues) -> Option<Pid> {
        // BTreeMap 按 key 升序排列，所以优先级数值最小（最高优先级）的在前面
        for (_priority, bucket) in queue.iter() {
            for (&pid, pcb) in bucket.iter() {
                if pcb.lock().state == ProcessState::Ready {
                    return Some(pid);
                }
            }
        }
        None
    }

    // ========================================================================
    // 公开 API
    // ========================================================================

    /// 添加进程到就绪队列
    ///
    /// 将进程插入到其动态优先级对应的桶中
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn add_process(pcb: ProcessControlBlock) {
        let (pid, priority) = {
            let mut proc = pcb.lock();
            proc.state = ProcessState::Ready;
            (proc.pid, proc.dynamic_priority)
        };
        {
            let mut queue = READY_QUEUE.lock();
            // 先从所有桶中移除（防止重复）
            for bucket in queue.values_mut() {
                bucket.remove(&pid);
            }
            // 插入到正确的优先级桶
            queue.entry(priority).or_default().insert(pid, pcb);
        }

        let mut stats = SCHEDULER_STATS.lock();
        stats.processes_created += 1;
    }

    /// 移除进程
    ///
    /// 从所有优先级桶中移除指定 PID
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn remove_process(pid: Pid) {
        {
            let mut queue = READY_QUEUE.lock();
            for bucket in queue.values_mut() {
                bucket.remove(&pid);
            }
            // 清理空桶
            queue.retain(|_, bucket| !bucket.is_empty());
        }

        let mut stats = SCHEDULER_STATS.lock();
        stats.processes_terminated += 1;
    }

    /// 选择下一个要运行的进程
    ///
    /// 按优先级从高到低（数值从小到大）遍历，返回第一个就绪进程
    pub fn select_next() -> Option<Pid> {
        let queue = READY_QUEUE.lock();
        Self::select_next_locked(&queue)
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
            current_pid.and_then(|pid| Self::find_pcb(&queue, pid))
        } {
            let mut proc = pcb.lock();

            // 减少时间片
            if proc.time_slice > 0 {
                proc.time_slice -= 1;
            }

            // 时间片已用完，标记为就绪态并降低优先级
            if proc.time_slice == 0 {
                proc.state = ProcessState::Ready;
                proc.decrease_dynamic_priority(); // 惩罚 CPU 密集型进程
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

        // 在单次锁定中获取所需的所有引用
        let (next_pid, current_proc, next_proc) = {
            let queue = READY_QUEUE.lock();
            let next = Self::select_next_locked(&queue);
            let current_proc = current_pid.and_then(|pid| Self::find_pcb(&queue, pid));
            let next_proc = next.and_then(|pid| Self::find_pcb(&queue, pid));
            (next, current_proc, next_proc)
        };

        // 选择下一个要运行的进程
        if let Some(next_pid) = next_pid {
            if Some(next_pid) != current_pid {
                // 保存当前进程状态
                if let Some(proc) = current_proc {
                    let mut pcb = proc.lock();
                    if pcb.state == ProcessState::Running {
                        pcb.state = ProcessState::Ready;
                    }
                }

                // 设置新进程为运行态并获取其地址空间
                let next_memory_space = if let Some(proc) = next_proc {
                    let mut pcb = proc.lock();
                    pcb.state = ProcessState::Running;
                    pcb.reset_time_slice();
                    pcb.memory_space
                } else {
                    0 // 默认使用引导页表
                };

                // 切换到目标进程的页表（0 表示继续使用引导页表）
                process::activate_memory_space(next_memory_space);

                // 更新当前进程
                Self::set_current(Some(next_pid));

                let mut stats = SCHEDULER_STATS.lock();
                stats.total_switches += 1;

                // 注意：在中断上下文中避免过多输出
                // println!("Scheduled: {} -> {}", current_pid.unwrap_or(0), next_pid);
            }
        }
    }

    /// 主动让出CPU
    pub fn yield_cpu() {
        if let Some(pid) = Self::get_current() {
            if let Some(pcb) = {
                let queue = READY_QUEUE.lock();
                Self::find_pcb(&queue, pid)
            } {
                let mut proc = pcb.lock();
                proc.state = ProcessState::Ready;
                proc.update_dynamic_priority(); // 奖励主动让出的进程
            }
        }

        Self::schedule();
    }

    /// 获取进程数量
    pub fn process_count() -> usize {
        READY_QUEUE
            .lock()
            .values()
            .map(|bucket| bucket.len())
            .sum()
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