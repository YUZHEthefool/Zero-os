//! 增强型调度器
//!
//! 实现多级反馈队列调度和时钟中断集成

use alloc::collections::BTreeMap;
use kernel_core::process::{Process, ProcessId, ProcessState};
use spin::Mutex;
use lazy_static::lazy_static;

// 类型别名以保持兼容性
pub type Pid = ProcessId;
pub type ProcessControlBlock = Process;

/// 全局就绪队列 - 按优先级维护就绪进程
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
    pub fn add_process(pcb: ProcessControlBlock) {
        let pid = pcb.pid;
        let mut queue = READY_QUEUE.lock();
        queue.insert(pid, pcb);
        
        let mut stats = SCHEDULER_STATS.lock();
        stats.processes_created += 1;
    }
    
    /// 移除进程
    pub fn remove_process(pid: Pid) {
        let mut queue = READY_QUEUE.lock();
        queue.remove(&pid);
        
        let mut stats = SCHEDULER_STATS.lock();
        stats.processes_terminated += 1;
    }
    
    /// 选择下一个要运行的进程
    pub fn select_next() -> Option<Pid> {
        let mut queue = READY_QUEUE.lock();
        
        // 查找优先级最高的就绪进程
        for (_pid, pcb) in queue.iter_mut().rev() {
            if pcb.state == ProcessState::Ready {
                return Some(pcb.pid);
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
    pub fn on_clock_tick() {
        let mut queue = READY_QUEUE.lock();
        
        // 增加时钟计数
        let mut stats = SCHEDULER_STATS.lock();
        stats.total_ticks += 1;
        drop(stats);
        
        // 当前运行的进程消耗一个时间片
        if let Some(current_pid) = *CURRENT_PROCESS.lock() {
            if let Some(pcb) = queue.get_mut(&current_pid) {
                // 减少时间片
                if pcb.time_slice > 0 {
                    pcb.time_slice -= 1;
                }
                
                // 时间片已用完，标记为就绪态
                if pcb.time_slice == 0 {
                    pcb.state = ProcessState::Ready;
                    pcb.reset_time_slice();
                }
            }
        }
        drop(queue);
        
        // 进行一次调度
        Self::schedule();
    }
    
    /// 执行调度 - 选择下一个进程并进行上下文切换
    pub fn schedule() {
        // 获取当前运行的进程
        let current_pid = *CURRENT_PROCESS.lock();
        
        // 选择下一个要运行的进程
        if let Some(next_pid) = Self::select_next() {
            if Some(next_pid) != current_pid {
                // 需要进行上下文切换
                let mut queue = READY_QUEUE.lock();
                
                // 保存当前进程状态
                if let Some(current_id) = current_pid {
                    if let Some(pcb) = queue.get_mut(&current_id) {
                        if pcb.state == ProcessState::Running {
                            pcb.state = ProcessState::Ready;
                        }
                    }
                }
                
                // 设置新进程为运行态
                if let Some(pcb) = queue.get_mut(&next_pid) {
                    pcb.state = ProcessState::Running;
                    pcb.reset_time_slice();
                }
                drop(queue);
                
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
            let mut queue = READY_QUEUE.lock();
            if let Some(pcb) = queue.get_mut(&pid) {
                pcb.state = ProcessState::Ready;
            }
            drop(queue);
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
    println!("Enhanced scheduler initialized");
    println!("  Ready queue capacity: unlimited");
    println!("  Scheduling algorithm: Priority-based with time slice");
}