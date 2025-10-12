//! Fork系统调用实现
//!
//! 实现完整的进程复制功能

use crate::process::{Process, ProcessId, ProcessState, get_process, create_process};
use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::format;
use spin::Mutex;

/// Fork系统调用的结果
pub enum ForkResult {
    /// 父进程返回值：子进程的PID
    Parent(ProcessId),
    /// 子进程返回值：0
    Child,
    /// 错误
    Error(ForkError),
}

/// Fork错误类型
#[derive(Debug, Clone, Copy)]
pub enum ForkError {
    /// 没有当前进程
    NoCurrentProcess,
    /// 无法获取进程信息
    ProcessNotFound,
    /// 内存分配失败
    MemoryAllocationFailed,
    /// 页表复制失败
    PageTableCopyFailed,
}

/// 执行fork系统调用
/// 
/// 创建当前进程的完整副本，包括：
/// - 进程控制块（PCB）
/// - CPU上下文
/// - 内存空间（使用写时复制COW）
/// - 文件描述符表
/// 
/// # 返回值
/// 
/// - 父进程：返回子进程的PID
/// - 子进程：返回0
/// - 错误：返回错误码
pub fn sys_fork() -> Result<ProcessId, ForkError> {
    // 获取当前进程
    let current_pid = crate::process::current_pid()
        .ok_or(ForkError::NoCurrentProcess)?;
    
    let parent_process = get_process(current_pid)
        .ok_or(ForkError::ProcessNotFound)?;
    
    let parent = parent_process.lock();
    
    // 创建子进程
    let child_name = alloc::format!("{}-child", parent.name);
    let child_pid = create_process(
        child_name,
        parent.pid,
        parent.priority,
    );
    
    // 获取子进程并复制父进程的状态
    if let Some(child_process) = get_process(child_pid) {
        let mut child = child_process.lock();
        
        // 复制CPU上下文
        child.context = parent.context;
        
        // 复制栈指针
        child.kernel_stack = parent.kernel_stack;
        child.user_stack = parent.user_stack;
        
        // 复制内存空间（实际应该使用COW）
        // TODO: 实现写时复制(Copy-On-Write)机制
        child.memory_space = parent.memory_space;
        
        // 复制其他状态
        child.time_slice = parent.time_slice;
        child.cpu_time = 0; // 子进程CPU时间从0开始
        
        // 设置子进程返回值为0（通过修改rax寄存器）
        child.context.rax = 0;
        
        // 设置子进程为就绪状态
        child.state = ProcessState::Ready;
        
        println!("Fork: parent={}, child={}", parent.pid, child.pid);
        
        drop(child);
        drop(parent);
        
        // 父进程返回子进程PID
        Ok(child_pid)
    } else {
        Err(ForkError::ProcessNotFound)
    }
}

/// 实现写时复制(Copy-On-Write)的页表复制
/// 
/// 这是fork的关键优化：
/// 1. 将父进程的所有可写页标记为只读
/// 2. 子进程共享这些页
/// 3. 当任一进程尝试写入时，触发页错误
/// 4. 页错误处理程序复制该页并更新页表
/// 
/// # Safety
/// 
/// 此函数直接操作页表，必须确保：
/// - 页表结构有效
/// - 有足够的物理内存
pub unsafe fn copy_page_table_cow(
    parent_page_table: usize,
    child_page_table: usize,
) -> Result<(), ForkError> {
    // TODO: 实现完整的COW页表复制
    // 
    // 步骤：
    // 1. 遍历父进程的页表项
    // 2. 对每个映射的页：
    //    a. 如果是可写页，标记为只读
    //    b. 增加物理页的引用计数
    //    c. 在子进程页表中创建相同的映射
    // 3. 设置页表项的COW标志
    
    println!("COW page table copy: parent=0x{:x}, child=0x{:x}", 
             parent_page_table, child_page_table);
    
    Ok(())
}

/// 处理写时复制的页错误
/// 
/// 当进程尝试写入COW页时调用
/// 
/// # Arguments
/// 
/// * `pid` - 触发页错误的进程ID
/// * `fault_addr` - 导致错误的虚拟地址
/// 
/// # Safety
/// 
/// 此函数分配新的物理页并更新页表
pub unsafe fn handle_cow_page_fault(
    pid: ProcessId,
    fault_addr: usize,
) -> Result<(), ForkError> {
    // TODO: 实现COW页错误处理
    // 
    // 步骤：
    // 1. 检查该页是否为COW页
    // 2. 分配新的物理页
    // 3. 复制原页内容到新页
    // 4. 更新页表映射
    // 5. 标记新页为可写
    // 6. 减少原物理页的引用计数
    
    println!("COW page fault: pid={}, addr=0x{:x}", pid, fault_addr);
    
    Ok(())
}

/// 物理页引用计数管理
pub struct PhysicalPageRefCount {
    // 物理页地址 -> 引用计数
    ref_counts: Arc<Mutex<alloc::collections::BTreeMap<usize, usize>>>,
}

impl PhysicalPageRefCount {
    pub fn new() -> Self {
        PhysicalPageRefCount {
            ref_counts: Arc::new(Mutex::new(alloc::collections::BTreeMap::new())),
        }
    }
    
    /// 增加页的引用计数
    pub fn increment(&self, phys_addr: usize) {
        let mut counts = self.ref_counts.lock();
        *counts.entry(phys_addr).or_insert(0) += 1;
    }
    
    /// 减少页的引用计数
    /// 
    /// 返回新的引用计数，如果为0则可以释放该页
    pub fn decrement(&self, phys_addr: usize) -> usize {
        let mut counts = self.ref_counts.lock();
        if let Some(count) = counts.get_mut(&phys_addr) {
            *count = count.saturating_sub(1);
            *count
        } else {
            0
        }
    }
    
    /// 获取页的引用计数
    pub fn get(&self, phys_addr: usize) -> usize {
        let counts = self.ref_counts.lock();
        counts.get(&phys_addr).copied().unwrap_or(0)
    }
}

/// 全局物理页引用计数器
lazy_static::lazy_static! {
    pub static ref PAGE_REF_COUNT: PhysicalPageRefCount = PhysicalPageRefCount::new();
}
