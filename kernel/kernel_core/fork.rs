//! Fork系统调用实现
//!
//! 实现完整的进程复制功能，包含写时复制(COW)机制

use crate::process::{ProcessId, ProcessState, current_pid, get_process, create_process};
use alloc::sync::Arc;
use mm::memory::FrameAllocator;
use spin::Mutex;
use x86_64::{
    PhysAddr, VirtAddr,
    instructions::tlb,
    registers::control::Cr3,
    structures::paging::{page_table::PageTableEntry, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB},
};

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
    let current = current_pid().ok_or(ForkError::NoCurrentProcess)?;
    let parent_process = get_process(current).ok_or(ForkError::ProcessNotFound)?;
    let mut parent = parent_process.lock();

    // 获取父进程页表根地址
    let parent_root = if parent.memory_space == 0 {
        let (cr3, _) = Cr3::read();
        cr3.start_address().as_u64() as usize
    } else {
        parent.memory_space
    };

    // 创建子进程
    let child_name = alloc::format!("{}-child", parent.name);
    let child_pid = create_process(child_name, parent.pid, parent.priority);

    if let Some(child_process) = get_process(child_pid) {
        let mut child = child_process.lock();

        // 分配子进程页表根
        let mut frame_alloc = FrameAllocator::new();
        let child_root_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        unsafe { zero_table(child_root_frame); }

        // 复制页表并设置 COW
        unsafe {
            copy_page_table_cow(
                parent_root,
                child_root_frame.start_address().as_u64() as usize,
            )?;
        }

        child.memory_space = child_root_frame.start_address().as_u64() as usize;

        // 复制 CPU 上下文
        child.context = parent.context;
        child.kernel_stack = parent.kernel_stack;
        child.user_stack = parent.user_stack;
        child.time_slice = parent.time_slice;
        child.cpu_time = 0;
        child.context.rax = 0; // 子进程返回值 0
        child.state = ProcessState::Ready;

        println!("Fork: parent={}, child={}, COW enabled", parent.pid, child.pid);
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
    let mut frame_alloc = FrameAllocator::new();
    let parent_root: PhysFrame<Size4KiB> = PhysFrame::containing_address(PhysAddr::new(parent_page_table as u64));
    let child_root: PhysFrame<Size4KiB> = PhysFrame::containing_address(PhysAddr::new(child_page_table as u64));

    let parent_pml4 = phys_to_virt_table(parent_root.start_address());
    let child_pml4 = phys_to_virt_table(child_root.start_address());

    // 复制内核高半区映射（索引 256-511）
    for i in 256..512 {
        child_pml4[i] = parent_pml4[i].clone();
    }

    // 克隆用户低半区 (索引 0-255) 并设置 COW
    clone_level(parent_pml4, child_pml4, &mut frame_alloc, 4)?;

    // 父进程页表被改成只读+BIT_9，需要刷新本地 TLB 才能生效
    tlb::flush_all();

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
    use mm::page_table::with_current_manager;

    let virt = VirtAddr::new(fault_addr as u64);
    let page = Page::containing_address(virt);

    // 查找页表项
    let pte = find_pte(virt).ok_or(ForkError::PageTableCopyFailed)?;
    let flags = pte.flags();

    // 检查是否为 COW 页
    if !flags.contains(cow_flag()) {
        return Err(ForkError::PageTableCopyFailed);
    }

    // 使用基于当前 CR3 的页表管理器，确保操作正确的地址空间
    let mut frame_alloc = FrameAllocator::new();

    with_current_manager(VirtAddr::new(0), |manager| -> Result<(), ForkError> {
        // 获取原物理地址
        let old_phys = manager
            .translate_addr(virt)
            .ok_or(ForkError::PageTableCopyFailed)?;
        let old_frame = PhysFrame::containing_address(old_phys);

        // 分配新物理页
        let new_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;

        // 复制页内容
        core::ptr::copy_nonoverlapping(
            old_frame.start_address().as_u64() as *const u8,
            new_frame.start_address().as_u64() as *mut u8,
            4096,
        );

        // 取消原映射
        let _ = manager.unmap_page(page);

        // 设置新标志：移除 COW，添加 WRITABLE
        let mut new_flags = flags;
        new_flags.remove(cow_flag());
        new_flags.insert(PageTableFlags::WRITABLE);

        // 建立新映射
        manager
            .map_page(page, new_frame, new_flags, &mut frame_alloc)
            .map_err(|_| ForkError::PageTableCopyFailed)?;

        // 减少原页引用计数
        let remaining = PAGE_REF_COUNT.decrement(old_phys.as_u64() as usize);
        if remaining == 0 {
            frame_alloc.deallocate_frame(old_frame);
        }

        println!("COW page fault: pid={}, addr=0x{:x} resolved", pid, fault_addr);
        Ok(())
    })
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

// ============================================================================
// COW 辅助函数
// ============================================================================

/// COW 标志位（使用 BIT_9，这是 x86_64 页表中可供软件使用的位）
#[inline]
const fn cow_flag() -> PageTableFlags {
    PageTableFlags::BIT_9
}

/// 递归克隆页表层级
///
/// level: 4=PML4, 3=PDPT, 2=PD, 1=PT
fn clone_level(
    parent: &mut PageTable,
    child: &mut PageTable,
    frame_alloc: &mut FrameAllocator,
    level: u8,
) -> Result<(), ForkError> {
    // 只处理用户空间（PML4 的索引 0-255）
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut parent[idx];
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }

        if level == 1 || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 叶子节点：复制映射并设置 COW
            clone_leaf(entry, &mut child[idx])?;
        } else {
            // 中间节点：分配新页表并递归
            let frame = frame_alloc
                .allocate_frame()
                .ok_or(ForkError::MemoryAllocationFailed)?;
            unsafe { zero_table(frame); }

            child[idx].set_addr(frame.start_address(), entry.flags());

            let parent_next = unsafe { phys_to_virt_table(entry.addr()) };
            let child_next = unsafe { phys_to_virt_table(frame.start_address()) };
            clone_level(parent_next, child_next, frame_alloc, level - 1)?;
        }
    }
    Ok(())
}

/// 克隆叶子页表项并设置 COW
fn clone_leaf(
    parent_entry: &mut PageTableEntry,
    child_entry: &mut PageTableEntry,
) -> Result<(), ForkError> {
    let addr = parent_entry.addr();
    let mut flags = parent_entry.flags();
    let addr_usize = addr.as_u64() as usize;

    // 处理已经是 COW 的页面（来自之前的 fork）
    if flags.contains(cow_flag()) {
        // 已经是 COW，给新子进程增加一份引用
        PAGE_REF_COUNT.increment(addr_usize);
    } else if flags.contains(PageTableFlags::WRITABLE) {
        // 如果页面可写，则标记为 COW
        flags.remove(PageTableFlags::WRITABLE);
        flags.insert(cow_flag());

        // 更新父进程页表项
        parent_entry.set_addr(addr, flags);

        // 增加引用计数（父进程和子进程各一次）
        PAGE_REF_COUNT.increment(addr_usize);
        PAGE_REF_COUNT.increment(addr_usize);
    }

    // 子进程使用相同的映射
    child_entry.set_addr(addr, flags);
    Ok(())
}

/// 查找虚拟地址对应的页表项
fn find_pte(addr: VirtAddr) -> Option<&'static mut PageTableEntry> {
    let (root, _) = Cr3::read();
    let mut table = unsafe { phys_to_virt_table(root.start_address()) };

    let idxs: [usize; 4] = [
        usize::from(addr.p4_index()),
        usize::from(addr.p3_index()),
        usize::from(addr.p2_index()),
        usize::from(addr.p1_index()),
    ];

    for (depth, idx) in idxs.iter().copied().enumerate() {
        let entry = unsafe { &mut *(&mut table[idx] as *mut PageTableEntry) };
        if entry.is_unused() {
            return None;
        }
        if depth == 3 {
            return Some(entry);
        }
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return None; // 大页不支持 COW
        }
        table = unsafe { phys_to_virt_table(entry.addr()) };
    }
    None
}

/// 将物理地址转换为页表引用
///
/// # Safety
///
/// 调用者必须确保物理地址指向有效的页表
unsafe fn phys_to_virt_table(phys: PhysAddr) -> &'static mut PageTable {
    // 在恒等映射环境中，物理地址 == 虚拟地址
    let ptr = phys.as_u64() as *mut PageTable;
    &mut *ptr
}

/// 将物理帧清零
unsafe fn zero_table(frame: PhysFrame) {
    core::ptr::write_bytes(frame.start_address().as_u64() as *mut u8, 0, 4096);
}
