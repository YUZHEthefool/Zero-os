//! Fork系统调用实现
//!
//! 实现完整的进程复制功能，包含写时复制(COW)机制

use crate::process::{ProcessId, ProcessState, current_pid, get_process, create_process, free_address_space, free_kernel_stack};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use mm::memory::FrameAllocator;
use spin::RwLock;
use x86_64::{
    PhysAddr, VirtAddr,
    instructions::{interrupts, tlb},
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

    // 捕获父进程信息后释放锁，避免 create_process 再次获取锁导致潜在问题
    let (parent_root, parent_pid, parent_prio, child_name) = {
        let parent = parent_process.lock();
        let root = if parent.memory_space == 0 {
            let (cr3, _) = Cr3::read();
            cr3.start_address().as_u64() as usize
        } else {
            parent.memory_space
        };
        (root, parent.pid, parent.priority, alloc::format!("{}-child", parent.name))
    };

    // 创建子进程（此时未持有父进程锁，避免死锁）
    let child_pid = create_process(child_name, parent_pid, parent_prio);

    // 重新获取父进程锁执行真正的 fork
    let mut parent = parent_process.lock();
    let result = fork_inner(&mut parent, child_pid, parent_root);

    if result.is_err() {
        // 从父进程子列表移除失败的占位 PID，防止悬挂
        parent.children.retain(|&pid| pid != child_pid);
        drop(parent);
        cleanup_partial_child(child_pid);
    }

    result
}

/// Fork 的内部实现，便于错误处理和回滚
fn fork_inner(
    parent: &mut crate::process::Process,
    child_pid: ProcessId,
    parent_root: usize,
) -> Result<ProcessId, ForkError> {
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
            if let Err(e) = copy_page_table_cow(
                parent_root,
                child_root_frame.start_address().as_u64() as usize,
            ) {
                // 页表复制失败，释放已分配的页表树
                // 注意：copy_page_table_cow 可能已经分配了部分子页表
                free_address_space(child_root_frame.start_address().as_u64() as usize);
                return Err(e);
            }
        }

        child.memory_space = child_root_frame.start_address().as_u64() as usize;

        // 复制 CPU 上下文（RAX 在下方置 0）
        child.context = parent.context;
        child.user_stack = parent.user_stack;

        // 子进程使用自己的内核栈（由 create_process -> allocate_kernel_stack 分配）
        // 复制父进程内核栈内容以保持返回路径一致
        let parent_top = parent.kernel_stack_top.as_u64();
        let parent_rsp = parent.context.rsp;
        let child_top = child.kernel_stack_top.as_u64();

        // 计算父进程已使用的栈空间
        let used = parent_top.saturating_sub(parent_rsp);
        let parent_stack_size = parent_top.saturating_sub(parent.kernel_stack.as_u64());

        if child_top != 0 && used > 0 && used <= parent_stack_size {
            // 子进程栈顶减去相同使用量 = 子进程 RSP
            let child_rsp = child_top - used;

            // 复制父栈内容到子栈
            unsafe {
                core::ptr::copy_nonoverlapping(
                    parent_rsp as *const u8,
                    child_rsp as *mut u8,
                    used as usize,
                );
            }

            child.context.rsp = child_rsp;

            // 调整 RBP（如果它指向父栈范围内）
            if parent.context.rbp >= parent_rsp && parent.context.rbp <= parent_top {
                // RBP 相对偏移保持不变
                let rbp_offset = parent.context.rbp - parent_rsp;
                child.context.rbp = child_rsp + rbp_offset;
            } else {
                // RBP 不在栈范围内，直接使用子栈顶
                child.context.rbp = child_rsp;
            }
        } else if child_top != 0 {
            // 无法复制栈，使用子栈顶作为起点
            child.context.rsp = child_top;
            child.context.rbp = child_top;
        }
        // 如果 child_top == 0，保持父进程的 rsp/rbp（回退到共享栈）

        // 克隆文件描述符表（每个 fd 调用 clone_box）
        for (&fd, desc) in parent.fd_table.iter() {
            child.fd_table.insert(fd, desc.clone_box());
        }

        child.time_slice = parent.time_slice;
        child.cpu_time = 0;

        // 继承父进程的凭证 (DAC支持)
        child.uid = parent.uid;
        child.gid = parent.gid;
        child.euid = parent.euid;
        child.egid = parent.egid;
        child.supplementary_groups = parent.supplementary_groups.clone();
        child.umask = parent.umask;

        child.context.rax = 0; // 子进程返回值 0
        child.state = ProcessState::Ready;

        println!("Fork: parent={}, child={}, COW enabled", parent.pid, child.pid);
        Ok(child_pid)
    } else {
        Err(ForkError::ProcessNotFound)
    }
}

/// 清理失败的 fork 创建的部分子进程
fn cleanup_partial_child(child_pid: ProcessId) {
    use crate::process::PROCESS_TABLE;

    // 预先收集需要释放的资源，避免长时间持有 PROCESS_TABLE 锁
    let (kstack, addr_space) = {
        let mut table = PROCESS_TABLE.lock();
        if let Some(slot) = table.get_mut(child_pid) {
            if let Some(process) = slot.take() {
                let proc = process.lock();
                (
                    if proc.kernel_stack.as_u64() != 0 {
                        Some(proc.kernel_stack)
                    } else {
                        None
                    },
                    proc.memory_space,
                )
            } else {
                (None, 0)
            }
        } else {
            (None, 0)
        }
    };

    // 在 PROCESS_TABLE 锁外释放资源
    if let Some(stack_base) = kstack {
        free_kernel_stack(child_pid, stack_base);
    }
    if addr_space != 0 {
        free_address_space(addr_space);
    }

    println!("Fork failed: cleaned up partial child PID {}", child_pid);
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

        // 复制页内容（使用高半区直映访问物理内存）
        let old_virt = mm::phys_to_virt(old_frame.start_address());
        let new_virt = mm::phys_to_virt(new_frame.start_address());
        core::ptr::copy_nonoverlapping(
            old_virt.as_ptr::<u8>(),
            new_virt.as_mut_ptr::<u8>(),
            4096,
        );

        // H-35 fix: Check unmap result - if it fails, deallocate the new frame and return error
        if manager.unmap_page(page).is_err() {
            frame_alloc.deallocate_frame(new_frame);
            return Err(ForkError::PageTableCopyFailed);
        }

        // 设置新标志：移除 COW，添加 WRITABLE
        let mut new_flags = flags;
        new_flags.remove(cow_flag());
        new_flags.insert(PageTableFlags::WRITABLE);

        // H-35 fix: If map fails, try to restore the old mapping to avoid page loss
        if let Err(_) = manager.map_page(page, new_frame, new_flags, &mut frame_alloc) {
            // Attempt to restore the old mapping
            let _ = manager.map_page(page, old_frame, flags, &mut frame_alloc);
            // Flush TLB for this page to ensure old mapping is visible
            x86_64::instructions::tlb::flush(virt);
            // Deallocate the new frame we allocated
            frame_alloc.deallocate_frame(new_frame);
            return Err(ForkError::PageTableCopyFailed);
        }

        // H-35 fix: Flush TLB to ensure the new mapping with WRITABLE flag is effective
        x86_64::instructions::tlb::flush(virt);

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
///
/// 使用 RwLock + AtomicU64 实现中断安全的引用计数：
/// - 读取操作只需 RwLock 读锁，高并发友好
/// - 原子操作确保增减引用不需要等待写锁
/// - 新增条目时禁用中断获取写锁，避免死锁
pub struct PhysicalPageRefCount {
    /// 物理页地址 -> 原子引用计数
    /// 使用 AtomicU64 避免在中断上下文中获取锁
    ref_counts: Arc<RwLock<alloc::collections::BTreeMap<usize, AtomicU64>>>,
}

impl PhysicalPageRefCount {
    pub fn new() -> Self {
        PhysicalPageRefCount {
            ref_counts: Arc::new(RwLock::new(alloc::collections::BTreeMap::new())),
        }
    }

    /// 增加页的引用计数
    ///
    /// 快速路径：如果条目已存在，只需原子增加
    /// 慢速路径：禁用中断并获取写锁创建新条目
    pub fn increment(&self, phys_addr: usize) -> u64 {
        // 快速路径：尝试读锁查找已存在的条目
        if let Some(count) = self.ref_counts.read().get(&phys_addr) {
            return count.fetch_add(1, Ordering::SeqCst) + 1;
        }

        // 慢速路径：禁用中断以安全获取写锁
        interrupts::without_interrupts(|| {
            let mut counts = self.ref_counts.write();
            // Double-check：可能在等待写锁期间被其他 CPU 创建
            let entry = counts
                .entry(phys_addr)
                .or_insert_with(|| AtomicU64::new(0));
            entry.fetch_add(1, Ordering::SeqCst) + 1
        })
    }

    /// 减少页的引用计数
    ///
    /// 返回更新后的引用计数。如果为 0 则调用者可以释放该页。
    /// 使用 CAS 循环确保原子性。
    /// 【M-15 修复】当引用计数归零时，自动从映射中移除条目以防止内存泄漏
    pub fn decrement(&self, phys_addr: usize) -> u64 {
        // 第一阶段：在读锁下进行CAS操作
        let (should_remove, remaining) = {
            let guard = self.ref_counts.read();
            if let Some(count) = guard.get(&phys_addr) {
                let mut prev = count.load(Ordering::SeqCst);
                loop {
                    if prev == 0 {
                        break (false, 0); // 已经为0，不需要移除
                    }
                    match count.compare_exchange(
                        prev,
                        prev - 1,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => {
                            let new_val = prev - 1;
                            break (new_val == 0, new_val); // CAS成功，返回是否需要移除和新值
                        }
                        Err(actual) => prev = actual,
                    }
                }
            } else {
                (false, 0)
            }
        }; // 读锁在这里释放

        // 第二阶段：如果需要移除，在写锁下执行（读锁已释放，避免死锁）
        if should_remove {
            self.remove_entry(phys_addr);
        }

        remaining
    }

    /// 移除指定地址的引用计数条目（引用计数归零时调用）
    fn remove_entry(&self, phys_addr: usize) {
        interrupts::without_interrupts(|| {
            let mut counts = self.ref_counts.write();
            // 二次检查确保确实归零（防止并发increment竞态）
            if let Some(entry) = counts.get(&phys_addr) {
                if entry.load(Ordering::SeqCst) == 0 {
                    counts.remove(&phys_addr);
                }
            }
        });
    }

    /// 获取页的引用计数
    pub fn get(&self, phys_addr: usize) -> u64 {
        self.ref_counts
            .read()
            .get(&phys_addr)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// 移除引用计数为 0 的条目（可选清理）
    pub fn cleanup_zero_entries(&self) {
        interrupts::without_interrupts(|| {
            let mut counts = self.ref_counts.write();
            counts.retain(|_, v| v.load(Ordering::Relaxed) > 0);
        });
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
    } else if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        // 【关键修复】只读用户页面（如代码段）也在进程间共享
        // 缺少引用计数会导致父进程退出时页面被释放，而子进程仍在使用
        //
        // 【TOCTOU 修复】使用一次原子加返回旧值的方式避免 get()+increment 竞态：
        // - increment() 返回更新后的值，减 1 得到旧值
        // - 如果旧值为 0，说明是首次跟踪此页面，需要补记父进程的引用
        // - 如果旧值 > 0，说明已有其他进程在跟踪，只需为子进程增加引用
        let new_count = PAGE_REF_COUNT.increment(addr_usize); // 子进程持有引用
        let prev = new_count.saturating_sub(1); // 计算旧值
        if prev == 0 {
            // 首次跟踪此页面时，补记父进程的持有
            PAGE_REF_COUNT.increment(addr_usize);
        }
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
    // 使用高半区直映访问物理内存
    let virt = mm::phys_to_virt(phys);
    let ptr = virt.as_mut_ptr::<PageTable>();
    &mut *ptr
}

/// 将物理帧清零
unsafe fn zero_table(frame: PhysFrame) {
    let virt = mm::phys_to_virt(frame.start_address());
    core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
}

/// 创建新的用户地址空间
///
/// 分配新的 PML4 页表并复制内核高半区映射（索引 256-511）。
/// 用户空间（索引 0-255）为空，供后续 ELF 加载使用。
///
/// # Returns
///
/// 成功返回新 PML4 的物理帧和物理地址，失败返回 ForkError
///
/// # Safety
///
/// 返回的页表必须在使用完毕后释放，否则会内存泄漏。
pub fn create_fresh_address_space() -> Result<(PhysFrame<Size4KiB>, usize), ForkError> {
    let mut frame_alloc = FrameAllocator::new();

    // 分配新的 PML4 帧
    let new_pml4_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;

    // 清零新页表
    unsafe { zero_table(new_pml4_frame); }

    // 获取当前页表根（复制内核映射）
    let (current_frame, _) = Cr3::read();

    // 递归页表槽索引 (PML4[510] 指向 PML4 自身)
    const RECURSIVE_INDEX: usize = 510;

    unsafe {
        let current_pml4 = phys_to_virt_table(current_frame.start_address());
        let new_pml4 = phys_to_virt_table(new_pml4_frame.start_address());

        // 【关键修复】深拷贝 PML4[0] 并为用户空间准备 4KB 页映射
        //
        // PML4[0] 包含恒等映射（0-4GB），使用 2MB 大页。
        // 用户空间需要 4KB 页映射，所以我们需要：
        // 1. 深拷贝 PML4[0] 路径上的页表（避免影响内核的恒等映射）
        // 2. 将用户空间区域（0x400000 附近）的 2MB 大页拆分为 4KB 页
        if !current_pml4[0].is_unused() {
            deep_copy_identity_for_user(
                current_pml4,
                new_pml4,
                &mut frame_alloc,
            )?;
        }

        // 复制内核高半区映射（索引 256-511）
        // 这些映射在所有进程间共享
        for i in 256..512 {
            new_pml4[i] = current_pml4[i].clone();
        }

        // 【关键修复】设置新页表的递归映射
        // PML4[510] 必须指向新的 PML4 帧自身，而不是从 boot 页表复制的旧值
        // 这样 recursive_pml4() 等函数才能正确访问新页表的条目
        let recursive_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE;
        new_pml4[RECURSIVE_INDEX].set_frame(new_pml4_frame, recursive_flags);
    }

    let phys_addr = new_pml4_frame.start_address().as_u64() as usize;
    Ok((new_pml4_frame, phys_addr))
}

/// 深拷贝恒等映射 PML4[0]，并为用户空间准备 4KB 页映射
///
/// 用户空间起始地址 0x400000 (4MB) 落在：
/// - PML4[0] (0-512GB)
/// - PDPT[0] (0-1GB)
/// - PD[2] (4MB-6MB，因为每个 PD entry 覆盖 2MB)
///
/// 我们需要：
/// 1. 为新页表分配独立的 PDPT（深拷贝）
/// 2. 为 PDPT[0] 分配独立的 PD（深拷贝）
/// 3. 将 PD[2] 的 2MB 大页拆分为 4KB PT（如果需要）
///
/// 这样用户空间可以使用 4KB 页，而内核的恒等映射不受影响。
unsafe fn deep_copy_identity_for_user(
    current_pml4: &mut PageTable,
    new_pml4: &mut PageTable,
    frame_alloc: &mut FrameAllocator,
) -> Result<(), ForkError> {
    // 用户空间起始地址对应的页表索引
    const USER_BASE: usize = 0x400000; // 4MB
    const PDPT_IDX: usize = 0;         // 0-1GB 在 PDPT[0]
    const PD_IDX: usize = 2;           // 4MB-6MB 在 PD[2] (4MB / 2MB = 2)

    let current_pml4_0 = &current_pml4[0];
    if current_pml4_0.is_unused() {
        return Ok(()); // 没有恒等映射，无需处理
    }

    // Step 1: 分配新的 PDPT
    let new_pdpt_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    zero_table(new_pdpt_frame);

    // 复制 PDPT 条目
    let current_pdpt = phys_to_virt_table(current_pml4_0.addr());
    let new_pdpt = phys_to_virt_table(new_pdpt_frame.start_address());
    for i in 0..512 {
        new_pdpt[i] = current_pdpt[i].clone();
    }

    // 更新新 PML4[0] 指向新 PDPT
    // 【关键修复】添加 USER_ACCESSIBLE 以允许用户态访问
    let mut pml4_flags = current_pml4_0.flags();
    pml4_flags.insert(PageTableFlags::USER_ACCESSIBLE);
    new_pml4[0].set_addr(new_pdpt_frame.start_address(), pml4_flags);

    // Step 2: 检查 PDPT[0]（0-1GB 区域）
    let current_pdpt_0 = &current_pdpt[PDPT_IDX];
    if current_pdpt_0.is_unused() {
        return Ok(()); // 0-1GB 未映射
    }

    // 如果 PDPT[0] 是 1GB 大页，我们不支持拆分（太复杂）
    if current_pdpt_0.flags().contains(PageTableFlags::HUGE_PAGE) {
        println!("WARNING: 1GB huge page at PDPT[0], cannot split for user space");
        return Err(ForkError::PageTableCopyFailed);
    }

    // Step 3: 分配新的 PD
    let new_pd_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    zero_table(new_pd_frame);

    // 复制 PD 条目
    let current_pd = phys_to_virt_table(current_pdpt_0.addr());
    let new_pd = phys_to_virt_table(new_pd_frame.start_address());
    for i in 0..512 {
        new_pd[i] = current_pd[i].clone();
    }

    // 更新新 PDPT[0] 指向新 PD
    // 【关键修复】添加 USER_ACCESSIBLE 以允许用户态访问
    let mut pdpt_flags = current_pdpt_0.flags();
    pdpt_flags.insert(PageTableFlags::USER_ACCESSIBLE);
    new_pdpt[PDPT_IDX].set_addr(new_pd_frame.start_address(), pdpt_flags);

    // Step 4: 检查并拆分 PD[2]（4MB-6MB 区域）的 2MB 大页
    let current_pd_entry = &new_pd[PD_IDX];
    if current_pd_entry.is_unused() {
        return Ok(()); // 4MB-6MB 未映射
    }

    if current_pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        // 这是 2MB 大页，需要拆分为 4KB PT
        // 但我们不填充 PT 条目，而是留空让 ELF loader 创建新映射
        // 用户进程不需要 identity mapping，它会有自己的物理帧

        // 分配新的 PT
        let new_pt_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        zero_table(new_pt_frame); // PT 保持为空，不填充 identity mapping

        // 更新 PD[2] 指向新的空 PT（不再是大页）
        // 【关键修复】添加 USER_ACCESSIBLE，移除 NO_EXECUTE 以允许用户代码执行
        // NX 位会被 ELF loader 在 PT 级别按需设置
        let mut pd_flags = current_pd_entry.flags();
        pd_flags.remove(PageTableFlags::HUGE_PAGE);
        pd_flags.remove(PageTableFlags::DIRTY); // DIRTY 是叶子页专有
        pd_flags.remove(PageTableFlags::NO_EXECUTE); // 允许子页按需设置执行权限
        pd_flags.insert(PageTableFlags::USER_ACCESSIBLE);
        new_pd[PD_IDX].set_addr(new_pt_frame.start_address(), pd_flags);
    } else {
        // PD[2] 已经是 4KB PT，确保有 USER_ACCESSIBLE 且无 NO_EXECUTE
        let pd_addr = current_pd_entry.addr();
        let mut pd_flags = current_pd_entry.flags();
        pd_flags.remove(PageTableFlags::NO_EXECUTE); // 允许子页按需设置执行权限
        pd_flags.insert(PageTableFlags::USER_ACCESSIBLE);
        new_pd[PD_IDX].set_addr(pd_addr, pd_flags);
    }

    Ok(())
}
