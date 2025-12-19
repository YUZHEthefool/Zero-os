//! Futex (Fast Userspace Mutex) 实现
//!
//! 提供用户空间快速互斥锁的内核支持，包括：
//! - FUTEX_WAIT: 如果 *uaddr == val，阻塞当前进程；否则返回 EAGAIN
//! - FUTEX_WAKE: 唤醒最多 n 个在 uaddr 上等待的进程
//!
//! 使用全局 FutexTable，以 (pid, vaddr) 为键索引等待队列。
//! 进程退出时自动清理其所有 futex 等待队列。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use kernel_core::process::ProcessId;
use spin::Mutex;

use crate::sync::WaitQueue;

/// Futex 操作码
pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;

/// Futex 错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexError {
    /// 值不匹配（FUTEX_WAIT 时 *uaddr != val）
    WouldBlock,
    /// 无效的操作码
    InvalidOperation,
    /// 内存访问错误
    Fault,
    /// 无当前进程
    NoProcess,
}

/// Futex 键：(进程ID, 虚拟地址)
type FutexKey = (ProcessId, usize);

/// 单个 futex 地址的等待状态
struct FutexBucket {
    /// 等待队列（Arc 包装，避免持有桶锁时阻塞导致死锁）
    queue: Arc<WaitQueue>,
    /// 活跃等待者计数（用于判断是否可以清理）
    waiter_count: usize,
}

impl FutexBucket {
    fn new() -> Self {
        FutexBucket {
            queue: Arc::new(WaitQueue::new()),
            waiter_count: 0,
        }
    }
}

lazy_static::lazy_static! {
    /// 全局 Futex 表
    ///
    /// 以 (pid, vaddr) 为键，管理该地址上的等待队列。
    /// 空队列会在唤醒后被清理，避免内存泄漏。
    static ref FUTEX_TABLE: Mutex<BTreeMap<FutexKey, Arc<Mutex<FutexBucket>>>> =
        Mutex::new(BTreeMap::new());
}

/// 从用户空间读取 u32 值
///
/// 用于 futex_wait 在入队前二次检查值，防止 lost-wake 竞态
fn read_user_u32(uaddr: usize) -> Result<u32, FutexError> {
    use mm::page_table::PageTableManager;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    // 验证用户内存
    unsafe {
        mm::page_table::with_current_manager(
            VirtAddr::new(0),
            |manager: &mut PageTableManager| -> Result<u32, FutexError> {
                let page_addr = uaddr & !0xfff;
                if let Some((_, flags)) =
                    manager.translate_with_flags(VirtAddr::new(page_addr as u64))
                {
                    if !flags.contains(PageTableFlags::PRESENT)
                        || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
                    {
                        return Err(FutexError::Fault);
                    }
                } else {
                    return Err(FutexError::Fault);
                }

                // 安全：已验证用户内存
                let value = core::ptr::read_volatile(uaddr as *const u32);
                Ok(value)
            },
        )
    }
}

/// FUTEX_WAIT 操作
///
/// 如果 *uaddr == expected，则阻塞当前进程；否则返回 WouldBlock。
///
/// # Arguments
///
/// * `pid` - 进程 ID
/// * `uaddr` - 用户空间 futex 地址（已验证）
/// * `expected` - 期望的值
/// * `current_value` - 当前从用户空间读取的值（调用者负责验证和读取）
///
/// # Returns
///
/// 成功阻塞并被唤醒后返回 Ok(0)，值不匹配返回 WouldBlock
pub fn futex_wait(
    pid: ProcessId,
    uaddr: usize,
    expected: u32,
    current_value: u32,
) -> Result<usize, FutexError> {
    // 值不匹配，立即返回
    if current_value != expected {
        return Err(FutexError::WouldBlock);
    }

    let key = (pid, uaddr);

    // 获取或创建此地址的等待桶
    let bucket = get_or_create_bucket(key);

    // 【关键修复】增加等待者计数并获取队列 Arc，然后立即释放桶锁
    // 避免持有桶锁时调用 WaitQueue::wait() 导致死锁
    let queue = {
        let mut b = bucket.lock();
        b.waiter_count += 1;
        b.queue.clone()
    }; // 桶锁在此释放

    // 【关键修复】在入队前二次读取 futex 值，防止 lost-wake 竞态
    // 如果值已变化，说明唤醒者已经完成操作，我们不应该阻塞
    match read_user_u32(uaddr) {
        Ok(cur) if cur == expected => {
            // 值仍然匹配，继续阻塞
        }
        Ok(_) => {
            // 值已变化，回滚等待者计数并返回
            let mut b = bucket.lock();
            if b.waiter_count > 0 {
                b.waiter_count -= 1;
            }
            drop(b);
            cleanup_empty_bucket(key, &bucket);
            return Err(FutexError::WouldBlock);
        }
        Err(e) => {
            // 内存访问错误，回滚并返回
            let mut b = bucket.lock();
            if b.waiter_count > 0 {
                b.waiter_count -= 1;
            }
            drop(b);
            cleanup_empty_bucket(key, &bucket);
            return Err(e);
        }
    }

    // 阻塞等待（WaitQueue::wait 会设置进程状态并触发调度）
    // 此时不持有桶锁，唤醒者可以安全地获取锁并调用 wake_n
    let waited = queue.wait();

    // 被唤醒后减少等待者计数
    {
        let mut b = bucket.lock();
        if b.waiter_count > 0 {
            b.waiter_count -= 1;
        }
    }

    // 尝试清理空桶
    cleanup_empty_bucket(key, &bucket);

    if waited {
        Ok(0)
    } else {
        Err(FutexError::NoProcess)
    }
}

/// FUTEX_WAKE 操作
///
/// 唤醒最多 n 个在 uaddr 上等待的进程。
///
/// # Arguments
///
/// * `pid` - 进程 ID
/// * `uaddr` - 用户空间 futex 地址
/// * `n` - 最多唤醒的进程数量
///
/// # Returns
///
/// 实际唤醒的进程数量
pub fn futex_wake(pid: ProcessId, uaddr: usize, n: usize) -> usize {
    let key = (pid, uaddr);

    // 查找此地址的等待桶
    let bucket = {
        let table = FUTEX_TABLE.lock();
        table.get(&key).cloned()
    };

    let woken = if let Some(ref bucket) = bucket {
        // 获取队列 Arc 后释放桶锁，避免在唤醒时持有锁
        let queue = {
            let b = bucket.lock();
            b.queue.clone()
        };
        queue.wake_n(n)
    } else {
        0
    };

    // 尝试清理空桶
    if let Some(ref bucket) = bucket {
        cleanup_empty_bucket(key, bucket);
    }

    woken
}

/// 清理进程的所有 futex 等待队列
///
/// 进程退出时调用，唤醒所有等待者并移除该进程的所有 futex 条目
pub fn cleanup_process_futexes(pid: ProcessId) {
    let mut table = FUTEX_TABLE.lock();

    // 收集要移除的键
    let keys_to_remove: alloc::vec::Vec<FutexKey> =
        table.keys().filter(|(p, _)| *p == pid).cloned().collect();

    // 唤醒所有等待者并移除条目
    for key in keys_to_remove {
        if let Some(bucket) = table.remove(&key) {
            let queue = {
                let b = bucket.lock();
                b.queue.clone()
            };
            queue.wake_all();
        }
    }
}

/// 获取或创建指定键的等待桶
fn get_or_create_bucket(key: FutexKey) -> Arc<Mutex<FutexBucket>> {
    let mut table = FUTEX_TABLE.lock();
    table
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(FutexBucket::new())))
        .clone()
}

/// 清理空的等待桶（无等待者时移除）
fn cleanup_empty_bucket(key: FutexKey, bucket: &Arc<Mutex<FutexBucket>>) {
    let b = bucket.lock();
    if b.waiter_count == 0 && b.queue.is_empty() {
        drop(b);

        // 重新获取 table 锁进行移除
        let mut table = FUTEX_TABLE.lock();
        if let Some(existing) = table.get(&key) {
            // 确保是同一个桶（防止竞态条件下移除新创建的桶）
            if Arc::ptr_eq(existing, bucket) {
                // 再次检查是否为空
                let b = existing.lock();
                if b.waiter_count == 0 && b.queue.is_empty() {
                    drop(b);
                    table.remove(&key);
                }
            }
        }
    }
}

/// 获取活跃的 futex 地址数量（调试用）
pub fn active_futex_count() -> usize {
    FUTEX_TABLE.lock().len()
}

/// FutexTable 类型别名（向后兼容）
pub type FutexTable = ();
