//! 同步原语
//!
//! 提供内核空间的同步机制，包括：
//! - 等待队列（WaitQueue）：用于进程阻塞/唤醒
//! - 互斥锁（KMutex）：内核互斥锁（可阻塞）
//! - 信号量（Semaphore）：计数信号量
//!
//! 这些原语是管道、消息队列阻塞操作的基础

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use kernel_core::process::{self, ProcessId, ProcessState};
use spin::Mutex;
use x86_64::instructions::interrupts;

/// 等待队列
///
/// 用于进程阻塞和唤醒。当资源不可用时，进程加入等待队列；
/// 当资源可用时，唤醒等待队列中的进程。
///
/// # X-6 安全增强
///
/// 添加 `closed` 标志防止在端点销毁后新的等待者加入，
/// 避免永久阻塞和资源泄漏。
#[derive(Debug)]
pub struct WaitQueue {
    /// 等待的进程ID列表
    waiters: Mutex<VecDeque<ProcessId>>,
    /// 当为 true 时不再接受新的等待者（用于端点销毁时取消阻塞）
    closed: AtomicBool,
}

impl WaitQueue {
    /// 创建新的等待队列
    pub const fn new() -> Self {
        WaitQueue {
            waiters: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// 将当前进程加入等待队列并阻塞
    ///
    /// 返回true表示成功阻塞后被唤醒，false表示无当前进程或队列已关闭
    ///
    /// # X-6 安全增强
    ///
    /// 如果队列已关闭（如端点被销毁），立即返回 false 而不阻塞，
    /// 防止进程在已销毁的端点上永久阻塞。
    pub fn wait(&self) -> bool {
        let pid = match process::current_pid() {
            Some(p) => p,
            None => return false,
        };

        // X-6: 快速检查 - 如果已关闭则不阻塞
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        let mut enqueued = false;

        // 在关中断状态下操作，防止竞态条件
        interrupts::without_interrupts(|| {
            // X-6: 二次检查 - 在临界区内再次确认未关闭
            if self.closed.load(Ordering::Relaxed) {
                return;
            }

            // 将当前进程加入等待队列
            self.waiters.lock().push_back(pid);

            // 将进程状态设为阻塞
            if let Some(proc_arc) = process::get_process(pid) {
                let mut proc = proc_arc.lock();
                proc.state = ProcessState::Blocked;
            }

            enqueued = true;
        });

        // X-6: 如果未能入队（队列已关闭），直接返回
        if !enqueued {
            return false;
        }

        // 触发调度，让出CPU
        kernel_core::force_reschedule();

        true
    }

    /// 唤醒等待队列中的一个进程
    ///
    /// 返回被唤醒的进程ID，如果队列为空返回None
    pub fn wake_one(&self) -> Option<ProcessId> {
        interrupts::without_interrupts(|| {
            let pid = self.waiters.lock().pop_front()?;

            // 将进程状态设为就绪
            if let Some(proc_arc) = process::get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.state = ProcessState::Ready;
                }
            }

            Some(pid)
        })
    }

    /// 唤醒等待队列中的所有进程
    ///
    /// 返回被唤醒的进程数量
    pub fn wake_all(&self) -> usize {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            let count = waiters.len();

            while let Some(pid) = waiters.pop_front() {
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state == ProcessState::Blocked {
                        proc.state = ProcessState::Ready;
                    }
                }
            }

            count
        })
    }

    /// 唤醒等待队列中的最多 n 个进程
    ///
    /// 用于 futex FUTEX_WAKE 操作，只唤醒指定数量的等待者
    ///
    /// # Arguments
    ///
    /// * `n` - 最多唤醒的进程数量
    ///
    /// # Returns
    ///
    /// 实际唤醒的进程数量
    pub fn wake_n(&self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }

        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            let mut woken = 0;

            while woken < n {
                if let Some(pid) = waiters.pop_front() {
                    if let Some(proc_arc) = process::get_process(pid) {
                        let mut proc = proc_arc.lock();
                        if proc.state == ProcessState::Blocked {
                            proc.state = ProcessState::Ready;
                            woken += 1;
                        }
                    }
                } else {
                    break;
                }
            }

            woken
        })
    }

    /// 检查等待队列是否为空
    pub fn is_empty(&self) -> bool {
        self.waiters.lock().is_empty()
    }

    /// 获取等待队列中的进程数量
    pub fn len(&self) -> usize {
        self.waiters.lock().len()
    }

    /// 检查队列是否已关闭（例如端点被销毁）
    ///
    /// # X-6 安全增强
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// 关闭队列并唤醒所有等待者
    ///
    /// 用于端点销毁时，确保所有等待者被唤醒并得到错误返回。
    /// 关闭后的队列不再接受新的等待者。
    ///
    /// # X-6 安全增强
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake_all();
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// 内核互斥锁
///
/// 可阻塞的互斥锁，当锁不可用时进程会被阻塞。
/// 适用于需要长时间持有锁的场景。
pub struct KMutex {
    /// 锁状态：true表示已锁定
    locked: AtomicBool,
    /// 等待队列
    wait_queue: WaitQueue,
    /// 当前持有锁的进程ID（调试用）
    owner: Mutex<Option<ProcessId>>,
}

impl KMutex {
    /// 创建新的互斥锁
    pub const fn new() -> Self {
        KMutex {
            locked: AtomicBool::new(false),
            wait_queue: WaitQueue::new(),
            owner: Mutex::new(None),
        }
    }

    /// 获取锁
    ///
    /// 如果锁已被持有，当前进程会被阻塞直到锁可用
    pub fn lock(&self) {
        loop {
            // 尝试获取锁
            if self.locked.compare_exchange(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            ).is_ok() {
                // 成功获取锁
                if let Some(pid) = process::current_pid() {
                    *self.owner.lock() = Some(pid);
                }
                return;
            }

            // 锁被占用，加入等待队列并阻塞
            self.wait_queue.wait();
        }
    }

    /// 尝试获取锁（非阻塞）
    ///
    /// 如果锁可用，获取锁并返回true；否则返回false
    pub fn try_lock(&self) -> bool {
        if self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok() {
            if let Some(pid) = process::current_pid() {
                *self.owner.lock() = Some(pid);
            }
            true
        } else {
            false
        }
    }

    /// 释放锁
    pub fn unlock(&self) {
        *self.owner.lock() = None;
        self.locked.store(false, Ordering::Release);

        // 唤醒一个等待者
        self.wait_queue.wake_one();
    }

    /// 检查锁是否被持有
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl Default for KMutex {
    fn default() -> Self {
        Self::new()
    }
}

/// 计数信号量
///
/// 用于控制对有限资源的并发访问
pub struct Semaphore {
    /// 当前计数
    count: AtomicU32,
    /// 等待队列
    wait_queue: WaitQueue,
}

impl Semaphore {
    /// 创建新的信号量
    ///
    /// # Arguments
    ///
    /// * `initial` - 初始计数值
    pub const fn new(initial: u32) -> Self {
        Semaphore {
            count: AtomicU32::new(initial),
            wait_queue: WaitQueue::new(),
        }
    }

    /// P操作（等待/获取）
    ///
    /// 如果计数大于0，减1并继续；否则阻塞直到计数大于0
    pub fn wait(&self) {
        loop {
            let current = self.count.load(Ordering::SeqCst);
            if current > 0 {
                // 尝试减少计数
                if self.count.compare_exchange(
                    current,
                    current - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ).is_ok() {
                    return;
                }
                // CAS失败，重试
                continue;
            }

            // 计数为0，阻塞
            self.wait_queue.wait();
        }
    }

    /// P操作（非阻塞）
    ///
    /// 如果计数大于0，减1并返回true；否则返回false
    pub fn try_wait(&self) -> bool {
        loop {
            let current = self.count.load(Ordering::SeqCst);
            if current == 0 {
                return false;
            }
            if self.count.compare_exchange(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ).is_ok() {
                return true;
            }
        }
    }

    /// V操作（发布/释放）
    ///
    /// 增加计数并唤醒一个等待者
    pub fn signal(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.wait_queue.wake_one();
    }

    /// 获取当前计数
    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }
}

/// 条件变量
///
/// 用于等待特定条件成立
pub struct CondVar {
    /// 等待队列
    wait_queue: WaitQueue,
}

impl CondVar {
    /// 创建新的条件变量
    pub const fn new() -> Self {
        CondVar {
            wait_queue: WaitQueue::new(),
        }
    }

    /// 等待条件成立
    ///
    /// 调用者必须在持有相关锁的情况下调用此函数。
    /// 此函数会释放锁、等待唤醒、然后重新获取锁。
    ///
    /// # Arguments
    ///
    /// * `mutex` - 保护条件的互斥锁
    pub fn wait(&self, mutex: &KMutex) {
        // 释放锁
        mutex.unlock();

        // 等待唤醒
        self.wait_queue.wait();

        // 重新获取锁
        mutex.lock();
    }

    /// 唤醒一个等待者
    pub fn notify_one(&self) {
        self.wait_queue.wake_one();
    }

    /// 唤醒所有等待者
    pub fn notify_all(&self) {
        self.wait_queue.wake_all();
    }
}

impl Default for CondVar {
    fn default() -> Self {
        Self::new()
    }
}
