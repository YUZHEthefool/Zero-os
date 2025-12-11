//! 调度器回调钩子
//!
//! 提供调度器与其他模块之间的解耦接口，避免循环依赖。
//! - arch 模块通过此钩子调用调度器的定时器处理
//! - syscall 模块通过此钩子触发重调度检查

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// 定时器回调类型：在定时器中断时调用
pub type TimerCallback = fn();

/// 重调度回调类型：force=true 强制调度，false 仅在需要时调度
pub type ReschedCallback = fn(force: bool);

/// 全局定时器回调
static TIMER_CB: Mutex<Option<TimerCallback>> = Mutex::new(None);

/// 全局重调度回调
static RESCHED_CB: Mutex<Option<ReschedCallback>> = Mutex::new(None);

/// 【关键修复】从中断上下文延迟的抢占请求标志
///
/// 在中断上下文中不能直接调用 switch_context（会导致栈和特权级问题），
/// 只设置此标志，由安全路径（syscall 返回）消费
static IRQ_RESCHED_PENDING: AtomicBool = AtomicBool::new(false);

/// 注册定时器回调
///
/// 调度器在初始化时调用此函数注册 on_clock_tick 处理器
pub fn register_timer_callback(cb: TimerCallback) {
    *TIMER_CB.lock() = Some(cb);
}

/// 注册重调度回调
///
/// 调度器在初始化时调用此函数注册 reschedule_now 处理器
pub fn register_resched_callback(cb: ReschedCallback) {
    *RESCHED_CB.lock() = Some(cb);
}

/// 调用定时器回调
///
/// 由 arch 模块的定时器中断处理器调用
#[inline]
pub fn on_scheduler_tick() {
    if let Some(cb) = *TIMER_CB.lock() {
        cb();
    }
}

/// 检查并执行重调度（如果需要）
///
/// 由系统调用返回路径调用，仅在 NEED_RESCHED 或 IRQ_RESCHED_PENDING 标志置位时执行调度
#[inline]
pub fn reschedule_if_needed() {
    // 消费中断触发的抢占请求
    let irq_pending = IRQ_RESCHED_PENDING.swap(false, Ordering::SeqCst);

    if let Some(cb) = *RESCHED_CB.lock() {
        // 如果有中断请求，强制调度；否则由调度器检查 NEED_RESCHED
        cb(irq_pending);
    }
}

/// 强制执行重调度
///
/// 由 sys_yield 调用，无论 NEED_RESCHED 标志如何都执行调度
#[inline]
pub fn force_reschedule() {
    if let Some(cb) = *RESCHED_CB.lock() {
        cb(true);
    }
}

/// 【新增】从中断上下文请求抢占
///
/// 仅设置标志，不执行实际的上下文切换。
/// 实际切换在安全路径（syscall 返回或下一个调度点）执行。
///
/// # Safety
///
/// 此函数可从中断上下文安全调用
#[inline]
pub fn request_resched_from_irq() {
    IRQ_RESCHED_PENDING.store(true, Ordering::SeqCst);
}
