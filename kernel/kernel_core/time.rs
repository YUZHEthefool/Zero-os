//! 简单时间管理模块
//!
//! 提供基于时钟中断的时间戳支持

use core::sync::atomic::{AtomicU64, Ordering};

/// 全局时钟计数器（每次时钟中断递增）
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// 系统启动时间的 TSC 值（用于更精确的时间测量）
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Last TIME_WAIT sweep timestamp (ms)
static LAST_TIME_WAIT_SWEEP: AtomicU64 = AtomicU64::new(0);

/// TIME_WAIT sweep interval in milliseconds (5 seconds)
const TIME_WAIT_SWEEP_INTERVAL_MS: u64 = 5000;

/// 初始化时间子系统
pub fn init() {
    // 记录启动时的 TSC 值
    let tsc = read_tsc();
    BOOT_TSC.store(tsc, Ordering::SeqCst);
}

/// 时钟中断处理 - 递增时钟计数器
///
/// 应由定时器中断处理程序调用
#[inline]
pub fn on_timer_tick() {
    let current = TICK_COUNT.fetch_add(1, Ordering::SeqCst) + 1;

    // Periodically sweep TIME_WAIT connections (every TIME_WAIT_SWEEP_INTERVAL_MS)
    let last_sweep = LAST_TIME_WAIT_SWEEP.load(Ordering::Relaxed);
    if current.saturating_sub(last_sweep) >= TIME_WAIT_SWEEP_INTERVAL_MS {
        // Try to claim the sweep (avoid multiple concurrent sweeps)
        if LAST_TIME_WAIT_SWEEP
            .compare_exchange(last_sweep, current, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            // Call the TIME_WAIT sweep function
            net::socket_table().sweep_time_wait(current);
        }
    }
}

/// 获取当前时钟计数（自启动以来的时钟周期数）
#[inline]
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::SeqCst)
}

/// 获取当前时间戳（毫秒）
///
/// 假设时钟中断频率为 1000Hz（每毫秒一次）
/// 如果实际频率不同，需要相应调整
#[inline]
pub fn current_timestamp_ms() -> u64 {
    get_ticks()
}

/// 读取 CPU 的时间戳计数器 (TSC)
#[inline]
pub fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let low: u32;
        let high: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, nomem)
        );
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// 获取自启动以来的 TSC 差值
pub fn tsc_since_boot() -> u64 {
    let current = read_tsc();
    let boot = BOOT_TSC.load(Ordering::SeqCst);
    current.saturating_sub(boot)
}
