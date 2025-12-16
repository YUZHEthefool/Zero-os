//! Minimal per-CPU storage for SMP support
//!
//! Provides a simple per-CPU storage abstraction using CPU ID indexed arrays.
//! Currently uses a single-core fallback (CPU ID always 0) until full SMP
//! support with APIC enumeration is implemented.
//!
//! # Usage
//!
//! ```rust,ignore
//! use cpu_local::CpuLocal;
//! use core::sync::atomic::AtomicUsize;
//!
//! static MY_DATA: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));
//!
//! MY_DATA.with(|d| d.fetch_add(1, Ordering::SeqCst));
//! ```

#![no_std]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use spin::Once;

/// Maximum number of CPUs supported
const MAX_CPUS: usize = 64;

/// Per-CPU storage wrapper
///
/// Stores one instance of T per CPU, lazily initialized on first access.
/// Safe to use from interrupt context as long as T's operations are safe.
pub struct CpuLocal<T> {
    /// Initialization function for each CPU's slot
    init: fn() -> T,
    /// Array of per-CPU slots, initialized lazily
    slots: Once<UnsafeCell<[MaybeUninit<T>; MAX_CPUS]>>,
}

// Safety: CpuLocal is Send+Sync because each CPU only accesses its own slot
unsafe impl<T: Send> Send for CpuLocal<T> {}
unsafe impl<T: Send + Sync> Sync for CpuLocal<T> {}

impl<T> CpuLocal<T> {
    /// Create a new per-CPU storage with the given initializer
    ///
    /// The initializer is called once per CPU slot on first access.
    pub const fn new(init: fn() -> T) -> Self {
        Self {
            init,
            slots: Once::new(),
        }
    }

    /// Get or initialize the slots array
    fn get_slots(&self) -> &UnsafeCell<[MaybeUninit<T>; MAX_CPUS]> {
        self.slots.call_once(|| {
            // Safety: We're initializing all slots before returning
            let mut arr: [MaybeUninit<T>; MAX_CPUS] =
                unsafe { MaybeUninit::uninit().assume_init() };
            for slot in &mut arr {
                slot.write((self.init)());
            }
            UnsafeCell::new(arr)
        })
    }

    /// Access the current CPU's slot immutably
    ///
    /// # Safety
    ///
    /// This is safe because each CPU only accesses its own slot, and we
    /// use interior mutability (e.g., atomics) for any mutations.
    #[inline]
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let id = current_cpu_id();
        // Hard bound check to prevent UB with non-zero-based APIC IDs
        assert!(id < MAX_CPUS, "CPU ID {} out of range (max {})", id, MAX_CPUS);
        // Safety: bound check above guarantees the slot exists and was initialized in get_slots()
        let slot = unsafe {
            let arr = &*self.get_slots().get();
            arr.get(id)
                .expect("CPU slot missing after bounds check")
                .assume_init_ref()
        };
        f(slot)
    }
}

/// Get the current CPU ID
///
/// # Current Implementation
///
/// Returns 0 for single-core operation. When SMP support is implemented,
/// this should read the APIC ID from the Local APIC or use CPUID.
///
/// # Future Implementation
///
/// ```rust,ignore
/// fn current_cpu_id() -> usize {
///     // Read Local APIC ID from 0xFEE00020
///     let apic_id = unsafe {
///         let apic_base = 0xFEE00000 as *const u32;
///         core::ptr::read_volatile(apic_base.add(0x20 / 4)) >> 24
///     };
///     apic_id as usize
/// }
/// ```
#[inline]
pub fn current_cpu_id() -> usize {
    // Single-core fallback - always CPU 0
    // TODO: Implement proper APIC ID reading for SMP
    0
}

/// Get the maximum number of supported CPUs
pub const fn max_cpus() -> usize {
    MAX_CPUS
}
