//! Zero-OS User-Space Library
//!
//! Provides system call wrappers and runtime support for user-space programs.
//!
//! ## Usage
//!
//! ```rust
//! #![no_std]
//! #![no_main]
//!
//! use userspace::syscall::{sys_write, sys_exit};
//!
//! #[no_mangle]
//! pub extern "C" fn _start() -> ! {
//!     unsafe {
//!         sys_write(1, b"Hello!\n".as_ptr(), 7);
//!         sys_exit(0);
//!     }
//! }
//! ```

#![no_std]

pub mod syscall;

/// Panic handler for user-space programs.
///
/// Attempts to print an error message and exits with code 1.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Try to print panic message to stderr
    unsafe {
        let msg = b"PANIC in user program\n";
        let _ = syscall::sys_write(2, msg.as_ptr(), msg.len() as u64);
        syscall::sys_exit(1);
    }
}
