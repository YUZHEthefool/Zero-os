//! Zero-OS Ring 3 Test Program
//!
//! A minimal user-space program that verifies Ring 3 execution and syscall functionality.
//! This program:
//! 1. Writes "Hello from Ring 3!" to stdout
//! 2. Gets and prints its PID
//! 3. Exits with code 0

#![no_std]
#![no_main]

use userspace::syscall::{sys_exit, sys_getpid, sys_write};

/// Test message written to stdout
const HELLO_MSG: &[u8] = b"Hello from Ring 3!\n";

/// PID prefix message
const PID_MSG: &[u8] = b"My PID is: ";

/// Newline character
const NEWLINE: &[u8] = b"\n";

/// Success message
const SUCCESS_MSG: &[u8] = b"Ring 3 syscall test passed!\n";

/// Program entry point
///
/// Called by the kernel after setting up the user-space environment.
/// Stack is set up according to System V AMD64 ABI.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        // Test 1: sys_write to stdout
        let _ = sys_write(1, HELLO_MSG.as_ptr(), HELLO_MSG.len() as u64);

        // Test 2: sys_getpid
        let pid = sys_getpid();

        // Print PID (simple decimal conversion)
        let _ = sys_write(1, PID_MSG.as_ptr(), PID_MSG.len() as u64);
        print_number(pid);
        let _ = sys_write(1, NEWLINE.as_ptr(), NEWLINE.len() as u64);

        // Test 3: Success message
        let _ = sys_write(1, SUCCESS_MSG.as_ptr(), SUCCESS_MSG.len() as u64);

        // Exit successfully
        sys_exit(0);
    }
}

/// Print a number to stdout (simple decimal conversion)
unsafe fn print_number(mut n: u64) {
    if n == 0 {
        let zero = b"0";
        let _ = sys_write(1, zero.as_ptr(), 1);
        return;
    }

    // Buffer for digits (max 20 digits for u64)
    let mut buf = [0u8; 20];
    let mut i = 20;

    while n > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }

    let _ = sys_write(1, buf[i..].as_ptr(), (20 - i) as u64);
}
