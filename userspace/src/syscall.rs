//! System Call Wrappers for Zero-OS
//!
//! Provides safe wrappers around the x86_64 `syscall` instruction.
//!
//! ## Syscall ABI (System V AMD64)
//!
//! - Syscall number: RAX
//! - Arguments: RDI, RSI, RDX, R10, R8, R9
//! - Return value: RAX
//! - Clobbered registers: RCX, R11 (by `syscall` instruction itself)
//!
//! ## Error Handling
//!
//! Syscalls return negative error codes on failure (Linux convention).
//! Use `is_error()` and `errno()` helpers to check results.

#![allow(dead_code)]

// ============================================================================
// Syscall Numbers (Linux-compatible)
// ============================================================================

/// Read from file descriptor
pub const SYS_READ: u64 = 0;

/// Write to file descriptor
pub const SYS_WRITE: u64 = 1;

/// Open file
pub const SYS_OPEN: u64 = 2;

/// Close file descriptor
pub const SYS_CLOSE: u64 = 3;

/// Memory map
pub const SYS_MMAP: u64 = 9;

/// Memory unmap
pub const SYS_MUNMAP: u64 = 11;

/// Change data segment size
pub const SYS_BRK: u64 = 12;

/// Yield CPU voluntarily
pub const SYS_YIELD: u64 = 24;

/// Get current process ID
pub const SYS_GETPID: u64 = 39;

/// Create child process (copy-on-write)
pub const SYS_FORK: u64 = 57;

/// Execute new program
pub const SYS_EXEC: u64 = 59;

/// Terminate current process
pub const SYS_EXIT: u64 = 60;

/// Wait for child process
pub const SYS_WAIT: u64 = 61;

/// Send signal to process
pub const SYS_KILL: u64 = 62;

/// Get parent process ID
pub const SYS_GETPPID: u64 = 110;

/// Get thread ID
pub const SYS_GETTID: u64 = 186;

/// Set TID address for clear_child_tid
pub const SYS_SET_TID_ADDRESS: u64 = 218;

/// Terminate process group
pub const SYS_EXIT_GROUP: u64 = 231;

/// Set robust list head
pub const SYS_SET_ROBUST_LIST: u64 = 273;

/// Get random bytes
pub const SYS_GETRANDOM: u64 = 318;

// ============================================================================
// Raw Syscall Primitives
// ============================================================================

/// Execute syscall with 0 arguments
#[inline(always)]
pub unsafe fn syscall0(num: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Execute syscall with 1 argument
#[inline(always)]
pub unsafe fn syscall1(num: u64, arg0: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Execute syscall with 2 arguments
#[inline(always)]
pub unsafe fn syscall2(num: u64, arg0: u64, arg1: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        in("rsi") arg1,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Execute syscall with 3 arguments
#[inline(always)]
pub unsafe fn syscall3(num: u64, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Execute syscall with 4 arguments
#[inline(always)]
pub unsafe fn syscall4(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        in("r10") arg3,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Execute syscall with 5 arguments
#[inline(always)]
pub unsafe fn syscall5(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        in("r10") arg3,
        in("r8") arg4,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Execute syscall with 6 arguments
#[inline(always)]
pub unsafe fn syscall6(
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        in("r10") arg3,
        in("r8") arg4,
        in("r9") arg5,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

// ============================================================================
// Error Handling Helpers
// ============================================================================

/// Maximum error code (syscalls return negative values on error)
const MAX_ERRNO: u64 = 4095;

/// Check if syscall result indicates an error
#[inline(always)]
pub fn is_error(result: u64) -> bool {
    result > (u64::MAX - MAX_ERRNO)
}

/// Extract errno from error result
#[inline(always)]
pub fn errno(result: u64) -> i32 {
    if is_error(result) {
        -(result as i64) as i32
    } else {
        0
    }
}

// ============================================================================
// Typed Syscall Wrappers
// ============================================================================

/// Write data to a file descriptor
///
/// # Arguments
/// - `fd`: File descriptor (1 = stdout, 2 = stderr)
/// - `buf`: Pointer to data buffer
/// - `count`: Number of bytes to write
///
/// # Returns
/// Number of bytes written, or negative error code
#[inline(always)]
pub unsafe fn sys_write(fd: u64, buf: *const u8, count: u64) -> u64 {
    syscall3(SYS_WRITE, fd, buf as u64, count)
}

/// Read data from a file descriptor
///
/// # Arguments
/// - `fd`: File descriptor (0 = stdin)
/// - `buf`: Pointer to destination buffer
/// - `count`: Maximum bytes to read
///
/// # Returns
/// Number of bytes read, or negative error code
#[inline(always)]
pub unsafe fn sys_read(fd: u64, buf: *mut u8, count: u64) -> u64 {
    syscall3(SYS_READ, fd, buf as u64, count)
}

/// Terminate the current process
///
/// # Arguments
/// - `code`: Exit status code (0 = success)
///
/// # Safety
/// This function never returns.
#[inline(always)]
pub unsafe fn sys_exit(code: u64) -> ! {
    core::arch::asm!(
        "syscall",
        in("rax") SYS_EXIT,
        in("rdi") code,
        options(noreturn, nostack),
    );
}

/// Get the current process ID
///
/// # Returns
/// Current process ID (always positive)
#[inline(always)]
pub unsafe fn sys_getpid() -> u64 {
    syscall0(SYS_GETPID)
}

/// Get the parent process ID
///
/// # Returns
/// Parent process ID
#[inline(always)]
pub unsafe fn sys_getppid() -> u64 {
    syscall0(SYS_GETPPID)
}

/// Create a child process (fork with copy-on-write)
///
/// # Returns
/// - In parent: child's PID
/// - In child: 0
/// - On error: negative error code
#[inline(always)]
pub unsafe fn sys_fork() -> u64 {
    syscall0(SYS_FORK)
}

/// Wait for a child process to terminate
///
/// # Arguments
/// - `status`: Pointer to store child's exit status (can be null)
///
/// # Returns
/// Child's PID, or negative error code
#[inline(always)]
pub unsafe fn sys_wait(status: *mut i32) -> u64 {
    syscall1(SYS_WAIT, status as u64)
}

/// Voluntarily yield the CPU to other processes
///
/// # Returns
/// 0 on success
#[inline(always)]
pub unsafe fn sys_yield() -> u64 {
    syscall0(SYS_YIELD)
}

/// Send a signal to a process
///
/// # Arguments
/// - `pid`: Target process ID
/// - `sig`: Signal number
///
/// # Returns
/// 0 on success, negative error code on failure
#[inline(always)]
pub unsafe fn sys_kill(pid: u64, sig: u64) -> u64 {
    syscall2(SYS_KILL, pid, sig)
}

/// Get current thread ID
///
/// # Returns
/// Current thread ID (equals PID in single-threaded processes)
#[inline(always)]
pub unsafe fn sys_gettid() -> u64 {
    syscall0(SYS_GETTID)
}

/// Set the address for clear_child_tid
///
/// # Arguments
/// - `tidptr`: Pointer to store TID (cleared on thread exit)
///
/// # Returns
/// Current TID on success, negative error code on failure
#[inline(always)]
pub unsafe fn sys_set_tid_address(tidptr: *mut i32) -> u64 {
    syscall1(SYS_SET_TID_ADDRESS, tidptr as u64)
}

/// Set robust list head pointer
///
/// # Arguments
/// - `head`: Pointer to robust_list_head structure
/// - `len`: Size of the structure (must be 24)
///
/// # Returns
/// 0 on success, negative error code on failure
#[inline(always)]
pub unsafe fn sys_set_robust_list(head: *const u8, len: usize) -> u64 {
    syscall2(SYS_SET_ROBUST_LIST, head as u64, len as u64)
}

/// Terminate process group
///
/// # Arguments
/// - `code`: Exit status code
///
/// # Safety
/// This function never returns.
#[inline(always)]
pub unsafe fn sys_exit_group(code: u64) -> ! {
    core::arch::asm!(
        "syscall",
        in("rax") SYS_EXIT_GROUP,
        in("rdi") code,
        options(noreturn, nostack),
    );
}

/// Get random bytes
///
/// # Arguments
/// - `buf`: Buffer to fill with random bytes
/// - `len`: Number of bytes to generate
/// - `flags`: Flags (GRND_NONBLOCK=1, GRND_RANDOM=2)
///
/// # Returns
/// Number of bytes written, or negative error code
#[inline(always)]
pub unsafe fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> u64 {
    syscall3(SYS_GETRANDOM, buf as u64, len as u64, flags as u64)
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Write a string slice to stdout
///
/// # Safety
/// The string must be valid UTF-8 (or at least valid bytes).
#[inline]
pub unsafe fn print(s: &str) -> u64 {
    sys_write(1, s.as_ptr(), s.len() as u64)
}

/// Write a string slice to stderr
///
/// # Safety
/// The string must be valid UTF-8 (or at least valid bytes).
#[inline]
pub unsafe fn eprint(s: &str) -> u64 {
    sys_write(2, s.as_ptr(), s.len() as u64)
}
