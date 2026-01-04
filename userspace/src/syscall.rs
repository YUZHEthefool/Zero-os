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

/// Get file status by path
pub const SYS_STAT: u64 = 4;

/// Get file status by descriptor
pub const SYS_FSTAT: u64 = 5;

/// Reposition file offset
pub const SYS_LSEEK: u64 = 8;

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

/// Get system information
pub const SYS_UNAME: u64 = 63;

/// Get current working directory
pub const SYS_GETCWD: u64 = 79;

/// Change current working directory
pub const SYS_CHDIR: u64 = 80;

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

/// Read directory entries
pub const SYS_GETDENTS64: u64 = 217;

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

/// Open a file or directory
///
/// # Arguments
/// - `path`: Path to open (null-terminated)
/// - `flags`: Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
/// - `mode`: Creation mode bits (used with O_CREAT)
///
/// # Returns
/// File descriptor on success, or negative error code
#[inline(always)]
pub unsafe fn sys_open(path: *const u8, flags: i32, mode: u32) -> u64 {
    syscall3(SYS_OPEN, path as u64, flags as u64, mode as u64)
}

/// Close a file descriptor
///
/// # Arguments
/// - `fd`: File descriptor to close
///
/// # Returns
/// 0 on success, or negative error code
#[inline(always)]
pub unsafe fn sys_close(fd: u64) -> u64 {
    syscall1(SYS_CLOSE, fd)
}

/// Get file status by path
///
/// # Arguments
/// - `path`: Path to the file (null-terminated)
/// - `statbuf`: Pointer to Stat structure to fill
///
/// # Returns
/// 0 on success, or negative error code
#[inline(always)]
pub unsafe fn sys_stat(path: *const u8, statbuf: *mut Stat) -> u64 {
    syscall2(SYS_STAT, path as u64, statbuf as u64)
}

/// Get file status by file descriptor
///
/// # Arguments
/// - `fd`: File descriptor
/// - `statbuf`: Pointer to Stat structure to fill
///
/// # Returns
/// 0 on success, or negative error code
#[inline(always)]
pub unsafe fn sys_fstat(fd: u64, statbuf: *mut Stat) -> u64 {
    syscall2(SYS_FSTAT, fd, statbuf as u64)
}

/// Reposition file offset
///
/// # Arguments
/// - `fd`: File descriptor
/// - `offset`: Offset value
/// - `whence`: Reference point (SEEK_SET=0, SEEK_CUR=1, SEEK_END=2)
///
/// # Returns
/// New file offset, or negative error code
#[inline(always)]
pub unsafe fn sys_lseek(fd: u64, offset: i64, whence: u64) -> u64 {
    syscall3(SYS_LSEEK, fd, offset as u64, whence)
}

/// Read directory entries
///
/// # Arguments
/// - `fd`: Directory file descriptor
/// - `dirp`: Buffer to fill with directory entries
/// - `count`: Buffer size in bytes
///
/// # Returns
/// Number of bytes read, or negative error code
#[inline(always)]
pub unsafe fn sys_getdents64(fd: i32, dirp: *mut u8, count: usize) -> u64 {
    syscall3(SYS_GETDENTS64, fd as u64, dirp as u64, count as u64)
}

/// Get current working directory
///
/// # Arguments
/// - `buf`: Buffer to store the path
/// - `size`: Buffer size
///
/// # Returns
/// Length of path on success, or negative error code
#[inline(always)]
pub unsafe fn sys_getcwd(buf: *mut u8, size: usize) -> u64 {
    syscall2(SYS_GETCWD, buf as u64, size as u64)
}

/// Change current working directory
///
/// # Arguments
/// - `path`: Path to the new directory (null-terminated)
///
/// # Returns
/// 0 on success, or negative error code
#[inline(always)]
pub unsafe fn sys_chdir(path: *const u8) -> u64 {
    syscall1(SYS_CHDIR, path as u64)
}

/// Get system information
///
/// # Arguments
/// - `buf`: Pointer to UtsName structure to fill
///
/// # Returns
/// 0 on success, or negative error code
#[inline(always)]
pub unsafe fn sys_uname(buf: *mut UtsName) -> u64 {
    syscall1(SYS_UNAME, buf as u64)
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
// Data Structures
// ============================================================================

/// File status structure (matches kernel VfsStat)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

/// Directory entry header returned by getdents64
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    // followed by name bytes + '\0'
}

/// System name structure (uname)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UtsName {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
        }
    }
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
