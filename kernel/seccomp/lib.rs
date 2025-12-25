//! Seccomp/Pledge Syscall Filtering for Zero-OS
//!
//! This module provides two complementary syscall filtering mechanisms:
//!
//! 1. **Seccomp BPF**: Linux-style flexible filtering with a BPF-like VM
//! 2. **Pledge**: OpenBSD-style promise-based sandboxing
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +-------------------+
//! | Syscall Entry    | --> | Seccomp Evaluate  |
//! | (syscall.rs)     |     | (filter stack)    |
//! +------------------+     +-------------------+
//!                                  |
//!                          +-------+-------+
//!                          |               |
//!                          v               v
//!                     Allow           Kill/Errno/Log
//!                          |               |
//!                          v               v
//!                    LSM Hooks       Audit + Action
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // In syscall dispatcher, before executing:
//! let verdict = seccomp::evaluate_current(syscall_nr, &args);
//! match verdict.action {
//!     SeccompAction::Allow => { /* proceed */ }
//!     SeccompAction::Kill => { terminate_with_sigsys(); }
//!     SeccompAction::Errno(e) => { return -e as isize; }
//!     SeccompAction::Log => { audit_log(); /* proceed */ }
//!     SeccompAction::Trap => { deliver_sigsys(); }
//! }
//! ```
//!
//! # Fork/Exec Semantics
//!
//! - **Fork**: Child inherits parent's filter stack (shared via Arc)
//! - **Exec**: Filters persist; pledge exec_promises take effect
//! - **no_new_privs**: Once set, cannot be cleared; prevents privilege escalation

#![no_std]

extern crate alloc;

#[macro_use]
extern crate drivers;

use alloc::vec::Vec;

// Audit integration for violation logging
use audit::{emit_seccomp_violation, AuditSeccompAction, AuditSubject};

pub mod types;

pub use types::{
    FastAllowSet, PledgePromises, PledgeState, SeccompAction, SeccompError,
    SeccompFilter, SeccompFlags, SeccompInsn, SeccompState, SeccompVerdict,
    MAX_INSNS,
};

// ============================================================================
// Strict Mode Syscall Whitelist
// ============================================================================

/// Syscalls allowed in SECCOMP_MODE_STRICT.
///
/// This mirrors Linux's strict mode whitelist.
const STRICT_ALLOWED: &[u64] = &[
    0,   // read
    1,   // write
    60,  // exit
    231, // exit_group
];

/// Create a filter for strict mode.
pub fn strict_filter() -> SeccompFilter {
    let mut prog = Vec::new();

    // Load syscall number
    prog.push(SeccompInsn::LdSyscallNr);

    // Check against whitelist
    for &nr in STRICT_ALLOWED {
        prog.push(SeccompInsn::JmpEq(nr, 0, 1)); // If equal, fall through to Allow
        prog.push(SeccompInsn::Ret(SeccompAction::Allow));
    }

    // Default: kill
    prog.push(SeccompInsn::Ret(SeccompAction::Kill));

    SeccompFilter::new(prog, SeccompAction::Kill, SeccompFlags::empty())
        .expect("strict filter should be valid")
}

// ============================================================================
// Pledge Filter Generation
// ============================================================================

/// Generate a seccomp filter from pledge promises.
///
/// This compiles the promise set into a BPF-like filter that can be
/// evaluated by the same code path as user-provided filters.
pub fn pledge_to_filter(promises: PledgePromises) -> SeccompFilter {
    let mut prog = Vec::new();
    let mut allowed_syscalls: Vec<u64> = Vec::new();

    // Always allow exit
    allowed_syscalls.push(60); // exit
    allowed_syscalls.push(231); // exit_group

    // Add syscalls for each promise
    if promises.contains(PledgePromises::STDIO) {
        allowed_syscalls.extend_from_slice(&[
            0,   // read
            1,   // write
            3,   // close
            5,   // fstat
            8,   // lseek
            39,  // getpid
            102, // getuid
            104, // getgid
            107, // geteuid
            108, // getegid
            110, // getppid
            24,  // sched_yield
        ]);
    }

    if promises.contains(PledgePromises::RPATH) {
        allowed_syscalls.extend_from_slice(&[
            2,   // open (checked separately for flags)
            4,   // stat
            6,   // lstat
            89,  // readlink
            217, // getdents64
        ]);
    }

    if promises.contains(PledgePromises::WPATH) {
        allowed_syscalls.extend_from_slice(&[
            2,  // open (checked separately for flags)
            82, // rename
            87, // unlink
            88, // symlink
        ]);
    }

    if promises.contains(PledgePromises::CPATH) {
        allowed_syscalls.extend_from_slice(&[
            83, // mkdir
            84, // rmdir
            86, // link
        ]);
    }

    if promises.contains(PledgePromises::VM) {
        allowed_syscalls.extend_from_slice(&[
            9,  // mmap
            10, // mprotect
            11, // munmap
            12, // brk
            25, // mremap
        ]);
    }

    if promises.contains(PledgePromises::PROC) {
        allowed_syscalls.extend_from_slice(&[
            56,  // clone
            57,  // fork
            58,  // vfork
            61,  // wait4
            62,  // kill
            247, // waitid
        ]);
    }

    if promises.contains(PledgePromises::EXEC) {
        allowed_syscalls.push(59); // execve
    }

    if promises.contains(PledgePromises::THREAD) {
        allowed_syscalls.extend_from_slice(&[
            56,  // clone (for CLONE_THREAD)
            202, // futex
            218, // set_tid_address
        ]);
    }

    if promises.contains(PledgePromises::TIME) {
        allowed_syscalls.extend_from_slice(&[
            228, // clock_gettime
            318, // getrandom
        ]);
    }

    if promises.contains(PledgePromises::SENDSIG) {
        allowed_syscalls.push(62); // kill
    }

    if promises.contains(PledgePromises::FATTR) {
        allowed_syscalls.extend_from_slice(&[
            90, // chmod
            92, // chown
            93, // fchmod
            94, // fchown
        ]);
    }

    if promises.contains(PledgePromises::RLIMIT) {
        allowed_syscalls.extend_from_slice(&[
            97,  // getrlimit
            160, // setrlimit
        ]);
    }

    // Deduplicate
    allowed_syscalls.sort();
    allowed_syscalls.dedup();

    // Build filter program
    prog.push(SeccompInsn::LdSyscallNr);

    for &nr in &allowed_syscalls {
        prog.push(SeccompInsn::JmpEq(nr, 0, 1));
        prog.push(SeccompInsn::Ret(SeccompAction::Allow));
    }

    // Default: kill
    prog.push(SeccompInsn::Ret(SeccompAction::Kill));

    SeccompFilter::new(prog, SeccompAction::Kill, SeccompFlags::empty())
        .expect("pledge filter should be valid")
}

// ============================================================================
// Current Process Integration
// ============================================================================

/// Evaluate seccomp filters for the current process.
///
/// This is the main entry point called from syscall dispatcher.
/// Returns Allow if no filters are installed.
///
/// # Note
///
/// This function requires access to the current process's PCB.
/// Integration with kernel_core::process is pending.
#[inline]
pub fn evaluate_current(_syscall_nr: u64, _args: &[u64; 6]) -> SeccompVerdict {
    // TODO: Get current process's SeccompState
    // For now, return Allow (no filtering)
    //
    // Integration:
    // if let Some(state) = kernel_core::process::current_seccomp_state() {
    //     return state.evaluate(syscall_nr, args);
    // }

    SeccompVerdict::allow()
}

/// Check if current process has seccomp enabled.
#[inline]
pub fn is_enabled() -> bool {
    // TODO: Check current process's seccomp state
    false
}

/// Convert SeccompAction to AuditSeccompAction.
#[inline]
fn action_to_audit(action: &SeccompAction) -> AuditSeccompAction {
    match action {
        SeccompAction::Allow => AuditSeccompAction::Allow,
        SeccompAction::Log => AuditSeccompAction::Log,
        SeccompAction::Errno(_) => AuditSeccompAction::Errno,
        SeccompAction::Trap => AuditSeccompAction::Trap,
        SeccompAction::Kill => AuditSeccompAction::Kill,
    }
}

/// Notify of a seccomp violation (for audit logging).
///
/// This function should be called when a seccomp filter returns a non-Allow
/// verdict. It emits an audit event with details about the blocked syscall.
///
/// # Arguments
///
/// * `pid` - Process ID of the caller
/// * `uid` - User ID of the caller
/// * `gid` - Group ID of the caller
/// * `syscall_nr` - System call number that was blocked
/// * `verdict` - The verdict returned by the filter
/// * `timestamp` - Event timestamp (from kernel_core::time::get_ticks())
///
/// # Note
///
/// This function is best-effort and ignores audit emission errors to avoid
/// affecting the main code path.
pub fn notify_violation(
    pid: u32,
    uid: u32,
    gid: u32,
    syscall_nr: u64,
    verdict: &SeccompVerdict,
    timestamp: u64,
) {
    let subject = AuditSubject::new(pid, uid, gid, None);
    let audit_action = action_to_audit(&verdict.action);

    // Extract errno from action if applicable
    let errno = match verdict.action {
        SeccompAction::Errno(e) => e as i32,
        SeccompAction::Kill => 9, // SIGKILL-like
        SeccompAction::Trap => 31, // SIGSYS
        _ => 0,
    };

    let _ = emit_seccomp_violation(
        subject,
        syscall_nr,
        verdict.filter_id,
        audit_action,
        errno,
        timestamp,
    );
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the seccomp subsystem.
pub fn init() {
    println!("  Seccomp/Pledge subsystem initialized");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_filter() {
        let filter = strict_filter();

        // Read should be allowed
        let args = [0u64; 6];
        assert_eq!(filter.evaluate(0, &args), SeccompAction::Allow);

        // Write should be allowed
        assert_eq!(filter.evaluate(1, &args), SeccompAction::Allow);

        // Exit should be allowed
        assert_eq!(filter.evaluate(60, &args), SeccompAction::Allow);

        // Other syscalls should be killed
        assert_eq!(filter.evaluate(2, &args), SeccompAction::Kill); // open
        assert_eq!(filter.evaluate(57, &args), SeccompAction::Kill); // fork
    }

    #[test]
    fn test_pledge_stdio() {
        let filter = pledge_to_filter(PledgePromises::STDIO);
        let args = [0u64; 6];

        // STDIO syscalls should be allowed
        assert_eq!(filter.evaluate(0, &args), SeccompAction::Allow); // read
        assert_eq!(filter.evaluate(1, &args), SeccompAction::Allow); // write
        assert_eq!(filter.evaluate(3, &args), SeccompAction::Allow); // close

        // Non-STDIO syscalls should be killed
        assert_eq!(filter.evaluate(57, &args), SeccompAction::Kill); // fork
    }

    #[test]
    fn test_promise_parsing() {
        let promises = PledgePromises::parse("stdio rpath").unwrap();
        assert!(promises.contains(PledgePromises::STDIO));
        assert!(promises.contains(PledgePromises::RPATH));
        assert!(!promises.contains(PledgePromises::WPATH));

        // Invalid promise should fail
        assert!(PledgePromises::parse("stdio invalid").is_err());
    }

    #[test]
    fn test_seccomp_state() {
        let mut state = SeccompState::new();
        assert!(!state.has_filters());

        // Add a strict filter
        state.add_filter(strict_filter());
        assert!(state.has_filters());

        // Evaluate
        let args = [0u64; 6];
        assert_eq!(state.evaluate(0, &args).action, SeccompAction::Allow);
        assert_eq!(state.evaluate(57, &args).action, SeccompAction::Kill);
    }

    #[test]
    fn test_filter_validation() {
        // Empty program should fail
        assert!(SeccompFilter::new(vec![], SeccompAction::Allow, SeccompFlags::empty()).is_err());

        // Program without terminator should fail
        let prog = vec![SeccompInsn::LdSyscallNr];
        assert!(SeccompFilter::new(prog, SeccompAction::Allow, SeccompFlags::empty()).is_err());

        // Valid program should succeed
        let prog = vec![SeccompInsn::Ret(SeccompAction::Allow)];
        assert!(SeccompFilter::new(prog, SeccompAction::Allow, SeccompFlags::empty()).is_ok());
    }

    #[test]
    fn test_pledge_rpath_blocks_write_and_create() {
        let state = PledgeState::new(PledgePromises::RPATH);
        let mut args = [0u64; 6];

        // O_RDONLY should be allowed with rpath
        args[1] = 0; // flags
        assert!(state.allows(2, &args)); // SYS_OPEN

        // O_WRONLY should be denied without wpath/cpath
        args[1] = 1; // O_WRONLY
        assert!(!state.allows(2, &args));

        // O_CREAT should be denied without cpath/tmppath
        args[1] = 0o100; // O_CREAT
        assert!(!state.allows(2, &args));
    }

    #[test]
    fn test_pledge_prot_exec_requires_promise() {
        const PROT_EXEC: u64 = 0x4;
        let vm_only = PledgeState::new(PledgePromises::VM);
        let vm_with_exec = PledgeState::new(PledgePromises::VM | PledgePromises::PROT_EXEC);

        // mprotect with PROT_EXEC should be denied without prot_exec promise
        let args = [0u64, 0, PROT_EXEC, 0, 0, 0];
        assert!(!vm_only.allows(10, &args)); // SYS_MPROTECT
        assert!(vm_with_exec.allows(10, &args));
    }
}
