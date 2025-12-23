//! Linux Security Module (LSM) Hook Infrastructure for Zero-OS
//!
//! This module provides a flexible hook-based security framework inspired by
//! Linux's LSM, allowing pluggable security policies to control kernel operations.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+
//! | Kernel Subsystem | --> | LSM Hook         |
//! | (syscall/vfs/ipc)|     | (hook_xxx_yyy)   |
//! +------------------+     +------------------+
//!                                  |
//!                                  v
//!                          +------------------+
//!                          | Active Policy    |
//!                          | (LsmPolicy impl) |
//!                          +------------------+
//!                                  |
//!                          +-------+-------+
//!                          |               |
//!                          v               v
//!                     Ok(()) = allow   Err = deny
//! ```
//!
//! # Feature Gate
//!
//! The `lsm` feature controls whether policy enforcement is active:
//! - `lsm` feature enabled: Hooks call the active policy
//! - `lsm` feature disabled: All hooks return Ok(()) (no overhead)
//!
//! # Callback Pattern
//!
//! To avoid cyclic dependencies with kernel_core, this module uses a callback
//! pattern for getting current process context. Call `register_context_provider()`
//! during kernel initialization.
//!
//! # Usage
//!
//! ```rust,ignore
//! // In syscall handler:
//! let ctx = SyscallCtx::from_current(syscall_nr, &args);
//! lsm::hook_syscall_enter(&ctx)?;
//!
//! // ... execute syscall ...
//!
//! lsm::hook_syscall_exit(&ctx, result);
//! ```

#![no_std]

extern crate alloc;

#[macro_use]
extern crate drivers;

use cap::{CapId, CapRights};
use core::sync::atomic::{AtomicPtr, Ordering};
use spin::Mutex;

// Audit integration (only when LSM feature is enabled)
#[cfg(feature = "lsm")]
use audit::{emit_lsm_denial, AuditLsmReason, AuditObject, AuditSubject};

pub mod policy;

pub use policy::{DenyAllPolicy, LsmError, LsmPolicy, LsmResult, PermissivePolicy};

// ============================================================================
// Local Type Definitions (to avoid cyclic dependency with kernel_core/vfs)
// ============================================================================

/// Process identifier type (matches kernel_core::ProcessId)
pub type ProcessId = usize;

/// Process credentials (matches kernel_core::Credentials)
#[derive(Debug, Clone, Copy)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
}

/// Open flags for file operations (simplified from vfs::OpenFlags)
#[derive(Debug, Clone, Copy)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Read-only flag
    pub const O_RDONLY: u32 = 0;
    /// Write-only flag
    pub const O_WRONLY: u32 = 1;
    /// Read-write flag
    pub const O_RDWR: u32 = 2;
    /// Create if not exists
    pub const O_CREAT: u32 = 0o100;
    /// Exclusive create
    pub const O_EXCL: u32 = 0o200;
    /// Truncate
    pub const O_TRUNC: u32 = 0o1000;
    /// Append
    pub const O_APPEND: u32 = 0o2000;

    #[inline]
    pub fn is_readable(&self) -> bool {
        (self.0 & 3) != Self::O_WRONLY
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        (self.0 & 3) != Self::O_RDONLY
    }

    #[inline]
    pub fn raw(&self) -> u32 {
        self.0
    }
}

// ============================================================================
// Context Provider Callbacks
// ============================================================================

/// Callback type for getting current process ID
pub type GetPidCallback = fn() -> Option<ProcessId>;

/// Callback type for getting current process credentials
pub type GetCredentialsCallback = fn() -> Option<Credentials>;

/// Callback type for getting current tick count (for timestamps)
pub type GetTicksCallback = fn() -> u64;

/// Context provider state
struct ContextProvider {
    get_pid: Option<GetPidCallback>,
    get_credentials: Option<GetCredentialsCallback>,
    get_ticks: Option<GetTicksCallback>,
}

static CONTEXT_PROVIDER: Mutex<ContextProvider> = Mutex::new(ContextProvider {
    get_pid: None,
    get_credentials: None,
    get_ticks: None,
});

/// Register callbacks for getting current process context.
///
/// Must be called during kernel initialization before LSM hooks are used.
pub fn register_context_provider(
    get_pid: GetPidCallback,
    get_credentials: GetCredentialsCallback,
    get_ticks: GetTicksCallback,
) {
    let mut provider = CONTEXT_PROVIDER.lock();
    provider.get_pid = Some(get_pid);
    provider.get_credentials = Some(get_credentials);
    provider.get_ticks = Some(get_ticks);
}

/// Get current process ID using registered callback
#[inline]
fn current_pid() -> Option<ProcessId> {
    let provider = CONTEXT_PROVIDER.lock();
    provider.get_pid.and_then(|f| f())
}

/// Get current credentials using registered callback
#[inline]
fn current_credentials() -> Option<Credentials> {
    let provider = CONTEXT_PROVIDER.lock();
    provider.get_credentials.and_then(|f| f())
}

/// Get current tick count using registered callback
#[cfg(feature = "lsm")]
#[inline]
fn get_ticks() -> u64 {
    let provider = CONTEXT_PROVIDER.lock();
    provider.get_ticks.map(|f| f()).unwrap_or(0)
}

// ============================================================================
// Hook Context Types
// ============================================================================

/// Syscall context for entry/exit hooks.
#[derive(Debug, Clone, Copy)]
pub struct SyscallCtx {
    /// Process ID of the caller.
    pub pid: ProcessId,
    /// Thread group ID.
    pub tgid: ProcessId,
    /// Real user ID.
    pub uid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// System call number.
    pub syscall_nr: u64,
    /// System call arguments.
    pub args: [u64; 6],
    /// Capability used for this operation (if any).
    pub cap: Option<CapId>,
}

impl SyscallCtx {
    /// Create a syscall context from current process state.
    pub fn from_current(syscall_nr: u64, args: &[u64; 6]) -> Option<Self> {
        let creds = current_credentials()?;
        let pid = current_pid()?;

        Some(Self {
            pid,
            tgid: pid, // TODO: get actual tgid when threading is full
            uid: creds.uid,
            gid: creds.gid,
            euid: creds.euid,
            egid: creds.egid,
            syscall_nr,
            args: *args,
            cap: None,
        })
    }
}

/// Process-level context (credentials + ids).
#[derive(Debug, Clone, Copy)]
pub struct ProcessCtx {
    /// Process ID.
    pub pid: ProcessId,
    /// Thread group ID.
    pub tgid: ProcessId,
    /// Real user ID.
    pub uid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Capability used for this operation (if any).
    pub cap: Option<CapId>,
}

impl ProcessCtx {
    /// Create a process context from current process state.
    pub fn from_current() -> Option<Self> {
        let creds = current_credentials()?;
        let pid = current_pid()?;

        Some(Self {
            pid,
            tgid: pid,
            uid: creds.uid,
            gid: creds.gid,
            euid: creds.euid,
            egid: creds.egid,
            cap: None,
        })
    }

    /// Create a process context with explicit values.
    pub fn new(
        pid: ProcessId,
        tgid: ProcessId,
        uid: u32,
        gid: u32,
        euid: u32,
        egid: u32,
    ) -> Self {
        Self {
            pid,
            tgid,
            uid,
            gid,
            euid,
            egid,
            cap: None,
        }
    }
}

/// File/VFS context.
#[derive(Debug, Clone)]
pub struct FileCtx {
    /// Inode number.
    pub inode: u64,
    /// File mode (permissions).
    pub mode: u32,
    /// Path hash (FNV-1a of the path string).
    pub path_hash: u64,
    /// Capability used for this operation (if any).
    pub cap: Option<CapId>,
}

impl FileCtx {
    /// Create a file context.
    pub fn new(inode: u64, mode: u32, path_hash: u64) -> Self {
        Self {
            inode,
            mode,
            path_hash,
            cap: None,
        }
    }
}

/// IPC context (mq/pipe/futex/shm).
#[derive(Debug, Clone, Copy)]
pub struct IpcCtx {
    /// Endpoint ID (for message queues).
    pub endpoint_id: u64,
    /// Number of bytes being transferred.
    pub bytes: usize,
    /// Capability used for this operation (if any).
    pub cap: Option<CapId>,
}

impl IpcCtx {
    /// Create an IPC context.
    pub fn new(endpoint_id: u64, bytes: usize) -> Self {
        Self {
            endpoint_id,
            bytes,
            cap: None,
        }
    }
}

/// Signal/ptrace context.
#[derive(Debug, Clone, Copy)]
pub struct SignalCtx {
    /// Target process ID.
    pub target_pid: ProcessId,
    /// Signal number.
    pub sig: i32,
    /// Capability used for this operation (if any).
    pub cap: Option<CapId>,
}

impl SignalCtx {
    /// Create a signal context.
    pub fn new(target_pid: ProcessId, sig: i32) -> Self {
        Self {
            target_pid,
            sig,
            cap: None,
        }
    }
}

/// Network context (socket/bind/connect/send/recv).
#[derive(Debug, Clone, Copy)]
pub struct NetCtx {
    /// Socket identifier.
    pub socket_id: u64,
    /// Protocol (e.g., IPPROTO_TCP = 6, IPPROTO_UDP = 17).
    pub proto: u16,
    /// Local address (packed IPv4 or hash of IPv6).
    pub local: u64,
    /// Local port.
    pub local_port: u16,
    /// Remote address.
    pub remote: u64,
    /// Remote port.
    pub remote_port: u16,
    /// Capability used for this operation (if any).
    pub cap: Option<CapId>,
}

impl NetCtx {
    /// Create a network context.
    pub fn new(socket_id: u64, proto: u16) -> Self {
        Self {
            socket_id,
            proto,
            local: 0,
            local_port: 0,
            remote: 0,
            remote_port: 0,
            cap: None,
        }
    }
}

// ============================================================================
// Audit Helpers (LSM feature only)
// ============================================================================

/// Convert LSM context to audit subject.
#[cfg(feature = "lsm")]
#[inline]
fn audit_subject_from_ctx(pid: ProcessId, uid: u32, gid: u32, cap: Option<CapId>) -> AuditSubject {
    AuditSubject::new(pid as u32, uid, gid, cap.map(|c| c.raw()))
}

/// Map LsmError to AuditLsmReason.
#[cfg(feature = "lsm")]
#[inline]
fn audit_reason_from_error(err: &LsmError) -> AuditLsmReason {
    match err {
        LsmError::Denied => AuditLsmReason::Policy,
        LsmError::Internal => AuditLsmReason::Internal,
    }
}

/// Emit audit event for LSM denial.
///
/// This is called internally by hook dispatchers when a policy denies an operation.
#[cfg(feature = "lsm")]
#[inline]
fn emit_denial_audit(
    subject: AuditSubject,
    object: AuditObject,
    hook: &'static str,
    err: &LsmError,
) {
    let reason = audit_reason_from_error(err);
    // EPERM = 1 for permission denied
    let _ = emit_lsm_denial(subject, object, hook, reason, 1, get_ticks());
}

// ============================================================================
// Policy Registry (IRQ-Safe with AtomicPtr)
// ============================================================================

/// Static reference to the permissive policy for default.
static PERMISSIVE: PermissivePolicy = PermissivePolicy;

/// Wrapper to hold the fat pointer atomically.
///
/// Using a struct wrapper allows us to store the entire trait object
/// reference in a single atomic slot, avoiding torn reads between
/// the data and vtable pointers.
#[cfg(feature = "lsm")]
#[repr(C)]
struct PolicySlot {
    policy: &'static dyn LsmPolicy,
}

#[cfg(feature = "lsm")]
static PERMISSIVE_SLOT: PolicySlot = PolicySlot { policy: &PERMISSIVE };

/// Active policy slot pointer.
///
/// Points to a PolicySlot containing the active policy. Uses AtomicPtr
/// for lock-free access from interrupt context. The pointer is initialized
/// to PERMISSIVE_SLOT and updated atomically via set_policy().
///
/// By storing a pointer to a struct containing the fat pointer (rather than
/// splitting the fat pointer across two atomics), we ensure readers always
/// see a consistent (data, vtable) pair.
#[cfg(feature = "lsm")]
static ACTIVE_POLICY_SLOT: AtomicPtr<PolicySlot> = AtomicPtr::new(core::ptr::null_mut());

/// Storage for user-provided policy slots.
///
/// Since policies are &'static, they live forever, but we need somewhere
/// to store the PolicySlot wrapper. We use a simple approach: the slot
/// is allocated statically for each set_policy call. For simplicity,
/// we only support a single non-default policy at a time.
#[cfg(feature = "lsm")]
static mut USER_POLICY_SLOT: Option<PolicySlot> = None;

/// Set the active security policy.
///
/// # Arguments
///
/// * `policy` - Static reference to a policy implementation
///
/// # Safety
///
/// This function is safe but should ideally be called only during boot.
/// If called while hooks are executing, the old policy may still be
/// called until the next hook invocation. This is intentional to avoid
/// requiring locks on the hot path.
///
/// # Note
///
/// This is a no-op when the `lsm` feature is disabled.
#[cfg(feature = "lsm")]
pub fn set_policy(policy: &'static dyn LsmPolicy) {
    // Store the policy in the user slot
    // Safety: This is safe because:
    // 1. We're storing a 'static reference
    // 2. The atomic store below ensures proper synchronization
    unsafe {
        USER_POLICY_SLOT = Some(PolicySlot { policy });
        // Get a pointer to the slot
        let slot_ptr = USER_POLICY_SLOT.as_ref().unwrap() as *const PolicySlot as *mut PolicySlot;
        ACTIVE_POLICY_SLOT.store(slot_ptr, Ordering::Release);
    }
}

#[cfg(not(feature = "lsm"))]
pub fn set_policy(_policy: &'static dyn LsmPolicy) {}

/// Get the active security policy.
///
/// This is lock-free and safe to call from interrupt context.
#[cfg(feature = "lsm")]
pub fn policy() -> &'static dyn LsmPolicy {
    let slot_ptr = ACTIVE_POLICY_SLOT.load(Ordering::Acquire);

    if slot_ptr.is_null() {
        // Not yet initialized, return permissive
        return &PERMISSIVE;
    }

    // Safety: The pointer is either null (handled above) or points to a
    // valid PolicySlot that was set by set_policy() or init().
    unsafe { (*slot_ptr).policy }
}

#[cfg(not(feature = "lsm"))]
pub fn policy() -> &'static dyn LsmPolicy {
    &PERMISSIVE
}

// ============================================================================
// Hook Dispatch Helpers
// ============================================================================

// When lsm feature is disabled, all hooks are inlined to Ok(())
// providing zero-overhead when security enforcement is not needed.

/// Hook: syscall entry.
#[inline]
pub fn hook_syscall_enter(ctx: &SyscallCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().syscall_enter(ctx);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(ctx.pid, ctx.uid, ctx.gid, ctx.cap);
            emit_denial_audit(subject, AuditObject::None, "syscall_enter", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = ctx;
        Ok(())
    }
}

/// Hook: syscall exit.
#[inline]
pub fn hook_syscall_exit(ctx: &SyscallCtx, ret: isize) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().syscall_exit(ctx, ret)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (ctx, ret);
        Ok(())
    }
}

/// Hook: process fork.
#[inline]
pub fn hook_task_fork(parent: &ProcessCtx, child: &ProcessCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().task_fork(parent, child);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(parent.pid, parent.uid, parent.gid, parent.cap);
            let object = AuditObject::Process { pid: child.pid as u32, signal: None };
            emit_denial_audit(subject, object, "task_fork", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (parent, child);
        Ok(())
    }
}

/// Hook: process exec.
#[inline]
pub fn hook_task_exec(task: &ProcessCtx, path_hash: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().task_exec(task, path_hash);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            let object = AuditObject::Path { inode: 0, mode: 0, path_hash };
            emit_denial_audit(subject, object, "task_exec", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, path_hash);
        Ok(())
    }
}

/// Hook: process exit.
#[inline]
pub fn hook_task_exit(task: &ProcessCtx, code: i32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().task_exit(task, code)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, code);
        Ok(())
    }
}

/// Hook: setuid/setgid.
#[inline]
pub fn hook_task_setuid(task: &ProcessCtx, new_uid: u32, new_gid: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().task_setuid(task, new_uid, new_gid);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            emit_denial_audit(subject, AuditObject::None, "task_setuid", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, new_uid, new_gid);
        Ok(())
    }
}

/// Hook: setresuid (real/effective/saved UIDs).
#[inline]
pub fn hook_task_setresuid(task: &ProcessCtx, ruid: u32, euid: u32, suid: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().task_setresuid(task, ruid, euid, suid)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ruid, euid, suid);
        Ok(())
    }
}

/// Hook: setgroups (supplementary groups).
#[inline]
pub fn hook_task_setgroups(task: &ProcessCtx, groups: &[u32]) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().task_setgroups(task, groups)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, groups);
        Ok(())
    }
}

/// Hook: prctl.
#[inline]
pub fn hook_task_prctl(task: &ProcessCtx, option: i32, arg2: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().task_prctl(task, option, arg2)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, option, arg2);
        Ok(())
    }
}

/// Hook: capability modification.
#[inline]
pub fn hook_task_cap_modify(task: &ProcessCtx, cap_id: CapId, op: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().task_cap_modify(task, cap_id, op)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, cap_id, op);
        Ok(())
    }
}

/// Hook: file lookup.
#[inline]
pub fn hook_file_lookup(task: &ProcessCtx, parent_inode: u64, name_hash: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_lookup(task, parent_inode, name_hash)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, parent_inode, name_hash);
        Ok(())
    }
}

/// Hook: file open.
#[inline]
pub fn hook_file_open(task: &ProcessCtx, inode: u64, flags: OpenFlags, ctx: &FileCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().file_open(task, inode, flags, ctx);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            let object = AuditObject::Path {
                inode: ctx.inode,
                mode: ctx.mode,
                path_hash: ctx.path_hash,
            };
            emit_denial_audit(subject, object, "file_open", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, inode, flags, ctx);
        Ok(())
    }
}

/// Hook: file create.
#[inline]
pub fn hook_file_create(task: &ProcessCtx, parent_inode: u64, name_hash: u64, mode: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().file_create(task, parent_inode, name_hash, mode);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            let object = AuditObject::Path {
                inode: parent_inode,
                mode,
                path_hash: name_hash,
            };
            emit_denial_audit(subject, object, "file_create", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, parent_inode, name_hash, mode);
        Ok(())
    }
}

/// Hook: file mmap.
#[inline]
pub fn hook_file_mmap(task: &ProcessCtx, inode: u64, prot: u32, flags: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().file_mmap(task, inode, prot, flags);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            // Use Memory object for mmap denials
            let object = AuditObject::Memory { vaddr: 0, size: 0, prot };
            emit_denial_audit(subject, object, "file_mmap", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, inode, prot, flags);
        Ok(())
    }
}

/// Hook: file chmod.
#[inline]
pub fn hook_file_chmod(task: &ProcessCtx, inode: u64, mode: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().file_chmod(task, inode, mode);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            let object = AuditObject::Path { inode, mode, path_hash: 0 };
            emit_denial_audit(subject, object, "file_chmod", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, inode, mode);
        Ok(())
    }
}

/// Hook: file chown.
#[inline]
pub fn hook_file_chown(task: &ProcessCtx, inode: u64, uid: u32, gid: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().file_chown(task, inode, uid, gid);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            let object = AuditObject::Path { inode, mode: 0, path_hash: 0 };
            emit_denial_audit(subject, object, "file_chown", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, inode, uid, gid);
        Ok(())
    }
}

/// Hook: file unlink.
#[inline]
pub fn hook_file_unlink(task: &ProcessCtx, parent_inode: u64, name_hash: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().file_unlink(task, parent_inode, name_hash);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            let object = AuditObject::Path { inode: parent_inode, mode: 0, path_hash: name_hash };
            emit_denial_audit(subject, object, "file_unlink", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, parent_inode, name_hash);
        Ok(())
    }
}

/// Hook: file rename.
#[inline]
pub fn hook_file_rename(
    task: &ProcessCtx,
    old_parent: u64,
    old_name_hash: u64,
    new_parent: u64,
    new_name_hash: u64,
) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_rename(task, old_parent, old_name_hash, new_parent, new_name_hash)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, old_parent, old_name_hash, new_parent, new_name_hash);
        Ok(())
    }
}

/// Hook: file hard link.
#[inline]
pub fn hook_file_link(task: &ProcessCtx, inode: u64, new_parent: u64, name_hash: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_link(task, inode, new_parent, name_hash)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, inode, new_parent, name_hash);
        Ok(())
    }
}

/// Hook: file symlink.
#[inline]
pub fn hook_file_symlink(task: &ProcessCtx, parent_inode: u64, name_hash: u64, target_hash: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_symlink(task, parent_inode, name_hash, target_hash)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, parent_inode, name_hash, target_hash);
        Ok(())
    }
}

/// Hook: mkdir.
#[inline]
pub fn hook_file_mkdir(task: &ProcessCtx, parent_inode: u64, name_hash: u64, mode: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_mkdir(task, parent_inode, name_hash, mode)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, parent_inode, name_hash, mode);
        Ok(())
    }
}

/// Hook: rmdir.
#[inline]
pub fn hook_file_rmdir(task: &ProcessCtx, parent_inode: u64, name_hash: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_rmdir(task, parent_inode, name_hash)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, parent_inode, name_hash);
        Ok(())
    }
}

/// Hook: file truncate.
#[inline]
pub fn hook_file_truncate(task: &ProcessCtx, inode: u64, size: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_truncate(task, inode, size)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, inode, size);
        Ok(())
    }
}

/// Hook: file permission check.
#[inline]
pub fn hook_file_permission(task: &ProcessCtx, inode: u64, access_mask: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_permission(task, inode, access_mask)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, inode, access_mask);
        Ok(())
    }
}

/// Hook: mount.
#[inline]
pub fn hook_file_mount(
    task: &ProcessCtx,
    source_hash: u64,
    target_hash: u64,
    fstype_hash: u64,
    flags: u64,
) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_mount(task, source_hash, target_hash, fstype_hash, flags)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, source_hash, target_hash, fstype_hash, flags);
        Ok(())
    }
}

/// Hook: umount.
#[inline]
pub fn hook_file_umount(task: &ProcessCtx, target_hash: u64, flags: u64) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().file_umount(task, target_hash, flags)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, target_hash, flags);
        Ok(())
    }
}

/// Hook: IPC send.
#[inline]
pub fn hook_ipc_send(task: &ProcessCtx, ctx: &IpcCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().ipc_send(task, ctx)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx);
        Ok(())
    }
}

/// Hook: IPC receive.
#[inline]
pub fn hook_ipc_recv(task: &ProcessCtx, ctx: &IpcCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().ipc_recv(task, ctx)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx);
        Ok(())
    }
}

/// Hook: pipe creation.
#[inline]
pub fn hook_ipc_pipe(task: &ProcessCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().ipc_pipe(task)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = task;
        Ok(())
    }
}

/// Hook: futex operation.
#[inline]
pub fn hook_ipc_futex(task: &ProcessCtx, addr: usize, op: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().ipc_futex(task, addr, op)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, addr, op);
        Ok(())
    }
}

/// Hook: shared memory operation.
#[inline]
pub fn hook_ipc_shm(task: &ProcessCtx, shm_id: u64, size: usize, rights: CapRights) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().ipc_shm(task, shm_id, size, rights)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, shm_id, size, rights);
        Ok(())
    }
}

/// Hook: signal send.
#[inline]
pub fn hook_signal_send(task: &ProcessCtx, ctx: &SignalCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().signal_send(task, ctx);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            let object = AuditObject::Process {
                pid: ctx.target_pid as u32,
                signal: Some(ctx.sig as u32),
            };
            emit_denial_audit(subject, object, "signal_send", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx);
        Ok(())
    }
}

/// Hook: ptrace operation.
#[inline]
pub fn hook_ptrace(tracer: &ProcessCtx, target: &ProcessCtx, op: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().ptrace(tracer, target, op);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(tracer.pid, tracer.uid, tracer.gid, tracer.cap);
            let object = AuditObject::Process {
                pid: target.pid as u32,
                signal: None,
            };
            emit_denial_audit(subject, object, "ptrace", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (tracer, target, op);
        Ok(())
    }
}

/// Hook: socket creation.
#[inline]
pub fn hook_net_socket(task: &ProcessCtx, ctx: &NetCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().net_socket(task, ctx);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            emit_denial_audit(subject, AuditObject::None, "net_socket", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx);
        Ok(())
    }
}

/// Hook: socket bind.
#[inline]
pub fn hook_net_bind(task: &ProcessCtx, ctx: &NetCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().net_bind(task, ctx);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            emit_denial_audit(subject, AuditObject::None, "net_bind", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx);
        Ok(())
    }
}

/// Hook: socket connect.
#[inline]
pub fn hook_net_connect(task: &ProcessCtx, ctx: &NetCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        let res = policy().net_connect(task, ctx);
        if let Err(ref err) = res {
            let subject = audit_subject_from_ctx(task.pid, task.uid, task.gid, task.cap);
            emit_denial_audit(subject, AuditObject::None, "net_connect", err);
        }
        res
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx);
        Ok(())
    }
}

/// Hook: socket listen.
#[inline]
pub fn hook_net_listen(task: &ProcessCtx, ctx: &NetCtx, backlog: u32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().net_listen(task, ctx, backlog)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx, backlog);
        Ok(())
    }
}

/// Hook: socket accept.
#[inline]
pub fn hook_net_accept(task: &ProcessCtx, ctx: &NetCtx) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().net_accept(task, ctx)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx);
        Ok(())
    }
}

/// Hook: setsockopt.
#[inline]
pub fn hook_net_setsockopt(task: &ProcessCtx, ctx: &NetCtx, level: i32, optname: i32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().net_setsockopt(task, ctx, level, optname)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx, level, optname);
        Ok(())
    }
}

/// Hook: network send.
#[inline]
pub fn hook_net_send(task: &ProcessCtx, ctx: &NetCtx, bytes: usize) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().net_send(task, ctx, bytes)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx, bytes);
        Ok(())
    }
}

/// Hook: network receive.
#[inline]
pub fn hook_net_recv(task: &ProcessCtx, ctx: &NetCtx, bytes: usize) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().net_recv(task, ctx, bytes)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx, bytes);
        Ok(())
    }
}

/// Hook: socket shutdown.
#[inline]
pub fn hook_net_shutdown(task: &ProcessCtx, ctx: &NetCtx, how: i32) -> LsmResult {
    #[cfg(feature = "lsm")]
    {
        policy().net_shutdown(task, ctx, how)
    }
    #[cfg(not(feature = "lsm"))]
    {
        let _ = (task, ctx, how);
        Ok(())
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the LSM subsystem.
///
/// Must be called during kernel boot. Sets the default permissive policy.
pub fn init() {
    #[cfg(feature = "lsm")]
    {
        // Initialize the policy registry with the permissive policy
        // This ensures policy() never returns from the null branch after init
        let slot_ptr = &PERMISSIVE_SLOT as *const PolicySlot as *mut PolicySlot;
        ACTIVE_POLICY_SLOT.store(slot_ptr, Ordering::Release);
    }
}
