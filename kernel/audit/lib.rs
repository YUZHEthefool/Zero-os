//! Security Audit Subsystem for Zero-OS
//!
//! This module provides enterprise-grade security audit logging with:
//!
//! - **Tamper Evidence**: Hash-chained events prevent undetected modification
//! - **IRQ Safety**: Lock operations disable interrupts to prevent deadlock
//! - **Fixed Ring Buffer**: Bounded memory with overflow accounting
//! - **Zero Allocation**: Event emission path avoids heap allocation
//! - **Capability Gating**: Future support for access control on audit reads
//!
//! # Security Design
//!
//! 1. **Hash Chain**: Each event includes `prev_hash` and `hash` fields.
//!    The chain allows verification that no events were inserted, deleted,
//!    or modified between any two points.
//!
//! 2. **Overflow Handling**: When the ring buffer is full, oldest events
//!    are evicted. The `dropped` counter in each event tracks how many
//!    events were lost before that record.
//!
//! 3. **Subject/Object Model**: Events capture WHO (subject: pid/uid/gid/cap)
//!    did WHAT (kind: syscall/fs/ipc) to WHOM (object: path/endpoint/socket).
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize during kernel boot
//! audit::init(256)?;
//!
//! // Emit events from syscall/VFS/IPC paths
//! audit::emit(
//!     AuditKind::Syscall,
//!     AuditOutcome::Success,
//!     AuditSubject::new(pid, uid, gid, None),
//!     AuditObject::None,
//!     &[syscall_nr, arg0, arg1],
//!     0,  // errno
//!     get_timestamp(),
//! )?;
//!
//! // Read events for logging/forwarding
//! let snapshot = audit::snapshot();
//! ```

#![no_std]

extern crate alloc;

#[macro_use]
extern crate drivers;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::instructions::interrupts;

// ============================================================================
// Configuration
// ============================================================================

/// Default ring buffer capacity (number of events)
pub const DEFAULT_CAPACITY: usize = 256;

/// Maximum capacity to prevent excessive memory usage
pub const MAX_CAPACITY: usize = 8192;

/// Maximum number of syscall arguments to store
/// Note: We store syscall_num + 6 args, so need 7 slots
pub const MAX_ARGS: usize = 7;

// ============================================================================
// Error Types
// ============================================================================

/// Audit subsystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// Audit subsystem not initialized
    Uninitialized,
    /// Already initialized
    AlreadyInitialized,
    /// Invalid capacity (zero or too large)
    InvalidCapacity,
    /// Audit subsystem is disabled
    Disabled,
}

// ============================================================================
// Event Classification
// ============================================================================

/// High-level category of audit events
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditKind {
    /// System call entry/exit
    Syscall = 0,
    /// Inter-process communication (pipe, mq, futex)
    Ipc = 1,
    /// File system operations (open, read, write, unlink)
    Fs = 2,
    /// Process lifecycle (fork, exec, exit)
    Process = 3,
    /// Signal delivery
    Signal = 4,
    /// Security decisions (DAC/MAC checks, capability use)
    Security = 5,
    /// Network operations (future)
    Network = 6,
    /// Kernel internal events (boot, shutdown)
    Internal = 7,
}

/// Outcome of the audited operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditOutcome {
    /// Operation succeeded
    Success = 0,
    /// Operation denied by security policy
    Denied = 1,
    /// Operation failed with error
    Error = 2,
    /// Informational event (no operation)
    Info = 3,
}

// ============================================================================
// Subject and Object Types
// ============================================================================

/// Subject (actor) of an audit event
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditSubject {
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Capability ID used (if any)
    pub cap_id: Option<u64>,
}

impl AuditSubject {
    /// Create a new audit subject
    #[inline]
    pub const fn new(pid: u32, uid: u32, gid: u32, cap_id: Option<u64>) -> Self {
        Self {
            pid,
            uid,
            gid,
            cap_id,
        }
    }

    /// Create a kernel subject (pid 0)
    #[inline]
    pub const fn kernel() -> Self {
        Self {
            pid: 0,
            uid: 0,
            gid: 0,
            cap_id: None,
        }
    }
}

/// Object (target) of an audit event
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditObject {
    /// No specific object
    None,
    /// File system object
    Path {
        /// Inode number
        inode: u64,
        /// File mode bits
        mode: u32,
        /// FNV-1a hash of the path string (to avoid storing full path)
        path_hash: u64,
    },
    /// IPC endpoint
    Endpoint {
        /// Endpoint ID
        id: u64,
    },
    /// Process target
    Process {
        /// Target PID
        pid: u32,
        /// Signal number (if signal-related)
        signal: Option<u32>,
    },
    /// Capability reference
    Capability {
        /// Capability ID
        cap_id: u64,
    },
    /// Socket (future)
    Socket {
        /// Protocol (TCP=6, UDP=17)
        proto: u8,
        /// Local address (packed IPv4 or hash of IPv6)
        local_addr: u64,
        /// Local port
        local_port: u16,
        /// Remote address
        remote_addr: u64,
        /// Remote port
        remote_port: u16,
    },
    /// Memory region
    Memory {
        /// Virtual address
        vaddr: u64,
        /// Size in bytes
        size: u64,
        /// Protection flags
        prot: u32,
    },
}

// ============================================================================
// Audit Event
// ============================================================================

/// A single audit record with hash chain metadata
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Monotonically increasing event ID
    pub id: u64,
    /// Timestamp (timer ticks since boot)
    pub timestamp: u64,
    /// Event category
    pub kind: AuditKind,
    /// Operation outcome
    pub outcome: AuditOutcome,
    /// Actor information
    pub subject: AuditSubject,
    /// Target object
    pub object: AuditObject,
    /// Operation-specific arguments
    pub args: [u64; MAX_ARGS],
    /// Number of valid arguments
    pub arg_count: u8,
    /// Error number (if outcome is Error)
    pub errno: i32,
    /// Number of events dropped before this one
    pub dropped: u64,
    /// Hash of the previous event (for chain verification)
    pub prev_hash: u64,
    /// Hash of this event (FNV-1a over all fields)
    pub hash: u64,
}

impl AuditEvent {
    /// Create a new event (id, dropped, prev_hash, hash filled by ring buffer)
    fn new(
        timestamp: u64,
        kind: AuditKind,
        outcome: AuditOutcome,
        subject: AuditSubject,
        object: AuditObject,
        args: &[u64],
        errno: i32,
    ) -> Self {
        let mut arg_buf = [0u64; MAX_ARGS];
        let arg_count = args.len().min(MAX_ARGS);
        arg_buf[..arg_count].copy_from_slice(&args[..arg_count]);

        Self {
            id: 0,
            timestamp,
            kind,
            outcome,
            subject,
            object,
            args: arg_buf,
            arg_count: arg_count as u8,
            errno,
            dropped: 0,
            prev_hash: 0,
            hash: 0,
        }
    }
}

// ============================================================================
// Hash Chain (FNV-1a 64-bit)
// ============================================================================

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// FNV-1a 64-bit hasher
struct Fnv1a64(u64);

impl Fnv1a64 {
    #[inline]
    fn new() -> Self {
        Self(FNV_OFFSET_BASIS)
    }

    #[inline]
    fn write_u8(&mut self, byte: u8) {
        self.0 ^= byte as u64;
        self.0 = self.0.wrapping_mul(FNV_PRIME);
    }

    #[inline]
    fn write_u16(&mut self, v: u16) {
        for b in v.to_le_bytes() {
            self.write_u8(b);
        }
    }

    #[inline]
    fn write_u32(&mut self, v: u32) {
        for b in v.to_le_bytes() {
            self.write_u8(b);
        }
    }

    #[inline]
    fn write_u64(&mut self, v: u64) {
        for b in v.to_le_bytes() {
            self.write_u8(b);
        }
    }

    #[inline]
    fn write_i32(&mut self, v: i32) {
        self.write_u32(v as u32);
    }

    #[inline]
    fn finish(self) -> u64 {
        self.0
    }
}

/// Compute FNV-1a hash of an AuditObject
fn hash_object(hasher: &mut Fnv1a64, obj: &AuditObject) {
    match obj {
        AuditObject::None => {
            hasher.write_u8(0);
        }
        AuditObject::Path {
            inode,
            mode,
            path_hash,
        } => {
            hasher.write_u8(1);
            hasher.write_u64(*inode);
            hasher.write_u32(*mode);
            hasher.write_u64(*path_hash);
        }
        AuditObject::Endpoint { id } => {
            hasher.write_u8(2);
            hasher.write_u64(*id);
        }
        AuditObject::Process { pid, signal } => {
            hasher.write_u8(3);
            hasher.write_u32(*pid);
            hasher.write_u32(signal.unwrap_or(0));
        }
        AuditObject::Capability { cap_id } => {
            hasher.write_u8(4);
            hasher.write_u64(*cap_id);
        }
        AuditObject::Socket {
            proto,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        } => {
            hasher.write_u8(5);
            hasher.write_u8(*proto);
            hasher.write_u64(*local_addr);
            hasher.write_u16(*local_port);
            hasher.write_u64(*remote_addr);
            hasher.write_u16(*remote_port);
        }
        AuditObject::Memory { vaddr, size, prot } => {
            hasher.write_u8(6);
            hasher.write_u64(*vaddr);
            hasher.write_u64(*size);
            hasher.write_u32(*prot);
        }
    }
}

/// Compute the hash of an audit event
fn hash_event(prev_hash: u64, event: &AuditEvent) -> u64 {
    let mut hasher = Fnv1a64::new();

    // Chain to previous event
    hasher.write_u64(prev_hash);

    // Event metadata
    hasher.write_u64(event.id);
    hasher.write_u64(event.timestamp);
    hasher.write_u8(event.kind as u8);
    hasher.write_u8(event.outcome as u8);

    // Subject
    hasher.write_u32(event.subject.pid);
    hasher.write_u32(event.subject.uid);
    hasher.write_u32(event.subject.gid);
    hasher.write_u64(event.subject.cap_id.unwrap_or(0));

    // Arguments
    hasher.write_u8(event.arg_count);
    for i in 0..event.arg_count as usize {
        hasher.write_u64(event.args[i]);
    }

    // Error and dropped count
    hasher.write_i32(event.errno);
    hasher.write_u64(event.dropped);

    // Object
    hash_object(&mut hasher, &event.object);

    hasher.finish()
}

// ============================================================================
// Ring Buffer
// ============================================================================

/// Internal ring buffer for audit events
struct AuditRing {
    /// Fixed-size buffer
    buf: Vec<Option<AuditEvent>>,
    /// Index of the oldest event
    head: usize,
    /// Number of events currently stored
    len: usize,
    /// Next event ID
    next_id: u64,
    /// Hash of the last event (chain head)
    prev_hash: u64,
    /// Accumulated dropped count since last emit
    dropped: u64,
}

impl AuditRing {
    /// Create a new ring buffer with given capacity
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: alloc::vec![None; capacity],
            head: 0,
            len: 0,
            next_id: 0,
            prev_hash: FNV_OFFSET_BASIS,
            dropped: 0,
        }
    }

    /// Push an event into the ring buffer
    fn push(&mut self, mut event: AuditEvent) {
        if self.buf.is_empty() {
            return;
        }

        // Evict oldest event if buffer is full
        if self.len == self.buf.len() {
            self.dropped = self.dropped.saturating_add(1);
            self.buf[self.head] = None;
            self.head = (self.head + 1) % self.buf.len();
            self.len -= 1;
        }

        // Fill in event metadata
        event.id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        event.prev_hash = self.prev_hash;
        event.dropped = core::mem::take(&mut self.dropped);
        event.hash = hash_event(event.prev_hash, &event);
        self.prev_hash = event.hash;

        // Insert at tail
        let tail = (self.head + self.len) % self.buf.len();
        self.buf[tail] = Some(event);
        self.len += 1;
    }

    /// Drain all events from the buffer
    fn drain(&mut self) -> Vec<AuditEvent> {
        let mut events = Vec::with_capacity(self.len);
        for _ in 0..self.len {
            if let Some(event) = self.buf[self.head].take() {
                events.push(event);
            }
            self.head = (self.head + 1) % self.buf.len();
        }
        self.len = 0;
        events
    }

    /// Get the current tail hash (for integrity verification)
    fn tail_hash(&self) -> u64 {
        self.prev_hash
    }

    /// Get statistics
    fn stats(&self) -> AuditStats {
        AuditStats {
            total_events: self.next_id,
            buffered_events: self.len as u64,
            dropped_events: self.dropped,
            capacity: self.buf.len() as u64,
            tail_hash: self.prev_hash,
        }
    }
}

// ============================================================================
// Audit Snapshot and Statistics
// ============================================================================

/// Snapshot of audit log for readers
pub struct AuditSnapshot {
    /// Drained events
    pub events: Vec<AuditEvent>,
    /// Number of events dropped since last snapshot
    pub dropped: u64,
    /// Hash of the last event in the chain
    pub tail_hash: u64,
}

/// Audit subsystem statistics
#[derive(Clone, Copy, Debug)]
pub struct AuditStats {
    /// Total events emitted since boot
    pub total_events: u64,
    /// Events currently in buffer
    pub buffered_events: u64,
    /// Events dropped due to overflow
    pub dropped_events: u64,
    /// Buffer capacity
    pub capacity: u64,
    /// Current tail hash
    pub tail_hash: u64,
}

// ============================================================================
// Global Audit Log
// ============================================================================

/// Global audit state
static AUDIT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static AUDIT_ENABLED: AtomicBool = AtomicBool::new(true);
static AUDIT_TOTAL_EMITTED: AtomicU64 = AtomicU64::new(0);

/// Global audit ring buffer (protected by Mutex with IRQ disable)
static AUDIT_RING: Mutex<Option<AuditRing>> = Mutex::new(None);

/// Initialize the audit subsystem
///
/// This must be called during kernel boot, after heap initialization
/// but before any audit events are emitted.
///
/// # Arguments
///
/// * `capacity` - Number of events to buffer (clamped to MAX_CAPACITY)
///
/// # Returns
///
/// Ok(()) on success, Err on failure
pub fn init(capacity: usize) -> Result<(), AuditError> {
    // Validate capacity
    if capacity == 0 {
        return Err(AuditError::InvalidCapacity);
    }
    let capacity = capacity.min(MAX_CAPACITY);

    // Check if already initialized
    if AUDIT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(AuditError::AlreadyInitialized);
    }

    // Initialize with interrupts disabled
    interrupts::without_interrupts(|| {
        let mut ring = AUDIT_RING.lock();
        if ring.is_some() {
            return Err(AuditError::AlreadyInitialized);
        }
        *ring = Some(AuditRing::with_capacity(capacity));
        AUDIT_INITIALIZED.store(true, Ordering::SeqCst);
        Ok(())
    })?;

    println!(
        "  Audit subsystem initialized (capacity: {} events)",
        capacity
    );
    Ok(())
}

/// Check if audit subsystem is initialized
#[inline]
pub fn is_initialized() -> bool {
    AUDIT_INITIALIZED.load(Ordering::Relaxed)
}

/// Enable audit event emission
pub fn enable() {
    AUDIT_ENABLED.store(true, Ordering::SeqCst);
}

/// Disable audit event emission
pub fn disable() {
    AUDIT_ENABLED.store(false, Ordering::SeqCst);
}

/// Check if audit is enabled
#[inline]
pub fn is_enabled() -> bool {
    AUDIT_ENABLED.load(Ordering::Relaxed)
}

/// Emit an audit event
///
/// This is the main entry point for recording security events.
/// The function is designed to be low-overhead and never panic.
///
/// # Arguments
///
/// * `kind` - Event category
/// * `outcome` - Operation result
/// * `subject` - Actor (who performed the action)
/// * `object` - Target (what was acted upon)
/// * `args` - Operation-specific arguments (max 6)
/// * `errno` - Error number (0 if success)
/// * `timestamp` - Event timestamp
///
/// # Returns
///
/// Ok(()) on success, Err if audit is not initialized or disabled
pub fn emit(
    kind: AuditKind,
    outcome: AuditOutcome,
    subject: AuditSubject,
    object: AuditObject,
    args: &[u64],
    errno: i32,
    timestamp: u64,
) -> Result<(), AuditError> {
    // Fast path: check enabled without lock
    if !AUDIT_ENABLED.load(Ordering::Relaxed) {
        return Err(AuditError::Disabled);
    }

    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return Err(AuditError::Uninitialized);
    }

    let event = AuditEvent::new(timestamp, kind, outcome, subject, object, args, errno);

    // Emit with interrupts disabled to prevent deadlock
    interrupts::without_interrupts(|| {
        let mut ring = AUDIT_RING.lock();
        if let Some(ref mut r) = *ring {
            r.push(event);
            AUDIT_TOTAL_EMITTED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(AuditError::Uninitialized)
        }
    })
}

/// Take a snapshot of the audit log (drains all buffered events)
///
/// This function is typically called by a log forwarder or
/// when dumping audit events for analysis.
///
/// # Returns
///
/// Snapshot containing all buffered events and metadata
pub fn snapshot() -> Result<AuditSnapshot, AuditError> {
    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return Err(AuditError::Uninitialized);
    }

    interrupts::without_interrupts(|| {
        let mut ring = AUDIT_RING.lock();
        if let Some(ref mut r) = *ring {
            let dropped = r.dropped;
            let tail_hash = r.tail_hash();
            let events = r.drain();
            Ok(AuditSnapshot {
                events,
                dropped,
                tail_hash,
            })
        } else {
            Err(AuditError::Uninitialized)
        }
    })
}

/// Get audit statistics without draining events
pub fn stats() -> Result<AuditStats, AuditError> {
    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return Err(AuditError::Uninitialized);
    }

    interrupts::without_interrupts(|| {
        let ring = AUDIT_RING.lock();
        if let Some(ref r) = *ring {
            Ok(r.stats())
        } else {
            Err(AuditError::Uninitialized)
        }
    })
}

/// Get total events emitted since boot
#[inline]
pub fn total_emitted() -> u64 {
    AUDIT_TOTAL_EMITTED.load(Ordering::Relaxed)
}

// ============================================================================
// Convenience Macros
// ============================================================================

/// Emit an audit event, ignoring errors
///
/// Use this macro when audit failure should not affect the main code path.
///
/// # Example
///
/// ```rust,ignore
/// audit_emit!(AuditKind::Syscall, AuditOutcome::Success,
///     AuditSubject::new(pid, uid, gid, None),
///     AuditObject::None,
///     &[syscall_nr],
///     timestamp);
/// ```
#[macro_export]
macro_rules! audit_emit {
    ($kind:expr, $outcome:expr, $subject:expr, $object:expr, $args:expr, $errno:expr, $ts:expr) => {{
        let _ = $crate::emit($kind, $outcome, $subject, $object, $args, $errno, $ts);
    }};
    ($kind:expr, $outcome:expr, $subject:expr, $object:expr, $args:expr, $ts:expr) => {{
        let _ = $crate::emit($kind, $outcome, $subject, $object, $args, 0, $ts);
    }};
}

/// Emit a syscall audit event
#[macro_export]
macro_rules! audit_syscall {
    ($outcome:expr, $subject:expr, $syscall_nr:expr, $args:expr, $errno:expr, $ts:expr) => {{
        let _ = $crate::emit(
            $crate::AuditKind::Syscall,
            $outcome,
            $subject,
            $crate::AuditObject::None,
            $args,
            $errno,
            $ts,
        );
    }};
}

/// Emit a file system audit event
#[macro_export]
macro_rules! audit_fs {
    ($outcome:expr, $subject:expr, $inode:expr, $mode:expr, $path_hash:expr, $args:expr, $errno:expr, $ts:expr) => {{
        let _ = $crate::emit(
            $crate::AuditKind::Fs,
            $outcome,
            $subject,
            $crate::AuditObject::Path {
                inode: $inode,
                mode: $mode,
                path_hash: $path_hash,
            },
            $args,
            $errno,
            $ts,
        );
    }};
}

/// Emit a security decision audit event
#[macro_export]
macro_rules! audit_security {
    ($outcome:expr, $subject:expr, $object:expr, $args:expr, $ts:expr) => {{
        let _ = $crate::emit(
            $crate::AuditKind::Security,
            $outcome,
            $subject,
            $object,
            $args,
            0,
            $ts,
        );
    }};
}

// ============================================================================
// Path Hashing Utility
// ============================================================================

/// Compute FNV-1a hash of a path string
///
/// This is used to avoid storing full path strings in audit events,
/// while still allowing correlation between related events.
pub fn hash_path(path: &str) -> u64 {
    let mut hasher = Fnv1a64::new();
    for byte in path.bytes() {
        hasher.write_u8(byte);
    }
    hasher.finish()
}

/// Compute FNV-1a hash of a byte slice
pub fn hash_bytes(data: &[u8]) -> u64 {
    let mut hasher = Fnv1a64::new();
    for byte in data {
        hasher.write_u8(*byte);
    }
    hasher.finish()
}

// ============================================================================
// Chain Verification
// ============================================================================

/// Verify the hash chain of a sequence of events
///
/// Returns true if all events have valid hash chains.
pub fn verify_chain(events: &[AuditEvent]) -> bool {
    if events.is_empty() {
        return true;
    }

    for (i, event) in events.iter().enumerate() {
        let expected_hash = hash_event(event.prev_hash, event);
        if event.hash != expected_hash {
            return false;
        }

        // Verify chain continuity (except for first event)
        if i > 0 && event.prev_hash != events[i - 1].hash {
            return false;
        }
    }

    true
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_hash() {
        let mut hasher = Fnv1a64::new();
        hasher.write_u64(0x12345678);
        let hash = hasher.finish();
        assert_ne!(hash, FNV_OFFSET_BASIS);
    }

    #[test]
    fn test_hash_path() {
        let h1 = hash_path("/etc/passwd");
        let h2 = hash_path("/etc/passwd");
        let h3 = hash_path("/etc/shadow");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            100,
            AuditKind::Syscall,
            AuditOutcome::Success,
            AuditSubject::new(1, 0, 0, None),
            AuditObject::None,
            &[1, 2, 3],
            0,
        );
        assert_eq!(event.timestamp, 100);
        assert_eq!(event.kind, AuditKind::Syscall);
        assert_eq!(event.arg_count, 3);
        assert_eq!(event.args[0], 1);
    }
}
