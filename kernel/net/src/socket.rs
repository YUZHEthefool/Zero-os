//! Socket capability layer for Zero-OS (Phase D.2)
//!
//! This module provides a capability-based socket API with security-first design:
//!
//! - **Capability-Based Access**: Sockets are accessed via CapId handles
//! - **LSM Integration**: All operations pass through security hooks
//! - **Rate Limiting**: Per-socket and global limits prevent DoS
//! - **Security Labels**: Sockets carry creator context for MAC enforcement
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! |  User Syscall    | --> |  SocketTable     | --> |  SocketState     |
//! |  (via CapId)     |     |  (global lookup) |     |  (per-socket)    |
//! +------------------+     +------------------+     +------------------+
//!                                  |                        |
//!                                  v                        v
//!                          +------------------+     +------------------+
//!                          |  Port Bindings   |     |  RX Queue        |
//!                          |  (UDP port map)  |     |  (datagrams)     |
//!                          +------------------+     +------------------+
//! ```
//!
//! # Security Features
//!
//! 1. **Capability Checks**: Each syscall validates CapId and rights
//! 2. **LSM Hooks**: create/bind/send/recv pass through hook_net_*
//! 3. **Socket Labels**: Creator credentials captured for MAC decisions
//! 4. **Queue Limits**: MAX_RX_QUEUE prevents memory exhaustion
//! 5. **Port Validation**: Privileged ports require root or capability
//!
//! # Example Flow
//!
//! ```text
//! 1. sys_socket() -> LSM hook_net_socket -> create SocketState -> CapId
//! 2. sys_bind()   -> LSM hook_net_bind   -> allocate port
//! 3. sys_sendto() -> LSM hook_net_send   -> build UDP datagram
//! 4. sys_recvfrom() -> wait on RX queue  -> LSM hook_net_recv -> return data
//! ```
//!
//! # References
//!
//! - POSIX.1-2017 Socket Interface
//! - RFC 768: UDP Protocol

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use spin::{Mutex, Once, RwLock};

use cap::CapId;
use lsm::{
    hook_net_bind, hook_net_recv, hook_net_send, hook_net_socket,
    LsmError, NetCtx, ProcessCtx,
};

// ============================================================================
// Simple Wait Primitives (local to net crate to avoid ipc dependency)
// ============================================================================

/// Wait operation outcome.
///
/// Represents the result of a blocking wait operation.
/// Used by both socket waits and futex operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Resource became available (waiter was explicitly woken)
    Woken,
    /// Operation timed out
    TimedOut,
    /// Resource closed (socket/queue closed while waiting)
    Closed,
    /// No process context available (called from kernel context)
    NoProcess,
}

// ============================================================================
// Socket Wait Hooks (Scheduler Integration)
// ============================================================================

/// Scheduler integration hooks for socket blocking waits.
///
/// This trait allows the net crate to perform true blocking waits without
/// depending on kernel_core's process/scheduler implementation directly.
/// kernel_core registers an implementation at initialization time.
///
/// # Design
///
/// The trait design follows the same pattern as stdin blocking in syscall.rs:
/// 1. Mark process as Blocked
/// 2. Add to waiter queue
/// 3. Call force_reschedule to yield CPU
/// 4. On wakeup, check condition and return outcome
///
/// # Safety
///
/// Implementations must:
/// - Properly handle interrupt disabling during state transitions
/// - Not hold locks across reschedule calls to avoid deadlock
/// - Clean up waiter entries on timeout or close
pub trait SocketWaitHooks: Send + Sync {
    /// Block the current task until woken, timed out, or the queue is closed.
    ///
    /// # Arguments
    /// * `queue` - The wait queue to block on
    /// * `timeout_ns` - Optional timeout in nanoseconds:
    ///   - `None`: Block indefinitely
    ///   - `Some(0)`: Non-blocking poll (return immediately)
    ///   - `Some(n)`: Block for up to n nanoseconds
    ///
    /// # Returns
    /// * `Woken` - Explicitly woken by wake_one/wake_all
    /// * `TimedOut` - Timeout expired before wakeup
    /// * `Closed` - Queue was closed while waiting
    /// * `NoProcess` - No current process context (kernel thread)
    fn wait(&self, queue: &WaitQueue, timeout_ns: Option<u64>) -> WaitOutcome;

    /// Wake one waiter blocked on this queue.
    ///
    /// If multiple waiters are blocked, wakes the one that blocked first (FIFO).
    fn wake_one(&self, queue: &WaitQueue);

    /// Wake all waiters blocked on this queue.
    fn wake_all(&self, queue: &WaitQueue);
}

/// Static storage for the registered wait hooks.
///
/// Uses spin::Once to ensure thread-safe one-time initialization.
/// After initialization, the reference is valid for the lifetime of the kernel.
static SOCKET_WAIT_HOOKS: spin::Once<&'static dyn SocketWaitHooks> = spin::Once::new();

/// Register kernel scheduler hooks for socket waits.
///
/// This should be called once during kernel initialization from kernel_core::init().
/// Multiple calls are safe - only the first registration takes effect.
///
/// # Arguments
/// * `hooks` - Static reference to a SocketWaitHooks implementation
pub fn register_socket_wait_hooks(hooks: &'static dyn SocketWaitHooks) {
    SOCKET_WAIT_HOOKS.call_once(|| hooks);
}

/// Get the registered wait hooks, if any.
#[inline]
fn socket_wait_hooks() -> Option<&'static dyn SocketWaitHooks> {
    SOCKET_WAIT_HOOKS.get().copied()
}

/// Simple wait queue with optional scheduler integration.
///
/// When SocketWaitHooks are registered, this queue supports true blocking
/// with timeout. Without hooks, only non-blocking polling is supported.
///
/// # Architecture
///
/// The queue maintains:
/// - A closed flag to signal permanent closure
/// - A wakeup counter for detecting spurious wakeups
///
/// Actual waiter tracking is delegated to the SocketWaitHooks implementation
/// in kernel_core, which has access to the process table and scheduler.
pub struct WaitQueue {
    /// Flag indicating if the queue is closed
    closed: AtomicBool,
    /// Wakeup counter (incremented on wake, read on wait to detect wakeup)
    wakeup_count: AtomicU64,
}

impl WaitQueue {
    /// Create a new wait queue.
    pub fn new() -> Self {
        WaitQueue {
            closed: AtomicBool::new(false),
            wakeup_count: AtomicU64::new(0),
        }
    }

    /// Wait with optional timeout.
    ///
    /// # Arguments
    /// * `timeout_ns` - Timeout in nanoseconds.
    ///   - `Some(0)`: Non-blocking poll (return immediately)
    ///   - `Some(n)`: Block for up to n nanoseconds
    ///   - `None`: Block indefinitely
    ///
    /// # Returns
    /// - `WaitOutcome::Woken` if wakeup was signaled
    /// - `WaitOutcome::TimedOut` if timeout expired or non-blocking poll
    /// - `WaitOutcome::Closed` if the queue is closed
    /// - `WaitOutcome::NoProcess` if no process context (kernel thread)
    pub fn wait_with_timeout(&self, timeout_ns: Option<u64>) -> WaitOutcome {
        // Check if closed
        if self.closed.load(Ordering::Acquire) {
            return WaitOutcome::Closed;
        }

        // Non-blocking poll returns immediately
        if timeout_ns == Some(0) {
            return WaitOutcome::TimedOut;
        }

        // Consume any pending wake signal that arrived before we registered
        // to avoid sleeping despite a ready datagram.
        if self
            .wakeup_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current > 0).then(|| current - 1)
            })
            .is_ok()
        {
            return WaitOutcome::Woken;
        }

        // Delegate to scheduler hooks for true blocking
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wait(self, timeout_ns)
        } else {
            // No scheduler hooks registered - fall back to non-blocking
            // This happens early in boot or in kernel threads
            WaitOutcome::TimedOut
        }
    }

    /// Signal one waiter.
    ///
    /// Wakes the first blocked waiter (FIFO order). If no waiters are blocked,
    /// increments the wakeup counter so the next wait() sees it.
    pub fn wake_one(&self) {
        self.wakeup_count.fetch_add(1, Ordering::Release);
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wake_one(self);
        }
    }

    /// Signal all waiters.
    ///
    /// Wakes all blocked waiters. If no waiters are blocked, increments the
    /// wakeup counter.
    pub fn wake_all(&self) {
        self.wakeup_count.fetch_add(1, Ordering::Release);
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wake_all(self);
        }
    }

    /// Close the queue and prevent further waits.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Check if closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

use crate::ipv4::Ipv4Addr;
use crate::udp::{
    build_udp_datagram, UdpError,
    EPHEMERAL_PORT_END, EPHEMERAL_PORT_START, UDP_PROTO,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum queued datagrams per socket.
///
/// This limit prevents memory exhaustion attacks. When the queue is full,
/// new datagrams are dropped (not an error - normal network behavior).
const MAX_RX_QUEUE: usize = 64;

/// Privileged port boundary (ports below this require special permissions).
const PRIVILEGED_PORT_LIMIT: u16 = 1024;

// ============================================================================
// Socket Types
// ============================================================================

/// Socket address domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDomain {
    /// IPv4 Internet domain (AF_INET)
    Inet4,
}

impl SocketDomain {
    /// Linux AF_INET value
    pub const AF_INET: u32 = 2;

    /// Parse from Linux domain constant
    pub fn from_raw(domain: u32) -> Option<Self> {
        match domain {
            Self::AF_INET => Some(SocketDomain::Inet4),
            _ => None,
        }
    }
}

/// Socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Datagram socket (SOCK_DGRAM)
    Dgram,
}

impl SocketType {
    /// Linux SOCK_DGRAM value
    pub const SOCK_DGRAM: u32 = 2;

    /// Parse from Linux type constant
    pub fn from_raw(ty: u32) -> Option<Self> {
        match ty {
            Self::SOCK_DGRAM => Some(SocketType::Dgram),
            _ => None,
        }
    }
}

/// Socket protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    /// UDP protocol (IPPROTO_UDP = 17)
    Udp,
}

impl SocketProtocol {
    /// Linux IPPROTO_UDP value
    pub const IPPROTO_UDP: u32 = 17;

    /// Parse from Linux protocol constant
    pub fn from_raw(proto: u32) -> Option<Self> {
        match proto {
            0 | Self::IPPROTO_UDP => Some(SocketProtocol::Udp),
            _ => None,
        }
    }
}

// ============================================================================
// Security Label
// ============================================================================

/// Security label captured at socket creation.
///
/// This label is stored with the socket and used for:
/// 1. LSM hook invocations (passing original creator context)
/// 2. MAC policy decisions (e.g., SELinux domain transitions)
/// 3. Audit logging (who created this socket)
#[derive(Debug, Clone, Copy)]
pub struct SocketLabel {
    /// Process context at creation time
    pub creator: ProcessCtx,
    /// Optional security marking (SELinux/SMACK/AppArmor)
    /// Value 0 means no marking set
    pub secmark: u64,
}

impl SocketLabel {
    /// Create a label from the current process context.
    ///
    /// Returns `None` if there is no current process (kernel context).
    pub fn from_current(secmark: u64) -> Option<Self> {
        ProcessCtx::from_current().map(|creator| SocketLabel { creator, secmark })
    }
}

// ============================================================================
// Pending Datagram
// ============================================================================

/// A received UDP datagram queued for userspace delivery.
#[derive(Debug, Clone)]
pub struct PendingDatagram {
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Source port
    pub src_port: u16,
    /// Datagram payload (UDP data only, no headers)
    pub data: Vec<u8>,
    /// Receive timestamp (ticks)
    pub received_at: u64,
}

// ============================================================================
// Socket Metadata
// ============================================================================

/// Socket binding and connection state.
#[derive(Debug, Clone, Copy, Default)]
struct SocketMeta {
    /// Local IP address (if bound)
    local_ip: Option<[u8; 4]>,
    /// Local port (if bound)
    local_port: Option<u16>,
    /// Remote IP address (if connected)
    remote_ip: Option<[u8; 4]>,
    /// Remote port (if connected)
    remote_port: Option<u16>,
}

impl SocketMeta {
    fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// Socket State
// ============================================================================

/// Per-socket state backing a capability handle.
///
/// This structure is wrapped in `Arc` and stored in the capability table.
/// Multiple CapId entries can reference the same socket (via dup()).
pub struct SocketState {
    /// Unique socket identifier (monotonically increasing)
    pub id: u64,
    /// Socket domain
    pub domain: SocketDomain,
    /// Socket type
    pub ty: SocketType,
    /// Socket protocol
    pub proto: SocketProtocol,
    /// Security label from creation
    pub label: SocketLabel,
    /// Reference count for file descriptors referencing this socket.
    ///
    /// Initialized to 1 at creation. Incremented on dup()/fork(), decremented
    /// on close(). Socket is only fully closed when refcount reaches 0.
    refcount: AtomicU64,
    /// Binding/connection metadata
    meta: Mutex<SocketMeta>,
    /// Received datagram queue
    rx_queue: Mutex<VecDeque<PendingDatagram>>,
    /// Wait queue for blocking recv
    waiters: WaitQueue,
    /// Socket closed flag
    closed: AtomicBool,
    /// Bytes received counter
    rx_bytes: AtomicU64,
    /// Bytes sent counter
    tx_bytes: AtomicU64,
    /// Datagrams received counter
    rx_datagrams: AtomicU64,
    /// Datagrams sent counter
    tx_datagrams: AtomicU64,
    /// Datagrams dropped due to queue full
    rx_dropped: AtomicU64,
}

impl core::fmt::Debug for SocketState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SocketState")
            .field("id", &self.id)
            .field("domain", &self.domain)
            .field("ty", &self.ty)
            .field("proto", &self.proto)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SocketState {
    /// Create a new socket state.
    pub fn new(
        id: u64,
        domain: SocketDomain,
        ty: SocketType,
        proto: SocketProtocol,
        label: SocketLabel,
    ) -> Self {
        SocketState {
            id,
            domain,
            ty,
            proto,
            label,
            refcount: AtomicU64::new(1),
            meta: Mutex::new(SocketMeta::new()),
            rx_queue: Mutex::new(VecDeque::new()),
            waiters: WaitQueue::new(),
            closed: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_datagrams: AtomicU64::new(0),
            tx_datagrams: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
        }
    }

    /// Check if the socket is closed.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Increment the socket reference count.
    ///
    /// Called when a file descriptor is duplicated (dup/dup2/dup3) or when
    /// forking a process that has socket file descriptors.
    ///
    /// Uses AcqRel ordering for symmetry with decrement_refcount() and to
    /// ensure visibility of all modifications before the increment.
    #[inline]
    pub fn increment_refcount(&self) {
        self.refcount.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrement the socket reference count and return the new count.
    ///
    /// Called when a file descriptor is closed. The socket should only be
    /// fully closed (port released, waiters woken) when this returns 0.
    ///
    /// Uses `fetch_update` to prevent underflow: if the refcount is already 0
    /// (which indicates a double-drop bug), we return 0 without modifying the
    /// counter, avoiding wrap to `u64::MAX` which would leak the socket.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if called with refcount == 0 (double-drop).
    #[inline]
    pub fn decrement_refcount(&self) -> u64 {
        match self.refcount.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if current == 0 {
                // Debug: catch double-drop bugs early
                debug_assert!(false, "socket refcount underflow: double-drop detected");
                None // Don't modify - already at 0
            } else {
                Some(current - 1)
            }
        }) {
            Ok(old) => old - 1, // Return new value (old - 1)
            Err(_) => 0,        // Was already 0, return 0
        }
    }

    /// Mark the socket as closed and wake all waiters.
    pub fn mark_closed(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return; // Already closed
        }
        self.waiters.wake_all();
    }

    /// Bind the socket to a local address.
    pub fn bind_local(&self, ip: Ipv4Addr, port: u16) {
        let mut meta = self.meta.lock();
        meta.local_ip = Some(ip.0);
        meta.local_port = Some(port);
    }

    /// Get the local port if bound.
    pub fn local_port(&self) -> Option<u16> {
        self.meta.lock().local_port
    }

    /// Get the local IP address if bound.
    ///
    /// R48-REVIEW FIX: Expose bound local IP for correct source address in sendto.
    pub fn local_ip(&self) -> Option<[u8; 4]> {
        self.meta.lock().local_ip
    }

    /// Get a snapshot of socket metadata.
    fn meta_snapshot(&self) -> SocketMeta {
        *self.meta.lock()
    }

    /// Enqueue a received datagram.
    ///
    /// Returns `true` if the datagram was queued, `false` if dropped
    /// (queue full or socket closed).
    fn enqueue_rx(&self, pkt: PendingDatagram) -> bool {
        if self.is_closed() {
            return false;
        }

        let mut queue = self.rx_queue.lock();
        if queue.len() >= MAX_RX_QUEUE {
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.rx_bytes.fetch_add(pkt.data.len() as u64, Ordering::Relaxed);
        self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
        queue.push_back(pkt);
        drop(queue);

        self.waiters.wake_one();
        true
    }

    /// Pop the next received datagram from the queue.
    fn pop_rx(&self) -> Option<PendingDatagram> {
        self.rx_queue.lock().pop_front()
    }

    /// Get socket statistics.
    pub fn stats(&self) -> SocketStats {
        SocketStats {
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            tx_datagrams: self.tx_datagrams.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            rx_queue_len: self.rx_queue.lock().len(),
        }
    }
}

/// Socket statistics.
#[derive(Debug, Clone, Copy)]
pub struct SocketStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_datagrams: u64,
    pub tx_datagrams: u64,
    pub rx_dropped: u64,
    pub rx_queue_len: usize,
}

// ============================================================================
// Socket Errors
// ============================================================================

/// Socket operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// Invalid socket domain
    InvalidDomain,
    /// Invalid socket type
    InvalidType,
    /// Invalid protocol
    InvalidProtocol,
    /// Permission denied (LSM or DAC)
    PermissionDenied,
    /// Port already in use
    PortInUse,
    /// No ephemeral ports available
    NoPorts,
    /// Socket not bound (sendto without prior bind)
    NotBound,
    /// Socket is closed
    Closed,
    /// Operation timed out
    Timeout,
    /// No current process context
    NoProcess,
    /// Socket not found
    NotFound,
    /// Privileged port requires root
    PrivilegedPort,
    /// UDP layer error
    Udp(UdpError),
    /// LSM policy denial
    Lsm(LsmError),
}

impl From<UdpError> for SocketError {
    fn from(e: UdpError) -> Self {
        SocketError::Udp(e)
    }
}

impl From<LsmError> for SocketError {
    fn from(e: LsmError) -> Self {
        SocketError::Lsm(e)
    }
}

// ============================================================================
// Socket Table
// ============================================================================

/// Global socket table: tracks all sockets and port bindings.
///
/// Thread-safe via RwLock (read-heavy) and Mutex (write operations).
pub struct SocketTable {
    /// Next socket ID (monotonically increasing)
    next_socket_id: AtomicU64,
    /// Next ephemeral port seed
    next_ephemeral: AtomicU16,
    /// All active sockets (socket_id -> SocketState)
    sockets: RwLock<BTreeMap<u64, Arc<SocketState>>>,
    /// UDP port bindings (port -> weak ref to socket)
    udp_bindings: Mutex<BTreeMap<u16, Weak<SocketState>>>,
    /// Statistics
    created: AtomicU64,
    closed_count: AtomicU64,
    bind_count: AtomicU64,
}

impl SocketTable {
    /// Create a new socket table.
    pub const fn new() -> Self {
        SocketTable {
            next_socket_id: AtomicU64::new(1),
            next_ephemeral: AtomicU16::new(EPHEMERAL_PORT_START),
            sockets: RwLock::new(BTreeMap::new()),
            udp_bindings: Mutex::new(BTreeMap::new()),
            created: AtomicU64::new(0),
            closed_count: AtomicU64::new(0),
            bind_count: AtomicU64::new(0),
        }
    }

    /// Create a UDP socket.
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_socket` for LSM policy check
    /// - Captures creator context in socket label
    ///
    /// # Returns
    ///
    /// Arc to the new socket state, ready to be wrapped in a CapEntry.
    pub fn create_udp_socket(&self, label: SocketLabel) -> Result<Arc<SocketState>, SocketError> {
        // Build LSM context
        let mut ctx = NetCtx::new(0, UDP_PROTO as u16);
        ctx.cap = Some(CapId::INVALID);

        // Check LSM policy
        hook_net_socket(&label.creator, &ctx)?;

        // Allocate socket ID
        let id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);

        // Create socket state
        let sock = Arc::new(SocketState::new(
            id,
            SocketDomain::Inet4,
            SocketType::Dgram,
            SocketProtocol::Udp,
            label,
        ));

        // Register in table
        self.sockets.write().insert(id, sock.clone());
        self.created.fetch_add(1, Ordering::Relaxed);

        Ok(sock)
    }

    /// Bind a UDP socket to an address and port.
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to bind
    /// * `current` - Current process context (for privilege check)
    /// * `cap_id` - Capability used for this operation
    /// * `ip` - Local IP address
    /// * `port` - Port number (None for ephemeral)
    /// * `can_bind_privileged` - Whether caller can bind to privileged ports
    ///                           (euid == 0 or NET_BIND_SERVICE capability)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_bind` for LSM policy check
    /// - Ports < 1024 require can_bind_privileged == true
    /// - R47-1 FIX: Uses current creds, not creation creds
    /// - R49-3 FIX: Respects NET_BIND_SERVICE capability via flag
    ///
    /// # Returns
    ///
    /// The bound port number on success.
    pub fn bind_udp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
    ) -> Result<u16, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        // Check if already bound
        if sock.local_port().is_some() {
            return Err(SocketError::PortInUse);
        }

        // Determine port
        let chosen_port = if let Some(p) = port {
            // R49-3 FIX: Privileged port check uses flag from syscall layer
            // This ensures NET_BIND_SERVICE capability is properly honored
            if p < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
                return Err(SocketError::PrivilegedPort);
            }
            p
        } else {
            self.alloc_ephemeral_port()?
        };

        // Build LSM context with actual CapId and current context
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(ip.0);
        ctx.local_port = chosen_port;
        ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

        // Check LSM policy using CURRENT process context
        hook_net_bind(current, &ctx)?;

        // Register port binding
        {
            let mut bindings = self.udp_bindings.lock();

            // Check for existing binding (race condition prevention)
            if let Some(existing) = bindings.get(&chosen_port) {
                if existing.upgrade().is_some() {
                    return Err(SocketError::PortInUse);
                }
                // R47-3 FIX: Remove stale weak reference
                bindings.remove(&chosen_port);
            }

            bindings.insert(chosen_port, Arc::downgrade(sock));
        }

        // Update socket state
        sock.bind_local(ip, chosen_port);
        self.bind_count.fetch_add(1, Ordering::Relaxed);

        Ok(chosen_port)
    }

    /// Build a UDP datagram for transmission.
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to send from
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `src_ip` - Source IP address (our IP)
    /// * `dst_ip` - Destination IP address
    /// * `dst_port` - Destination port
    /// * `payload` - Data to send
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_send` for LSM policy check
    /// - Automatically binds to ephemeral port if not bound
    /// - R47-2 FIX: Uses current creds and actual CapId
    ///
    /// # Returns
    ///
    /// Complete UDP datagram ready for IPv4 encapsulation.
    pub fn send_to_udp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        // Check if closed
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Get or allocate local port
        let local_port = match sock.local_port() {
            Some(p) => p,
            None => {
                // Auto-bind to ephemeral port - no privilege needed for ephemeral ports
                // (ephemeral range is 49152-65535, well above privileged port limit)
                self.bind_udp(sock, current, cap_id, src_ip, None, false)?
            }
        };

        // Build LSM context with actual CapId
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(src_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(dst_ip.0);
        ctx.remote_port = dst_port;
        ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

        // Check LSM policy using CURRENT process context
        hook_net_send(current, &ctx, payload.len())?;

        // Build UDP datagram
        let datagram = build_udp_datagram(src_ip, dst_ip, local_port, dst_port, payload)?;

        // Update statistics
        sock.tx_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
        sock.tx_datagrams.fetch_add(1, Ordering::Relaxed);

        Ok(datagram)
    }

    /// Receive a UDP datagram (blocking with optional timeout).
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to receive from
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `timeout_ns` - Timeout in nanoseconds (None for blocking)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_recv` for LSM policy check
    /// - R47-2 FIX: Uses current creds and actual CapId
    ///
    /// # Returns
    ///
    /// Received datagram on success.
    pub fn recv_from_udp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        timeout_ns: Option<u64>,
    ) -> Result<PendingDatagram, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        loop {
            // Check if closed
            if sock.is_closed() {
                return Err(SocketError::Closed);
            }

            // Try to get a datagram
            if let Some(pkt) = sock.pop_rx() {
                // Build LSM context with actual CapId
                let mut ctx = self.ctx_from_socket(sock);
                ctx.remote = ipv4_to_u64(pkt.src_ip.0);
                ctx.remote_port = pkt.src_port;
                ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

                // Check LSM policy using CURRENT process context
                hook_net_recv(current, &ctx, pkt.data.len())?;

                return Ok(pkt);
            }

            // Block on wait queue
            match sock.waiters.wait_with_timeout(timeout_ns) {
                WaitOutcome::Woken => continue,
                WaitOutcome::TimedOut => return Err(SocketError::Timeout),
                WaitOutcome::Closed => return Err(SocketError::Closed),
                WaitOutcome::NoProcess => return Err(SocketError::NoProcess),
            }
        }
    }

    /// Deliver an inbound UDP datagram to a bound socket.
    ///
    /// Called from the network stack's packet processing path.
    ///
    /// # Arguments
    ///
    /// * `dst_port` - Destination port
    /// * `src_ip` - Source IP address
    /// * `src_port` - Source port
    /// * `data` - Datagram payload
    /// * `now_ticks` - Current time in ticks
    ///
    /// # Security
    ///
    /// - R47-3 FIX: Cleans up stale port bindings
    /// - R47-4 FIX: Checks queue capacity before copying to prevent DoS
    ///
    /// # Returns
    ///
    /// `true` if delivered to a socket, `false` if no listener.
    pub fn deliver_udp(
        &self,
        dst_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
        data: &[u8],
        now_ticks: u64,
    ) -> bool {
        // Look up bound socket
        let target = {
            let mut bindings = self.udp_bindings.lock();
            match bindings.get(&dst_port).and_then(|w| w.upgrade()) {
                Some(sock) => Some(sock),
                None => {
                    // R47-3 FIX: Clean up stale binding if upgrade failed
                    bindings.remove(&dst_port);
                    None
                }
            }
        };

        let Some(sock) = target else {
            return false;
        };

        // R48-3 FIX: Invoke LSM policy check BEFORE allocating/copying
        // attacker-controlled payload. This prevents unauthorized peers from
        // filling MAX_RX_QUEUE of MAC-protected sockets, causing legitimate
        // traffic to be dropped despite policy denial at recv_from_udp time.
        //
        // We use the socket creator's context for the policy decision, since
        // this is packet delivery (not a specific syscall caller context).
        {
            let mut ctx = self.ctx_from_socket(&sock);
            ctx.remote = ipv4_to_u64(src_ip.0);
            ctx.remote_port = src_port;
            // Note: No CapId available in delivery path (not a syscall)

            if hook_net_recv(&sock.label.creator, &ctx, data.len()).is_err() {
                // LSM policy denied - drop packet without consuming queue space
                sock.rx_dropped.fetch_add(1, Ordering::Relaxed);
                return true; // Socket exists but policy denied
            }
        }

        // R47-4 FIX: Check queue capacity BEFORE copying
        // This prevents memory exhaustion from large datagrams
        {
            let queue = sock.rx_queue.lock();
            if queue.len() >= MAX_RX_QUEUE {
                sock.rx_dropped.fetch_add(1, Ordering::Relaxed);
                return true; // Socket exists but queue full - don't report no listener
            }
        }

        // Now safe to allocate memory for the datagram (LSM approved, queue has space)
        let pkt = PendingDatagram {
            src_ip,
            src_port,
            data: data.to_vec(),
            received_at: now_ticks,
        };

        // Enqueue (enqueue_rx may still drop if race condition)
        sock.enqueue_rx(pkt)
    }

    /// Close and remove a socket.
    ///
    /// Called when the capability is revoked or explicitly closed.
    pub fn close(&self, socket_id: u64) {
        if let Some(sock) = self.sockets.write().remove(&socket_id) {
            // Remove port binding
            let meta = sock.meta_snapshot();
            if let Some(port) = meta.local_port {
                self.udp_bindings.lock().remove(&port);
            }

            // Mark closed and wake waiters
            sock.mark_closed();
            self.closed_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get a socket by ID.
    pub fn get(&self, socket_id: u64) -> Option<Arc<SocketState>> {
        self.sockets.read().get(&socket_id).cloned()
    }

    /// Get table statistics.
    pub fn stats(&self) -> TableStats {
        TableStats {
            created: self.created.load(Ordering::Relaxed),
            closed: self.closed_count.load(Ordering::Relaxed),
            active: self.sockets.read().len(),
            bound_ports: self.udp_bindings.lock().len(),
        }
    }

    /// Allocate an ephemeral port.
    fn alloc_ephemeral_port(&self) -> Result<u16, SocketError> {
        let range = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let bindings = self.udp_bindings.lock();

        // Try up to `range` ports
        for _ in 0..range {
            let seed = self.next_ephemeral.fetch_add(1, Ordering::Relaxed);
            let candidate = EPHEMERAL_PORT_START + (seed % range);

            if !bindings.contains_key(&candidate) {
                return Ok(candidate);
            }
        }

        Err(SocketError::NoPorts)
    }

    /// Build LSM NetCtx from socket state.
    fn ctx_from_socket(&self, sock: &SocketState) -> NetCtx {
        let meta = sock.meta_snapshot();
        let mut ctx = NetCtx::new(sock.id, UDP_PROTO as u16);

        if let Some(ip) = meta.local_ip {
            ctx.local = ipv4_to_u64(ip);
        }
        if let Some(port) = meta.local_port {
            ctx.local_port = port;
        }
        if let Some(ip) = meta.remote_ip {
            ctx.remote = ipv4_to_u64(ip);
        }
        if let Some(port) = meta.remote_port {
            ctx.remote_port = port;
        }
        ctx.cap = Some(CapId::INVALID);

        ctx
    }
}

/// Socket table statistics.
#[derive(Debug, Clone, Copy)]
pub struct TableStats {
    pub created: u64,
    pub closed: u64,
    pub active: usize,
    pub bound_ports: usize,
}

// ============================================================================
// Global Singleton
// ============================================================================

static SOCKET_TABLE: Once<SocketTable> = Once::new();

/// Get the global socket table.
pub fn socket_table() -> &'static SocketTable {
    SOCKET_TABLE.call_once(SocketTable::new)
}

// ============================================================================
// Helpers
// ============================================================================

/// Convert IPv4 bytes to u64 for LSM context.
#[inline]
fn ipv4_to_u64(bytes: [u8; 4]) -> u64 {
    u32::from_be_bytes(bytes) as u64
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_domain_from_raw() {
        assert_eq!(SocketDomain::from_raw(2), Some(SocketDomain::Inet4));
        assert_eq!(SocketDomain::from_raw(0), None);
        assert_eq!(SocketDomain::from_raw(10), None); // AF_INET6
    }

    #[test]
    fn test_socket_type_from_raw() {
        assert_eq!(SocketType::from_raw(2), Some(SocketType::Dgram));
        assert_eq!(SocketType::from_raw(1), None); // SOCK_STREAM
    }

    #[test]
    fn test_socket_protocol_from_raw() {
        assert_eq!(SocketProtocol::from_raw(17), Some(SocketProtocol::Udp));
        assert_eq!(SocketProtocol::from_raw(0), Some(SocketProtocol::Udp));
        assert_eq!(SocketProtocol::from_raw(6), None); // TCP
    }

    #[test]
    fn test_ipv4_to_u64() {
        assert_eq!(ipv4_to_u64([192, 168, 1, 1]), 0xC0A80101);
        assert_eq!(ipv4_to_u64([0, 0, 0, 0]), 0);
        assert_eq!(ipv4_to_u64([255, 255, 255, 255]), 0xFFFFFFFF);
    }
}
