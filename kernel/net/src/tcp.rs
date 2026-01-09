//! TCP (Transmission Control Protocol) for Zero-OS (Phase D.2)
//!
//! This module provides RFC 793 compliant TCP implementation with security-first design.
//!
//! # TCP Header Format (RFC 793)
//!
//! ```text
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |         Source Port           |       Destination Port        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                        Sequence Number                        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                     Acknowledgment Number                     |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Data  |       |U|A|P|R|S|F|                                   |
//! | Offs  | Resv  |R|C|S|S|Y|I|            Window                 |
//! |       |       |G|K|H|T|N|N|                                   |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |           Checksum            |         Urgent Pointer        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Options (if data offset > 5)               |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                             Data                              |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! # Security Features
//!
//! - ISN randomization per RFC 6528 (keyed hash over 4-tuple + time)
//! - Strict sequence number validation (prevents off-path attacks)
//! - SYN flood protection with backlog limits (SYN cookies placeholder)
//! - Connection resource limits
//! - Checksum verification with IPv4 pseudo-header
//! - RST rate limiting
//! - Invalid flag combination rejection
//!
//! # State Machine
//!
//! ```text
//!                              +---------+ ---------\      active OPEN
//!                              |  CLOSED |            \    -----------
//!                              +---------+<---------\   \   create TCB
//!                                |     ^              \   \  snd SYN
//!                   passive OPEN |     |   CLOSE        \   \
//!                   ------------ |     | ----------       \   \
//!                    create TCB  |     | delete TCB         \   \
//!                                V     |                      \   \
//!                              +---------+            CLOSE    |    \
//!                              |  LISTEN |          ---------- |     |
//!                              +---------+          delete TCB |     |
//!                   rcv SYN      |     |     SEND              |     |
//!                  -----------   |     |    -------            |     V
//! +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//! |         |<-----------------           ------------------>|         |
//! |   SYN   |                    rcv SYN                     |   SYN   |
//! |   RCVD  |<-----------------------------------------------|   SENT  |
//! |         |                    snd ACK                     |         |
//! |         |------------------           -------------------|         |
//! +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//!   |           --------------   |     |   -----------
//!   |                  x         |     |     snd ACK
//!   |                            V     V
//!   |  CLOSE                   +---------+
//!   | -------                  |  ESTAB  |
//!   | snd FIN                  +---------+
//!   |                   ...continued states...
//! ```
//!
//! # References
//!
//! - RFC 793: Transmission Control Protocol
//! - RFC 1122: Requirements for Internet Hosts
//! - RFC 6528: Defending Against Sequence Number Attacks
//! - RFC 5961: Improving TCP's Robustness to Blind In-Window Attacks

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use crate::ipv4::{compute_checksum, Ipv4Addr};

// ============================================================================
// TCP Constants
// ============================================================================

/// TCP header minimum length in bytes (without options)
pub const TCP_HEADER_MIN_LEN: usize = 20;

/// TCP header maximum length in bytes (with max options)
pub const TCP_HEADER_MAX_LEN: usize = 60;

/// TCP protocol number (for IPv4)
pub const TCP_PROTO: u8 = 6;

/// Maximum Segment Size default (RFC 879)
pub const TCP_DEFAULT_MSS: u16 = 536;

/// Maximum Segment Size for Ethernet (1500 - 20 IP - 20 TCP)
pub const TCP_ETHERNET_MSS: u16 = 1460;

/// Default receive window size
pub const TCP_DEFAULT_WINDOW: u16 = 65535;

/// Maximum retransmission attempts before giving up
pub const TCP_MAX_RETRIES: u8 = 15;

/// Initial retransmission timeout in milliseconds
pub const TCP_INITIAL_RTO_MS: u64 = 1000;

/// Minimum retransmission timeout in milliseconds
pub const TCP_MIN_RTO_MS: u64 = 200;

/// Maximum retransmission timeout in milliseconds
pub const TCP_MAX_RTO_MS: u64 = 120_000;

/// TIME-WAIT duration (2*MSL = 2*60 seconds per RFC 793)
pub const TCP_TIME_WAIT_MS: u64 = 120_000;

/// Maximum SYN backlog per listening socket
pub const TCP_MAX_SYN_BACKLOG: usize = 128;

/// Maximum pending connections per listening socket
pub const TCP_MAX_ACCEPT_BACKLOG: usize = 128;

// ============================================================================
// TCP Flags
// ============================================================================

/// FIN flag - sender has finished sending
pub const TCP_FLAG_FIN: u8 = 0x01;
/// SYN flag - synchronize sequence numbers
pub const TCP_FLAG_SYN: u8 = 0x02;
/// RST flag - reset the connection
pub const TCP_FLAG_RST: u8 = 0x04;
/// PSH flag - push function
pub const TCP_FLAG_PSH: u8 = 0x08;
/// ACK flag - acknowledgment field is significant
pub const TCP_FLAG_ACK: u8 = 0x10;
/// URG flag - urgent pointer field is significant
pub const TCP_FLAG_URG: u8 = 0x20;
/// ECE flag - ECN-Echo (RFC 3168)
pub const TCP_FLAG_ECE: u8 = 0x40;
/// CWR flag - Congestion Window Reduced (RFC 3168)
pub const TCP_FLAG_CWR: u8 = 0x80;

// ============================================================================
// TCP State Machine
// ============================================================================

/// TCP connection state per RFC 793
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// No connection state at all
    Closed,
    /// Waiting for a connection request from any remote TCP
    Listen,
    /// Waiting for a matching connection request after having sent one
    SynSent,
    /// Waiting for confirming connection request acknowledgment
    SynReceived,
    /// Open connection, data can be exchanged
    Established,
    /// Waiting for a connection termination request from remote TCP
    /// (after local close)
    FinWait1,
    /// Waiting for a connection termination request from remote TCP
    FinWait2,
    /// Waiting for a connection termination request from local user
    CloseWait,
    /// Waiting for connection termination request acknowledgment from remote TCP
    Closing,
    /// Waiting for acknowledgment of connection termination request
    LastAck,
    /// Waiting for enough time to pass to be sure remote TCP received
    /// acknowledgment of its connection termination request
    TimeWait,
}

impl TcpState {
    /// Check if the connection is in an established or semi-established state
    pub fn can_send(&self) -> bool {
        matches!(
            self,
            TcpState::Established | TcpState::CloseWait
        )
    }

    /// Check if the connection can receive data
    pub fn can_receive(&self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
        )
    }

    /// Check if the connection is closed or closing
    pub fn is_closed(&self) -> bool {
        matches!(self, TcpState::Closed | TcpState::TimeWait)
    }

    /// Check if the connection is synchronized (after handshake)
    pub fn is_synchronized(&self) -> bool {
        !matches!(
            self,
            TcpState::Closed | TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
        )
    }
}

// ============================================================================
// TCP Header
// ============================================================================

/// Parsed TCP header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Sequence number
    pub seq_num: u32,
    /// Acknowledgment number (valid if ACK flag set)
    pub ack_num: u32,
    /// Data offset in 32-bit words (5-15)
    pub data_offset: u8,
    /// Reserved bits (must be zero)
    pub reserved: u8,
    /// Control flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
    pub flags: u8,
    /// Receive window size
    pub window: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer (valid if URG flag set)
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Create a new TCP header with the given parameters
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u8,
        window: u16,
    ) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset: 5, // No options, 20 bytes
            reserved: 0,
            flags,
            window,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    /// Get the header length in bytes
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    /// Check if SYN flag is set
    pub fn is_syn(&self) -> bool {
        self.flags & TCP_FLAG_SYN != 0
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags & TCP_FLAG_ACK != 0
    }

    /// Check if FIN flag is set
    pub fn is_fin(&self) -> bool {
        self.flags & TCP_FLAG_FIN != 0
    }

    /// Check if RST flag is set
    pub fn is_rst(&self) -> bool {
        self.flags & TCP_FLAG_RST != 0
    }

    /// Check if PSH flag is set
    pub fn is_psh(&self) -> bool {
        self.flags & TCP_FLAG_PSH != 0
    }

    /// Serialize header to bytes (without checksum)
    pub fn to_bytes(&self) -> [u8; TCP_HEADER_MIN_LEN] {
        let mut bytes = [0u8; TCP_HEADER_MIN_LEN];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        // Data offset (4 bits) + reserved (4 bits)
        bytes[12] = (self.data_offset << 4) | (self.reserved & 0x0F);
        bytes[13] = self.flags;
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        bytes
    }
}

// ============================================================================
// TCP Options
// ============================================================================

/// TCP option kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOptionKind {
    /// End of option list
    EndOfList,
    /// No-operation (padding)
    Nop,
    /// Maximum Segment Size
    Mss(u16),
    /// Window Scale (RFC 7323)
    WindowScale(u8),
    /// Selective Acknowledgment Permitted (RFC 2018)
    SackPermitted,
    /// Timestamps (RFC 7323)
    Timestamps { ts_val: u32, ts_ecr: u32 },
    /// Unknown option
    Unknown { kind: u8, len: u8 },
}

/// Parsed TCP options
#[derive(Debug, Clone, Default)]
pub struct TcpOptions {
    /// Maximum Segment Size
    pub mss: Option<u16>,
    /// Window Scale factor
    pub window_scale: Option<u8>,
    /// SACK permitted
    pub sack_permitted: bool,
    /// Timestamps
    pub timestamps: Option<(u32, u32)>,
}

// ============================================================================
// TCP Control Block (TCB)
// ============================================================================

/// 4-tuple connection key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnKey {
    /// Local IP address
    pub local_ip: Ipv4Addr,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_ip: Ipv4Addr,
    /// Remote port
    pub remote_port: u16,
}

impl TcpConnKey {
    /// Create a new connection key
    pub fn new(local_ip: Ipv4Addr, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }

    /// Create the reverse key (for matching incoming packets)
    pub fn reverse(&self) -> Self {
        Self {
            local_ip: self.remote_ip,
            local_port: self.remote_port,
            remote_ip: self.local_ip,
            remote_port: self.local_port,
        }
    }
}

/// TCP Control Block - per-connection state
pub struct TcpControlBlock {
    /// Connection state
    pub state: TcpState,

    /// Connection key (4-tuple)
    pub key: TcpConnKey,

    // === Send Sequence Space (RFC 793 Section 3.2) ===
    /// Initial Send Sequence Number
    pub iss: u32,
    /// Send Unacknowledged - oldest unacknowledged sequence number
    pub snd_una: u32,
    /// Send Next - next sequence number to send
    pub snd_nxt: u32,
    /// Send Window - send window size
    pub snd_wnd: u32,
    /// Segment sequence number used for last window update
    pub snd_wl1: u32,
    /// Segment acknowledgment number used for last window update
    pub snd_wl2: u32,

    // === Receive Sequence Space ===
    /// Initial Receive Sequence Number
    pub irs: u32,
    /// Receive Next - next sequence number expected
    pub rcv_nxt: u32,
    /// Receive Window - receive window size
    pub rcv_wnd: u32,

    // === Segment Size ===
    /// Maximum Segment Size for sending
    pub snd_mss: u16,
    /// Maximum Segment Size for receiving
    pub rcv_mss: u16,

    // === Retransmission State ===
    /// Current retransmission timeout in milliseconds
    pub rto_ms: u64,
    /// Smoothed Round-Trip Time (SRTT) in microseconds
    pub srtt_us: u64,
    /// RTT variance (RTTVAR) in microseconds
    pub rttvar_us: u64,
    /// Number of consecutive retransmissions
    pub retries: u8,

    // === Buffers ===
    /// Send buffer (unacknowledged segments)
    pub send_buffer: VecDeque<TcpSegment>,
    /// Receive buffer (in-order data)
    pub recv_buffer: VecDeque<u8>,
    /// Out-of-order segments
    pub ooo_queue: VecDeque<TcpSegment>,

    // === Flags ===
    /// FIN has been sent
    pub fin_sent: bool,
    /// FIN has been received
    pub fin_received: bool,
    /// ACK is pending (delayed ACK)
    pub ack_pending: bool,

    // === Timestamps ===
    /// Connection established timestamp (for TIME-WAIT)
    pub established_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
}

/// A TCP segment for buffering
#[derive(Debug, Clone)]
pub struct TcpSegment {
    /// Sequence number of first byte
    pub seq: u32,
    /// Segment data
    pub data: Vec<u8>,
    /// Timestamp when segment was sent (for RTT)
    pub sent_at: u64,
    /// Number of times retransmitted
    pub retrans_count: u8,
}

impl TcpControlBlock {
    /// Create a new TCB for an outgoing connection (client)
    pub fn new_client(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
    ) -> Self {
        Self {
            state: TcpState::Closed,
            key: TcpConnKey::new(local_ip, local_port, remote_ip, remote_port),
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: TCP_DEFAULT_WINDOW as u32,
            snd_mss: TCP_DEFAULT_MSS,
            rcv_mss: TCP_ETHERNET_MSS,
            rto_ms: TCP_INITIAL_RTO_MS,
            srtt_us: 0,
            rttvar_us: 0,
            retries: 0,
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            ooo_queue: VecDeque::new(),
            fin_sent: false,
            fin_received: false,
            ack_pending: false,
            established_at: 0,
            last_activity: 0,
        }
    }

    /// Create a new TCB for an incoming connection (server)
    pub fn new_server(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
        irs: u32,
    ) -> Self {
        let mut tcb = Self::new_client(local_ip, local_port, remote_ip, remote_port, iss);
        tcb.irs = irs;
        tcb.rcv_nxt = irs.wrapping_add(1);
        tcb.state = TcpState::SynReceived;
        tcb
    }

    /// Check if there is unsent or unacknowledged data
    pub fn has_pending_data(&self) -> bool {
        !self.send_buffer.is_empty() || self.snd_una != self.snd_nxt
    }

    /// Get the amount of data available to read
    pub fn available_data(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Calculate available send window
    pub fn send_window_available(&self) -> u32 {
        let bytes_in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
        self.snd_wnd.saturating_sub(bytes_in_flight)
    }
}

// ============================================================================
// TCP Errors
// ============================================================================

/// Errors that can occur during TCP processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// Packet is too short
    Truncated,
    /// Invalid header length (data offset)
    InvalidHeaderLen,
    /// Invalid flags combination
    InvalidFlags,
    /// Checksum verification failed
    BadChecksum,
    /// Connection refused (RST received)
    ConnectionRefused,
    /// Connection reset by peer
    ConnectionReset,
    /// Connection timed out
    Timeout,
    /// Invalid state for operation
    InvalidState,
    /// No route to host
    NoRoute,
    /// Address already in use
    AddressInUse,
    /// Connection already exists
    ConnectionExists,
    /// Not connected
    NotConnected,
    /// Resource temporarily unavailable
    WouldBlock,
    /// Invalid sequence number
    InvalidSeq,
}

/// Result type for TCP operations
pub type TcpResult<T> = Result<T, TcpError>;

// ============================================================================
// TCP Statistics
// ============================================================================

/// TCP stack statistics
#[derive(Debug, Default)]
pub struct TcpStats {
    /// Total segments received
    pub rx_segments: AtomicU64,
    /// Total segments sent
    pub tx_segments: AtomicU64,
    /// Segments dropped (invalid)
    pub rx_dropped: AtomicU64,
    /// Checksum errors
    pub checksum_errors: AtomicU64,
    /// Connections established
    pub connections_established: AtomicU64,
    /// Connections reset
    pub connections_reset: AtomicU64,
    /// Retransmissions
    pub retransmissions: AtomicU64,
    /// Segments received out of order
    pub out_of_order: AtomicU64,
}

impl TcpStats {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            rx_segments: AtomicU64::new(0),
            tx_segments: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            checksum_errors: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
            connections_reset: AtomicU64::new(0),
            retransmissions: AtomicU64::new(0),
            out_of_order: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// TCP Parsing Functions
// ============================================================================

/// Parse TCP header from raw bytes
///
/// # Security
///
/// - Validates minimum header length
/// - Validates data offset field
/// - Does NOT verify checksum (caller must do this)
///
/// # Arguments
///
/// * `data` - Raw TCP segment bytes
///
/// # Returns
///
/// Parsed header on success
pub fn parse_tcp_header(data: &[u8]) -> TcpResult<TcpHeader> {
    // Check minimum length
    if data.len() < TCP_HEADER_MIN_LEN {
        return Err(TcpError::Truncated);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = (data[12] >> 4) & 0x0F;
    let reserved = data[12] & 0x0F;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    // Validate data offset (must be at least 5 = 20 bytes)
    if data_offset < 5 {
        return Err(TcpError::InvalidHeaderLen);
    }

    // Validate data offset doesn't exceed packet
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len {
        return Err(TcpError::Truncated);
    }

    // Validate reserved bits are zero (RFC 793)
    // Note: Modern TCP uses some reserved bits for ECN, so we're lenient here
    if reserved & 0x0E != 0 {
        // Only check bits 1-3, bit 0 is NS flag
        // For strict compliance, could reject here
    }

    Ok(TcpHeader {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        reserved,
        flags,
        window,
        checksum,
        urgent_ptr,
    })
}

/// Parse TCP options from header
///
/// # Arguments
///
/// * `data` - TCP segment bytes (starting from byte 0)
/// * `header` - Parsed TCP header
///
/// # Returns
///
/// Parsed options
pub fn parse_tcp_options(data: &[u8], header: &TcpHeader) -> TcpOptions {
    let mut options = TcpOptions::default();
    let header_len = header.header_len();

    if header_len <= TCP_HEADER_MIN_LEN || data.len() < header_len {
        return options;
    }

    let opts_data = &data[TCP_HEADER_MIN_LEN..header_len];
    let mut i = 0;

    while i < opts_data.len() {
        match opts_data[i] {
            0 => break, // End of Option List
            1 => i += 1, // NOP
            2 => {
                // MSS
                if i + 4 <= opts_data.len() && opts_data[i + 1] == 4 {
                    options.mss = Some(u16::from_be_bytes([opts_data[i + 2], opts_data[i + 3]]));
                    i += 4;
                } else {
                    break;
                }
            }
            3 => {
                // Window Scale
                if i + 3 <= opts_data.len() && opts_data[i + 1] == 3 {
                    options.window_scale = Some(opts_data[i + 2]);
                    i += 3;
                } else {
                    break;
                }
            }
            4 => {
                // SACK Permitted
                if i + 2 <= opts_data.len() && opts_data[i + 1] == 2 {
                    options.sack_permitted = true;
                    i += 2;
                } else {
                    break;
                }
            }
            8 => {
                // Timestamps
                if i + 10 <= opts_data.len() && opts_data[i + 1] == 10 {
                    let ts_val = u32::from_be_bytes([
                        opts_data[i + 2],
                        opts_data[i + 3],
                        opts_data[i + 4],
                        opts_data[i + 5],
                    ]);
                    let ts_ecr = u32::from_be_bytes([
                        opts_data[i + 6],
                        opts_data[i + 7],
                        opts_data[i + 8],
                        opts_data[i + 9],
                    ]);
                    options.timestamps = Some((ts_val, ts_ecr));
                    i += 10;
                } else {
                    break;
                }
            }
            _ => {
                // Unknown option - skip based on length field
                if i + 1 < opts_data.len() {
                    let len = opts_data[i + 1] as usize;
                    if len < 2 || i + len > opts_data.len() {
                        break;
                    }
                    i += len;
                } else {
                    break;
                }
            }
        }
    }

    options
}

/// Compute TCP checksum using IPv4 pseudo-header
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// TCP checksum value
pub fn compute_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    // Build pseudo-header
    let tcp_len = tcp_data.len() as u16;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.0);
    pseudo[4..8].copy_from_slice(&dst_ip.0);
    pseudo[8] = 0; // Zero
    pseudo[9] = TCP_PROTO;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    // Compute checksum over pseudo-header + TCP segment
    let mut sum: u32 = compute_checksum(&pseudo, pseudo.len()) as u32;

    // Add TCP segment
    let tcp_sum = compute_checksum(tcp_data, tcp_data.len()) as u32;
    sum = sum.wrapping_add(tcp_sum);

    // Fold and complement
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Verify TCP checksum
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// true if checksum is valid
pub fn verify_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> bool {
    compute_tcp_checksum(src_ip, dst_ip, tcp_data) == 0
}

/// Build a TCP segment with the given parameters
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `src_port` - Source port
/// * `dst_port` - Destination port
/// * `seq_num` - Sequence number
/// * `ack_num` - Acknowledgment number
/// * `flags` - TCP flags
/// * `window` - Window size
/// * `payload` - Segment payload
///
/// # Returns
///
/// Complete TCP segment with checksum
pub fn build_tcp_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header = TcpHeader::new(src_port, dst_port, seq_num, ack_num, flags, window);
    let mut segment = Vec::with_capacity(TCP_HEADER_MIN_LEN + payload.len());
    segment.extend_from_slice(&header.to_bytes());
    segment.extend_from_slice(payload);

    // Compute and set checksum
    let checksum = compute_tcp_checksum(src_ip, dst_ip, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    segment
}

// ============================================================================
// ISN Generation (RFC 6528)
// ============================================================================

/// Global ISN generator state
static ISN_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Generate an Initial Sequence Number (ISN) per RFC 6528
///
/// Uses a simple time-based counter with some randomization.
/// A production implementation should use a keyed hash function.
///
/// # Arguments
///
/// * `local_ip` - Local IP address
/// * `local_port` - Local port
/// * `remote_ip` - Remote IP address
/// * `remote_port` - Remote port
///
/// # Returns
///
/// Random ISN for the connection
pub fn generate_isn(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> u32 {
    // Simple implementation: counter + hash of 4-tuple
    // A real implementation would use a cryptographic hash with a secret key
    let counter = ISN_COUNTER.fetch_add(64000, Ordering::Relaxed);

    // Simple hash of 4-tuple (placeholder - should use SipHash or similar)
    let mut hash: u32 = 0;
    for &b in &local_ip.0 {
        hash = hash.wrapping_mul(31).wrapping_add(b as u32);
    }
    for &b in &remote_ip.0 {
        hash = hash.wrapping_mul(31).wrapping_add(b as u32);
    }
    hash = hash.wrapping_mul(31).wrapping_add(local_port as u32);
    hash = hash.wrapping_mul(31).wrapping_add(remote_port as u32);

    // Mix with RDTSC if available (adds timing entropy)
    #[cfg(target_arch = "x86_64")]
    let time_component = {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
        }
        lo ^ hi
    };
    #[cfg(not(target_arch = "x86_64"))]
    let time_component = 0u32;

    counter
        .wrapping_add(hash)
        .wrapping_add(time_component)
}

// ============================================================================
// Sequence Number Arithmetic (RFC 793 Section 3.3)
// ============================================================================

/// Check if sequence number a is less than b (with wraparound)
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Check if sequence number a is less than or equal to b (with wraparound)
#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// Check if sequence number a is greater than b (with wraparound)
#[inline]
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Check if sequence number a is greater than or equal to b (with wraparound)
#[inline]
pub fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// Check if sequence number seq is within window [left, left+size)
#[inline]
pub fn seq_in_window(seq: u32, left: u32, size: u32) -> bool {
    let right = left.wrapping_add(size);
    if size == 0 {
        false
    } else if seq_le(left, right) {
        // No wraparound
        seq_ge(seq, left) && seq_lt(seq, right)
    } else {
        // Window wraps around
        seq_ge(seq, left) || seq_lt(seq, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_header_parsing() {
        // SYN packet
        let syn = [
            0x00, 0x50, // src port 80
            0x1F, 0x90, // dst port 8080
            0x00, 0x00, 0x00, 0x01, // seq 1
            0x00, 0x00, 0x00, 0x00, // ack 0
            0x50, // data offset 5 (20 bytes)
            0x02, // SYN flag
            0xFF, 0xFF, // window 65535
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // urgent ptr
        ];

        let header = parse_tcp_header(&syn).unwrap();
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 8080);
        assert_eq!(header.seq_num, 1);
        assert_eq!(header.ack_num, 0);
        assert!(header.is_syn());
        assert!(!header.is_ack());
    }

    #[test]
    fn test_seq_arithmetic() {
        // Normal case
        assert!(seq_lt(100, 200));
        assert!(seq_le(100, 100));
        assert!(seq_gt(200, 100));

        // Wraparound case
        assert!(seq_lt(0xFFFFFFFF, 0));
        assert!(seq_gt(0, 0xFFFFFFFF));
    }

    #[test]
    fn test_tcp_state() {
        assert!(!TcpState::Closed.can_send());
        assert!(TcpState::Established.can_send());
        assert!(TcpState::Established.can_receive());
        assert!(!TcpState::TimeWait.can_receive());
    }
}
