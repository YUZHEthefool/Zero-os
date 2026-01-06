//! Network protocol stack for Zero-OS (Phase D.2)
//!
//! This module provides the main packet processing loop that integrates
//! all protocol layers (Ethernet, IPv4, ICMP).
//!
//! # Architecture
//!
//! ```text
//!                     +------------------+
//!                     |   NetDevice      |
//!                     | (virtio-net)     |
//!                     +--------+---------+
//!                              |
//!                     +--------v---------+
//!                     |   Ethernet       |
//!                     |   (parse/build)  |
//!                     +--------+---------+
//!                              |
//!              +---------------+---------------+
//!              |                               |
//!     +--------v---------+           +---------v--------+
//!     |     IPv4         |           |      ARP         |
//!     | (validate/route) |           |   (future)       |
//!     +--------+---------+           +------------------+
//!              |
//!     +--------v---------+
//!     |     ICMP         |
//!     |  (echo reply)    |
//!     +------------------+
//! ```
//!
//! # Security
//!
//! - All packet parsing uses strict validation
//! - ICMP responses are rate-limited
//! - Source routing is rejected
//! - Broadcast/multicast sources are rejected

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::buffer::NetBuf;
use crate::ethernet::{parse_ethernet, build_ethernet_frame, EthAddr, EthHeader, ETHERTYPE_IPV4};
use crate::icmp::{build_echo_reply, parse_icmp, IcmpError, ICMP_RATE_LIMITER, ICMP_TYPE_ECHO_REQUEST};
use crate::ipv4::{build_ipv4_header, parse_ipv4, Ipv4Addr, Ipv4Error, Ipv4Header, Ipv4Proto};

// ============================================================================
// Statistics
// ============================================================================

/// Network stack statistics
#[derive(Debug, Default)]
pub struct NetStats {
    /// Total packets received
    pub rx_packets: AtomicU64,
    /// Packets dropped due to parsing errors
    pub rx_errors: AtomicU64,
    /// IPv4 packets received
    pub ipv4_rx: AtomicU64,
    /// ICMP packets received
    pub icmp_rx: AtomicU64,
    /// ICMP echo requests received
    pub icmp_echo_rx: AtomicU64,
    /// ICMP echo replies sent
    pub icmp_echo_tx: AtomicU64,
    /// Packets dropped by rate limiter
    pub rate_limited: AtomicU64,
    /// Packets dropped due to unsupported protocol
    pub unsupported_proto: AtomicU64,
}

impl NetStats {
    /// Create new stats counter
    pub const fn new() -> Self {
        NetStats {
            rx_packets: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            ipv4_rx: AtomicU64::new(0),
            icmp_rx: AtomicU64::new(0),
            icmp_echo_rx: AtomicU64::new(0),
            icmp_echo_tx: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            unsupported_proto: AtomicU64::new(0),
        }
    }

    #[inline]
    fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_ipv4_rx(&self) {
        self.ipv4_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_rx(&self) {
        self.icmp_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_echo_rx(&self) {
        self.icmp_echo_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_echo_tx(&self) {
        self.icmp_echo_tx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_unsupported_proto(&self) {
        self.unsupported_proto.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Packet Processing Result
// ============================================================================

/// Result of processing an incoming packet
#[derive(Debug)]
pub enum ProcessResult {
    /// Packet was handled, no response needed
    Handled,
    /// Packet requires a response to be sent
    Reply(Vec<u8>),
    /// Packet was dropped with reason
    Dropped(DropReason),
}

/// Reason for dropping a packet
#[derive(Debug, Clone, Copy)]
pub enum DropReason {
    /// Ethernet frame parsing failed
    EthParseError,
    /// IPv4 parsing/validation failed
    Ipv4Error(Ipv4Error),
    /// ICMP parsing failed
    IcmpError(IcmpError),
    /// Unsupported EtherType
    UnsupportedEtherType,
    /// Unsupported IP protocol
    UnsupportedProtocol,
    /// Rate limited
    RateLimited,
}

// ============================================================================
// Packet Handler
// ============================================================================

/// Process an incoming Ethernet frame.
///
/// This is the main entry point for packet processing. It:
/// 1. Parses the Ethernet header
/// 2. Validates the frame is addressed to us (unicast or broadcast)
/// 3. Routes to the appropriate protocol handler (IPv4, ARP, etc.)
/// 4. Returns any response packet that should be sent
///
/// # Security
///
/// - Only processes frames addressed to our MAC or broadcast
/// - Silently drops frames to other destinations (no error logged)
///
/// # Arguments
/// * `frame` - Raw Ethernet frame bytes
/// * `our_mac` - Our MAC address (for filtering and responses)
/// * `our_ip` - Our IP address (for filtering and responses)
/// * `stats` - Statistics counters
/// * `now_ms` - Current time in milliseconds (for rate limiting)
///
/// # Returns
/// `ProcessResult` indicating what action to take
pub fn process_frame(
    frame: &[u8],
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    now_ms: u64,
) -> ProcessResult {
    stats.inc_rx_packets();

    // Parse Ethernet header
    let (eth_hdr, eth_payload) = match parse_ethernet(frame) {
        Ok(result) => result,
        Err(_) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::EthParseError);
        }
    };

    // MAC filtering: only accept frames addressed to us or broadcast
    // This prevents processing stray traffic and reflection attacks
    if eth_hdr.dst != our_mac && !eth_hdr.dst.is_broadcast() {
        // Not for us - silently drop without incrementing error counter
        return ProcessResult::Handled;
    }

    // Route to protocol handler
    match eth_hdr.ethertype {
        ETHERTYPE_IPV4 => {
            process_ipv4(eth_payload, &eth_hdr, our_mac, our_ip, stats, now_ms)
        }
        // TODO: Add ARP handling
        _ => {
            stats.inc_unsupported_proto();
            ProcessResult::Dropped(DropReason::UnsupportedEtherType)
        }
    }
}

/// Process an IPv4 packet.
fn process_ipv4(
    packet: &[u8],
    eth_hdr: &EthHeader,
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    now_ms: u64,
) -> ProcessResult {
    stats.inc_ipv4_rx();

    // Parse and validate IPv4 header
    let (ip_hdr, _options, payload) = match parse_ipv4(packet) {
        Ok(result) => result,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::Ipv4Error(e));
        }
    };

    // Check if packet is destined for us (unicast only for responses)
    // Security: We accept broadcast for informational purposes but will NOT
    // generate responses to broadcast destinations (Smurf attack prevention)
    let is_broadcast_dst = ip_hdr.dst.is_broadcast();
    if ip_hdr.dst != our_ip && !is_broadcast_dst {
        // Not for us, silently drop (no error)
        return ProcessResult::Handled;
    }

    // Don't respond to fragments (we don't do reassembly yet)
    if ip_hdr.is_fragment() {
        return ProcessResult::Handled;
    }

    // Route to protocol handler
    match ip_hdr.proto() {
        Some(Ipv4Proto::Icmp) => {
            // Pass broadcast flag to ICMP handler for response suppression
            process_icmp(payload, &ip_hdr, eth_hdr, our_mac, our_ip, stats, now_ms, is_broadcast_dst)
        }
        Some(Ipv4Proto::Tcp) | Some(Ipv4Proto::Udp) => {
            // TODO: TCP/UDP handling
            stats.inc_unsupported_proto();
            ProcessResult::Dropped(DropReason::UnsupportedProtocol)
        }
        None => {
            stats.inc_unsupported_proto();
            ProcessResult::Dropped(DropReason::UnsupportedProtocol)
        }
    }
}

/// Process an ICMP packet.
///
/// # Security
///
/// - Does NOT respond to echo requests sent to broadcast/multicast IP addresses
///   (Smurf attack prevention per RFC 1122 section 3.2.2.6)
/// - Rate limits all ICMP responses
fn process_icmp(
    packet: &[u8],
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    now_ms: u64,
    is_broadcast_dst: bool,
) -> ProcessResult {
    stats.inc_icmp_rx();

    // Parse ICMP header
    let (icmp_hdr, _payload) = match parse_icmp(packet) {
        Ok(result) => result,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::IcmpError(e));
        }
    };

    // Handle echo request (ping)
    if icmp_hdr.icmp_type == ICMP_TYPE_ECHO_REQUEST {
        stats.inc_icmp_echo_rx();

        // SECURITY: Never respond to echo requests sent to broadcast/multicast
        // This prevents Smurf attacks (RFC 1122 section 3.2.2.6)
        if is_broadcast_dst {
            return ProcessResult::Handled;
        }

        // Also check if destination MAC was broadcast (belt and suspenders)
        if eth_hdr.dst.is_broadcast() || eth_hdr.dst.is_multicast() {
            return ProcessResult::Handled;
        }

        // Rate limit ICMP responses
        if !ICMP_RATE_LIMITER.allow(now_ms) {
            stats.inc_rate_limited();
            return ProcessResult::Dropped(DropReason::RateLimited);
        }

        // Build ICMP echo reply
        let icmp_reply = match build_echo_reply(packet) {
            Ok(reply) => reply,
            Err(e) => {
                stats.inc_rx_errors();
                return ProcessResult::Dropped(DropReason::IcmpError(e));
            }
        };

        // Build IPv4 header (swap src/dst)
        let ip_reply = build_ipv4_header(
            our_ip,          // Our IP as source
            ip_hdr.src,      // Original source as destination
            Ipv4Proto::Icmp,
            icmp_reply.len() as u16,
            64,              // Default TTL
        );

        // Combine IP header and ICMP reply
        let mut ip_packet = Vec::with_capacity(ip_reply.len() + icmp_reply.len());
        ip_packet.extend_from_slice(&ip_reply);
        ip_packet.extend_from_slice(&icmp_reply);

        // Build Ethernet frame (swap src/dst MACs)
        let frame = build_ethernet_frame(
            eth_hdr.src,     // Original source as destination
            our_mac,         // Our MAC as source
            ETHERTYPE_IPV4,
            &ip_packet,
        );

        stats.inc_icmp_echo_tx();
        return ProcessResult::Reply(frame);
    }

    // Other ICMP types are just handled (logged but no response)
    ProcessResult::Handled
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_atomic() {
        let stats = NetStats::new();
        stats.inc_rx_packets();
        stats.inc_rx_packets();
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 2);
    }
}
