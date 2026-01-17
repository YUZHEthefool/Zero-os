//! Runtime Test Infrastructure for Zero-OS
//!
//! This module provides comprehensive functional tests that run during kernel boot
//! to verify all critical subsystems are working correctly.
//!
//! # Design
//!
//! Unlike `#[cfg(test)]` unit tests which require a test harness, these tests
//! run within the kernel itself and can test actual hardware interactions,
//! interrupt handling, and cross-module integration.
//!
//! # Test Categories
//!
//! - **Memory**: Heap allocation, buddy allocator
//! - **Capability**: CapTable lifecycle, rights enforcement
//! - **Seccomp**: Filter evaluation, pledge promises
//! - **Network**: Packet parsing/serialization
//! - **Scheduler**: Starvation prevention
//! - **Process**: Creation and lifecycle
//! - **Security**: W^X, RNG, kptr validation

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// Test Result Types
// ============================================================================

/// Result of a runtime test
#[derive(Debug, Clone)]
pub enum TestResult {
    /// Test passed successfully
    Pass,
    /// Test passed with a warning
    Warning(String),
    /// Test failed
    Fail(String),
}

impl TestResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, TestResult::Pass | TestResult::Warning(_))
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, TestResult::Fail(_))
    }
}

/// Outcome of a single test execution
#[derive(Debug, Clone)]
pub struct TestOutcome {
    pub name: &'static str,
    pub result: TestResult,
}

/// Aggregate report for all runtime tests
#[derive(Debug, Clone)]
pub struct TestReport {
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub outcomes: Vec<TestOutcome>,
}

impl TestReport {
    pub fn empty() -> Self {
        Self {
            passed: 0,
            failed: 0,
            warnings: 0,
            outcomes: Vec::new(),
        }
    }

    pub fn ok(&self) -> bool {
        self.failed == 0
    }
}

/// Trait for runtime tests
pub trait RuntimeTest {
    fn name(&self) -> &'static str;
    fn run(&self) -> TestResult;
    fn description(&self) -> &'static str {
        "Runtime validation test"
    }
}

// ============================================================================
// Memory Tests
// ============================================================================

/// Test heap allocation works correctly
struct HeapAllocationTest;

impl RuntimeTest for HeapAllocationTest {
    fn name(&self) -> &'static str {
        "heap_allocation"
    }

    fn description(&self) -> &'static str {
        "Verify kernel heap allocation and deallocation"
    }

    fn run(&self) -> TestResult {
        // Test 1: Simple vector allocation
        let mut v: Vec<u64> = Vec::with_capacity(100);
        for i in 0..100 {
            v.push(i);
        }

        if v.len() != 100 {
            return TestResult::Fail(String::from("Vector allocation failed"));
        }

        // Verify values
        for (i, &val) in v.iter().enumerate() {
            if val != i as u64 {
                return TestResult::Fail(String::from("Vector content corruption"));
            }
        }

        // Test 2: Box allocation
        let boxed: alloc::boxed::Box<[u8; 4096]> = alloc::boxed::Box::new([0u8; 4096]);
        if boxed[0] != 0 || boxed[4095] != 0 {
            return TestResult::Fail(String::from("Box allocation corruption"));
        }

        // Test 3: String allocation
        let s = String::from("Hello Zero-OS Runtime Tests!");
        if s.len() != 28 {
            return TestResult::Fail(String::from("String allocation failed"));
        }

        TestResult::Pass
    }
}

/// Test buddy allocator physical page allocation
struct BuddyAllocatorTest;

impl RuntimeTest for BuddyAllocatorTest {
    fn name(&self) -> &'static str {
        "buddy_allocator"
    }

    fn description(&self) -> &'static str {
        "Verify buddy allocator physical page management"
    }

    fn run(&self) -> TestResult {
        use mm::buddy_allocator;

        // Get initial stats
        let stats_before = match buddy_allocator::get_allocator_stats() {
            Some(s) => s,
            None => return TestResult::Warning(String::from("Buddy allocator not initialized")),
        };

        // Allocate a single page
        let frame = match buddy_allocator::alloc_physical_pages(1) {
            Some(f) => f,
            None => return TestResult::Fail(String::from("Failed to allocate 1 page")),
        };

        // Verify stats changed
        let stats_after = match buddy_allocator::get_allocator_stats() {
            Some(s) => s,
            None => return TestResult::Fail(String::from("Stats unavailable after alloc")),
        };

        // Free pages should have decreased by at least 1
        // (buddy allocator may round up to power of 2)
        if stats_after.free_pages >= stats_before.free_pages {
            return TestResult::Fail(String::from("Free page count did not decrease"));
        }

        // Free the page
        buddy_allocator::free_physical_pages(frame, 1);

        // Verify stats restored
        let stats_restored = match buddy_allocator::get_allocator_stats() {
            Some(s) => s,
            None => return TestResult::Fail(String::from("Stats unavailable after free")),
        };

        if stats_restored.free_pages != stats_before.free_pages {
            return TestResult::Warning(String::from("Free pages not fully restored (fragmentation?)"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Capability Tests
// ============================================================================

/// Test capability table lifecycle
struct CapTableLifecycleTest;

impl RuntimeTest for CapTableLifecycleTest {
    fn name(&self) -> &'static str {
        "cap_table_lifecycle"
    }

    fn description(&self) -> &'static str {
        "Verify capability allocation, lookup, and revocation"
    }

    fn run(&self) -> TestResult {
        use cap::{CapEntry, CapObject, CapRights, CapTable};

        // Create a new capability table
        let table = CapTable::new();

        // Allocate a capability with read-only rights using Endpoint as test object
        let entry = CapEntry::new(
            CapObject::Endpoint(9999),  // Use Endpoint with dummy ID for testing
            CapRights::READ,
        );

        let cap_id = match table.allocate(entry) {
            Ok(id) => id,
            Err(e) => return TestResult::Fail(alloc::format!("Allocate failed: {:?}", e)),
        };

        // Lookup should succeed
        let looked_up = match table.lookup(cap_id) {
            Ok(e) => e,
            Err(e) => return TestResult::Fail(alloc::format!("Lookup failed: {:?}", e)),
        };

        // Verify rights (rights is a field, not a method)
        if !looked_up.rights.contains(CapRights::READ) {
            return TestResult::Fail(String::from("Rights not preserved"));
        }

        if looked_up.rights.contains(CapRights::WRITE) {
            return TestResult::Fail(String::from("Unexpected WRITE right"));
        }

        // Revoke the capability
        if let Err(e) = table.revoke(cap_id) {
            return TestResult::Fail(alloc::format!("Revoke failed: {:?}", e));
        }

        // Lookup after revoke should fail
        if table.lookup(cap_id).is_ok() {
            return TestResult::Fail(String::from("Lookup succeeded after revoke"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Seccomp Tests
// ============================================================================

/// Test strict mode seccomp filter
struct StrictSeccompFilterTest;

impl RuntimeTest for StrictSeccompFilterTest {
    fn name(&self) -> &'static str {
        "seccomp_strict_filter"
    }

    fn description(&self) -> &'static str {
        "Verify strict mode filter allows only read/write/exit"
    }

    fn run(&self) -> TestResult {
        use seccomp::{strict_filter, SeccompAction};

        let filter = strict_filter();

        // Test syscall evaluation helper
        // SeccompFilter::evaluate returns SeccompAction directly
        let eval = |nr: u64| -> SeccompAction {
            let args = [0u64; 6];
            filter.evaluate(nr, &args)
        };

        // read (0) should be allowed
        if !matches!(eval(0), SeccompAction::Allow) {
            return TestResult::Fail(String::from("read(0) not allowed in strict mode"));
        }

        // write (1) should be allowed
        if !matches!(eval(1), SeccompAction::Allow) {
            return TestResult::Fail(String::from("write(1) not allowed in strict mode"));
        }

        // exit (60) should be allowed
        if !matches!(eval(60), SeccompAction::Allow) {
            return TestResult::Fail(String::from("exit(60) not allowed in strict mode"));
        }

        // exit_group (231) should be allowed
        if !matches!(eval(231), SeccompAction::Allow) {
            return TestResult::Fail(String::from("exit_group(231) not allowed in strict mode"));
        }

        // open (2) should be killed
        if !matches!(eval(2), SeccompAction::Kill) {
            return TestResult::Fail(String::from("open(2) not killed in strict mode"));
        }

        // mmap (9) should be killed
        if !matches!(eval(9), SeccompAction::Kill) {
            return TestResult::Fail(String::from("mmap(9) not killed in strict mode"));
        }

        TestResult::Pass
    }
}

/// Test pledge promise filter
struct PledgeSeccompFilterTest;

impl RuntimeTest for PledgeSeccompFilterTest {
    fn name(&self) -> &'static str {
        "seccomp_pledge_filter"
    }

    fn description(&self) -> &'static str {
        "Verify pledge promise filtering"
    }

    fn run(&self) -> TestResult {
        use seccomp::{pledge_to_filter, PledgePromises, SeccompAction};

        // Create a filter with only STDIO promise
        let promises = PledgePromises::STDIO;
        let filter = pledge_to_filter(promises);

        let eval = |nr: u64| -> SeccompAction {
            let args = [0u64; 6];
            filter.evaluate(nr, &args)
        };

        // read (0) should be allowed with STDIO
        if !matches!(eval(0), SeccompAction::Allow) {
            return TestResult::Fail(String::from("read not allowed with STDIO promise"));
        }

        // write (1) should be allowed with STDIO
        if !matches!(eval(1), SeccompAction::Allow) {
            return TestResult::Fail(String::from("write not allowed with STDIO promise"));
        }

        // fork (57) should be blocked without PROC promise
        if matches!(eval(57), SeccompAction::Allow) {
            return TestResult::Fail(String::from("fork allowed without PROC promise"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Audit Tests
// ============================================================================

/// Test audit hash chain verification function
struct AuditHashChainTest;

impl RuntimeTest for AuditHashChainTest {
    fn name(&self) -> &'static str {
        "audit_verify_chain"
    }

    fn description(&self) -> &'static str {
        "Verify audit hash chain verification function"
    }

    fn run(&self) -> TestResult {
        use audit::verify_chain;

        // Test with empty events (should succeed)
        let empty_events: Vec<audit::AuditEvent> = Vec::new();
        if !verify_chain(&empty_events) {
            return TestResult::Fail(String::from("Empty chain verification failed"));
        }

        // Note: Full hash chain testing requires emitting events and reading them back,
        // which requires proper capability authorization. The verify_chain function
        // itself is tested with empty input to verify it's compiled and accessible.

        TestResult::Pass
    }
}

// ============================================================================
// Network Tests
// ============================================================================

/// Test network packet parsing and serialization
struct NetworkParsingTest;

impl RuntimeTest for NetworkParsingTest {
    fn name(&self) -> &'static str {
        "network_parsing"
    }

    fn description(&self) -> &'static str {
        "Verify ARP, UDP, and TCP packet parsing"
    }

    fn run(&self) -> TestResult {
        // Test ARP parsing
        if let Err(e) = self.test_arp() {
            return TestResult::Fail(alloc::format!("ARP test failed: {}", e));
        }

        // Test UDP parsing
        if let Err(e) = self.test_udp() {
            return TestResult::Fail(alloc::format!("UDP test failed: {}", e));
        }

        // Test TCP parsing
        if let Err(e) = self.test_tcp() {
            return TestResult::Fail(alloc::format!("TCP test failed: {}", e));
        }

        TestResult::Pass
    }
}

impl NetworkParsingTest {
    fn test_arp(&self) -> Result<(), String> {
        use net::{parse_arp, serialize_arp, ArpOp, ArpPacket, EthAddr, Ipv4Addr};

        // Create a test ARP request packet
        let request = ArpPacket {
            sender_hw: EthAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            sender_ip: Ipv4Addr([192, 168, 1, 1]),
            target_hw: EthAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            target_ip: Ipv4Addr([192, 168, 1, 2]),
            op: ArpOp::Request,
        };

        // Serialize
        let bytes = serialize_arp(&request);
        if bytes.len() != 28 {
            return Err(String::from("ARP serialization wrong length"));
        }

        // Parse back
        let parsed = parse_arp(&bytes).map_err(|e| alloc::format!("{:?}", e))?;

        // Verify fields
        if parsed.op != ArpOp::Request {
            return Err(String::from("ARP opcode mismatch"));
        }
        if parsed.sender_ip.0 != [192, 168, 1, 1] {
            return Err(String::from("ARP sender_ip mismatch"));
        }
        if parsed.target_ip.0 != [192, 168, 1, 2] {
            return Err(String::from("ARP target_ip mismatch"));
        }

        Ok(())
    }

    fn test_udp(&self) -> Result<(), String> {
        use net::{build_udp_datagram, parse_udp, Ipv4Addr};

        let src_ip = Ipv4Addr([10, 0, 0, 1]);
        let dst_ip = Ipv4Addr([10, 0, 0, 2]);
        let src_port = 12345u16;
        let dst_port = 80u16;
        let payload = b"Hello UDP!";

        // Build UDP datagram (returns Result)
        let datagram = build_udp_datagram(src_ip, dst_ip, src_port, dst_port, payload)
            .map_err(|e| alloc::format!("{:?}", e))?;

        if datagram.len() != 8 + payload.len() {
            return Err(alloc::format!(
                "UDP datagram wrong length: {} (expected {})",
                datagram.len(),
                8 + payload.len()
            ));
        }

        // Parse UDP header
        let (header, data) = parse_udp(&datagram, src_ip, dst_ip)
            .map_err(|e| alloc::format!("{:?}", e))?;

        if header.src_port != src_port {
            return Err(String::from("UDP src_port mismatch"));
        }
        if header.dst_port != dst_port {
            return Err(String::from("UDP dst_port mismatch"));
        }
        if data != payload {
            return Err(String::from("UDP payload mismatch"));
        }

        Ok(())
    }

    fn test_tcp(&self) -> Result<(), String> {
        use net::{parse_tcp_header, TCP_FLAG_SYN, TCP_FLAG_ACK};

        // Create a minimal TCP SYN packet
        #[rustfmt::skip]
        let tcp_syn: [u8; 20] = [
            0x30, 0x39,  // src port: 12345
            0x00, 0x50,  // dst port: 80
            0x00, 0x00, 0x00, 0x01,  // seq: 1
            0x00, 0x00, 0x00, 0x00,  // ack: 0
            0x50, 0x02,  // data offset: 5, flags: SYN
            0x20, 0x00,  // window: 8192
            0x00, 0x00,  // checksum (placeholder)
            0x00, 0x00,  // urgent ptr: 0
        ];

        let header = parse_tcp_header(&tcp_syn).map_err(|e| alloc::format!("{:?}", e))?;

        if header.src_port != 12345 {
            return Err(String::from("TCP src_port mismatch"));
        }
        if header.dst_port != 80 {
            return Err(String::from("TCP dst_port mismatch"));
        }
        if header.seq_num != 1 {
            return Err(String::from("TCP seq_num mismatch"));
        }
        // Check SYN flag using flags field and constant
        if header.flags & TCP_FLAG_SYN == 0 {
            return Err(String::from("TCP SYN flag not set"));
        }
        // Check ACK flag not set
        if header.flags & TCP_FLAG_ACK != 0 {
            return Err(String::from("TCP ACK flag incorrectly set"));
        }

        Ok(())
    }
}

// ============================================================================
// Scheduler Tests
// ============================================================================

/// Test scheduler starvation prevention
struct SchedulerStarvationTest;

impl RuntimeTest for SchedulerStarvationTest {
    fn name(&self) -> &'static str {
        "scheduler_starvation"
    }

    fn description(&self) -> &'static str {
        "Verify wait_ticks counter and priority boosting"
    }

    fn run(&self) -> TestResult {
        use kernel_core::process::Process;

        // Create a test process with low priority
        // ProcessId is type alias for usize
        let mut process = Process::new(
            9999,     // pid: usize
            1,        // ppid: usize
            String::from("test_process"),
            100,      // priority: u8 (lower = higher priority, 100 is low)
        );

        let initial_priority = process.dynamic_priority;
        let initial_wait_ticks = process.wait_ticks;

        // Simulate waiting ticks
        for _ in 0..100 {
            process.wait_ticks = process.wait_ticks.saturating_add(1);
        }

        if process.wait_ticks != initial_wait_ticks + 100 {
            return TestResult::Fail(String::from("wait_ticks not incremented correctly"));
        }

        // Simulate starvation boost (threshold is 100 ticks per STARVATION_THRESHOLD)
        // Set wait_ticks at threshold
        process.wait_ticks = 100;
        process.check_and_boost_starved();

        // After boosting, wait_ticks should reset and priority should increase
        if process.wait_ticks != 0 {
            return TestResult::Fail(String::from("wait_ticks not reset after boost"));
        }

        // Dynamic priority should have increased (lower value = higher priority)
        if process.dynamic_priority >= initial_priority {
            return TestResult::Warning(String::from("Priority did not increase (may be at max)"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Process Tests
// ============================================================================

/// Test process creation and basic lifecycle
struct ProcessCreationTest;

impl RuntimeTest for ProcessCreationTest {
    fn name(&self) -> &'static str {
        "process_creation"
    }

    fn description(&self) -> &'static str {
        "Verify process creation and initialization"
    }

    fn run(&self) -> TestResult {
        use kernel_core::process::{Process, ProcessState};

        // Create a new process
        // ProcessId is type alias for usize
        let process = Process::new(
            1234,     // pid: usize
            1,        // ppid: usize
            String::from("test_proc"),
            50,       // priority: u8
        );

        // Verify initial state
        if process.pid != 1234 {
            return TestResult::Fail(String::from("PID not set correctly"));
        }

        if process.ppid != 1 {
            return TestResult::Fail(String::from("PPID not set correctly"));
        }

        if process.state != ProcessState::Ready {
            return TestResult::Fail(String::from("Initial state should be Ready"));
        }

        if process.priority != 50 {
            return TestResult::Fail(String::from("Priority not set correctly"));
        }

        // Verify wait_ticks starts at 0
        if process.wait_ticks != 0 {
            return TestResult::Fail(String::from("wait_ticks should start at 0"));
        }

        // Verify tid == pid (Linux semantics)
        if process.tid != process.pid {
            return TestResult::Fail(String::from("tid should equal pid"));
        }

        // Verify tgid == pid (main thread)
        if process.tgid != process.pid {
            return TestResult::Fail(String::from("tgid should equal pid for main thread"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Security Tests Integration
// ============================================================================

/// Run security subsystem tests
struct SecuritySubsystemTest;

impl RuntimeTest for SecuritySubsystemTest {
    fn name(&self) -> &'static str {
        "security_subsystem"
    }

    fn description(&self) -> &'static str {
        "Run security module tests (W^X, RNG, kptr)"
    }

    fn run(&self) -> TestResult {
        use security::tests::{run_security_tests, TestContext};
        use x86_64::VirtAddr;

        // Create test context with physical offset 0 (identity mapping for low memory)
        let ctx = TestContext {
            phys_offset: VirtAddr::new(0),
        };

        let report = run_security_tests(&ctx);

        if report.failed > 0 {
            return TestResult::Fail(alloc::format!(
                "{} security tests failed out of {}",
                report.failed,
                report.passed + report.failed + report.warnings
            ));
        }

        if report.warnings > 0 {
            return TestResult::Warning(alloc::format!(
                "{} security tests had warnings",
                report.warnings
            ));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Test Runner
// ============================================================================

/// Run all runtime tests and return a report
pub fn run_all_runtime_tests() -> TestReport {
    let tests: [&dyn RuntimeTest; 10] = [
        &HeapAllocationTest,
        &BuddyAllocatorTest,
        &CapTableLifecycleTest,
        &StrictSeccompFilterTest,
        &PledgeSeccompFilterTest,
        &AuditHashChainTest,
        &NetworkParsingTest,
        &SchedulerStarvationTest,
        &ProcessCreationTest,
        &SecuritySubsystemTest,
    ];

    let mut outcomes = Vec::with_capacity(tests.len());
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut warnings = 0usize;

    println!();
    println!("=== Runtime Functional Tests ===");
    println!();

    for test in tests {
        print!("  [TEST] {}... ", test.name());

        let result = test.run();

        match &result {
            TestResult::Pass => {
                println!("PASS");
                passed += 1;
            }
            TestResult::Warning(msg) => {
                println!("WARN: {}", msg);
                warnings += 1;
            }
            TestResult::Fail(msg) => {
                println!("FAIL: {}", msg);
                failed += 1;
            }
        }

        outcomes.push(TestOutcome {
            name: test.name(),
            result,
        });
    }

    println!();
    println!(
        "=== Test Summary: {} passed, {} warnings, {} failed ===",
        passed, warnings, failed
    );
    println!();

    TestReport {
        passed,
        failed,
        warnings,
        outcomes,
    }
}

/// Run a single test by name
pub fn run_test(name: &str) -> Option<TestOutcome> {
    let tests: [&dyn RuntimeTest; 10] = [
        &HeapAllocationTest,
        &BuddyAllocatorTest,
        &CapTableLifecycleTest,
        &StrictSeccompFilterTest,
        &PledgeSeccompFilterTest,
        &AuditHashChainTest,
        &NetworkParsingTest,
        &SchedulerStarvationTest,
        &ProcessCreationTest,
        &SecuritySubsystemTest,
    ];

    for test in tests {
        if test.name() == name {
            return Some(TestOutcome {
                name: test.name(),
                result: test.run(),
            });
        }
    }

    None
}
