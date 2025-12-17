# Zero-OS Enterprise Security Kernel Roadmap

**Version:** 2.0
**Last Updated:** 2025-12-11
**Design Principle:** Security > Efficiency > Speed

This document extends the Zero-OS development roadmap toward an **enterprise-grade secure server kernel**, comparable to Linux and Windows Server in capability while prioritizing security-first design.

---

## Executive Summary

### Vision

Zero-OS aims to be an enterprise-grade server kernel with:
- **Defense in Depth**: Multiple security layers (Capability, MAC, DAC, Audit)
- **Memory Safety**: Rust + hardware protections (SMAP/SMEP/NX/W^X)
- **Process Isolation**: Strong address space separation with COW
- **Secure IPC**: Capability-based access control for all kernel objects
- **Compliance Ready**: Comprehensive audit logging with tamper evidence

### Current Status (as of 2025-12-16)

| Component | Status | Security Level |
|-----------|--------|----------------|
| Boot & Memory | Complete | Hardened (COW, guard pages, W^X) |
| Process Management | Complete | Isolated (per-process address space) |
| Scheduler | Complete | Safe (IRQ-safe, MLFQ) |
| IPC (Pipe/MQ/Futex) | Complete | Basic capabilities |
| Signals | Complete | Basic |
| VFS | Complete | DAC permissions (owner/group/other/umask) |
| Audit | Complete | Hash-chained syscall logging |
| User Mode (Ring 3) | Not started | - |
| Network | Not started | - |
| SMP | Not started | - |
| Security Framework | In progress | Audit only (no MAC/LSM/Capabilities) |

### Issue Resolution Summary

- **Total Audits**: 19 rounds
- **Issues Identified**: 79
- **Issues Fixed**: 68 (86%)
- **Open Issues**: 11 (deferred to future phases)

---

## Part I: Threat Model

### Attacker Profiles

1. **Malicious Tenant** (Multi-tenant server)
   - Goal: Escape container/VM, access other tenant data
   - Mitigations: Address space isolation, capability-based IPC, MAC

2. **Remote Attacker**
   - Goal: Network exploitation, code execution
   - Mitigations: Secure network stack, firewall, input validation

3. **Compromised User Process**
   - Goal: Privilege escalation, kernel exploitation
   - Mitigations: SMAP/SMEP, syscall filtering, W^X

4. **Insider with User Access**
   - Goal: Data exfiltration, audit tampering
   - Mitigations: MAC, audit with tamper evidence, least privilege

### Trust Anchors

- UEFI Secure Boot chain
- Kernel image integrity (signed)
- TPM-based entropy and measurements
- Capability-based resource handles (non-forgeable)
- Audit log integrity chain

---

## Part II: Current Implementation Analysis

### 2.1 Completed Security Features

#### Memory Management
- [x] Buddy physical page allocator with validation
- [x] LockedHeap with proper initialization
- [x] COW with IRQ-safe reference counting (RwLock + AtomicU64)
- [x] Per-process mmap regions tracking
- [x] User pointer validation (verify_user_memory)
- [x] Page zeroing before allocation (info leak prevention)
- [x] Guard pages for kernel stacks
- [x] 4GB identity map limit enforcement

#### Process Isolation
- [x] Per-process page tables (CR3 switching)
- [x] Per-process kernel stacks
- [x] Full context switch (registers + FPU/SIMD)
- [x] Orphan process reparenting to init
- [x] Zombie cleanup with resource reclamation
- [x] Page table hierarchy recursive teardown

#### IPC Security
- [x] Capability-based endpoint access control
- [x] Per-process endpoint isolation
- [x] Message queue backpressure (quota enforcement)
- [x] Futex with lost-wake race protection
- [x] Pipe with reference counting
- [x] Process exit cleanup for IPC resources

#### Scheduler Safety
- [x] IRQ-safe lock ordering (without_interrupts)
- [x] NEED_RESCHED flag (no CR3 switch in interrupt context)
- [x] Priority-based selection (MLFQ)
- [x] Process cleanup notification

### 2.2 Known Gaps (To Be Addressed)

#### Critical Security Gaps
1. **No User Mode (Ring 3)** - All code runs in Ring 0
2. **No Syscall Gate** - Uses cooperative function calls
3. **No MAC/LSM Framework** - Only basic DAC
4. **No Capability System** - IPC-only capabilities
5. **No Audit Subsystem** - Only debug logging

#### High Priority Gaps
1. **No VFS** - No file-based permissions
2. **No Network Stack** - No network security
3. **No SMP** - Single CPU only
4. **No SMAP/SMEP** - Not enabled
5. **No seccomp/pledge** - No syscall filtering
6. **No IOMMU/VT-d** - No DMA isolation
7. **No Spectre/Meltdown mitigations** - Side channel vulnerable
8. **No IMA/EVM** - No integrity measurement

---

## Part II-B: Codex Audit Findings (2025-12-11)

### Completeness Gaps

The following enterprise-critical components are missing from current implementation:

| Category | Missing Feature | Priority |
|----------|----------------|----------|
| Integrity | IMA/EVM-like measurement | High |
| Storage | dm-verity/measure-on-open | High |
| Storage | Journaling/write barriers | High |
| Crypto | TPM-backed keystore | High |
| Crypto | Key rotation policy | Medium |
| Time | Secure NTP/PTP with auth | Medium |
| Update | Secure update/rollback (A/B) | High |
| Encryption | Per-volume disk encryption | High |
| Debug | kdump/redaction | Medium |
| Attestation | Remote attestation | Medium |
| Patching | Live patch policy | Low |
| Device | IOMMU/VT-d isolation | High |
| Virtualization | Container/VM posture | Medium |
| Compliance | Hardening profiles | High |

### Priority Adjustments

**Move to Phase 0 (Immediate):**

- SMAP/SMEP/KPTI/retpoline
- Spectre/Meltdown mitigations (IBRS/IBPB/STIBP)
- kptr guard/redaction

**Gate Requirements:**

- Capability + LSM + Audit must be ready BEFORE enabling VFS/Net/SMP
- Integrity measurement (IMA/verity) must ship with VFS
- Firewall/conntrack baseline before TCP features
- Lockdep/RCU debug enabled during SMP bring-up

### Feasibility Notes

1. **Ring 3 Entry:** Requires trapframe save/restore not in current context_switch
2. **Capability Migration:** Must coexist with fd_table; needs migration helpers
3. **VFS ACL/MAC:** Depends on xattr support in tmpfs/devfs/procfs
4. **Network Stack:** Depends on timer/wallclock entropy and per-CPU data
5. **kdump:** Depends on block I/O path

### Security Design Gaps

1. **Kernel pointer exposure** - Need kASLR + KPTI + kptr guard + log redaction
2. **No panic-on-UB policy** - Should be configurable
3. **BPF/JIT policy** - Should default-deny
4. **Side channels** - Timer granularity, scheduler leakage not addressed
5. **Audit shipping** - No attestation of remote log integrity
6. **DMA protection** - No IOMMU enablement plan

### Enterprise Parity Gaps (vs Linux/Windows Server)

| Feature | Linux | Windows Server | Zero-OS Status |
|---------|-------|----------------|----------------|
| Role-based admin | Capabilities | AD Groups | Not started |
| Strong auth | Kerberos/LDAP | AD/Kerberos | Not started |
| Storage reliability | Journaling | NTFS journal | Not started |
| HA/Upgrade | A/B boot | WIM | Not started |
| Cgroups | v2 unified | Job Objects | Not started |
| Remote mgmt | IPMI/Serial | WMI/WinRM | Not started |
| FIPS crypto | FIPS modules | FIPS mode | Not started |
| Compliance | STIG profiles | SCM | Not started |

---

## Part III: Enterprise Security Roadmap

### Phase 0: Security Hardening Foundation (Current + Next)

**Priority:** Critical
**Target:** Harden existing subsystems before adding features

#### 0.1 Memory Hardening

- [x] Enable W^X (no writable+executable pages) ✓ (W-1, W^X-1, W^X-2, 2025-12-16)
- [x] Remove writable identity map after boot ✓ (L-5, 2025-12-16 - RemoveWritable strategy)
- [ ] Stack canaries for kernel functions
- [ ] KASLR (Kernel Address Space Layout Randomization)
- [ ] Slab allocator with red zones and quarantine
- [ ] KPTI (Kernel Page Table Isolation) preparation
- [ ] **Spectre/Meltdown mitigations** (IBRS/IBPB/STIBP or retpoline)
- [ ] **kptr guard/redaction** for logs and debug paths

#### 0.2 Cryptographic Foundation

- [ ] Hardware RNG integration (RDRAND/RDSEED)
- [ ] CSPRNG (Cryptographically Secure PRNG)
- [ ] Entropy health monitoring
- [ ] Kernel crypto API (constant-time primitives)
- [ ] **TPM-backed keystore** (seal/unseal) and key rollover policy

#### 0.3 Secure Boot Enhancement
- [ ] Kernel image signature verification
- [ ] TPM PCR measurements
- [ ] Module signing infrastructure
- [ ] Boot parameter integrity

#### 0.4 Testing Infrastructure
- [ ] Syscall fuzzer (all implemented syscalls)
- [ ] Memory allocator property tests
- [ ] IPC stress tests
- [ ] COW correctness tests

---

### Phase 1: Isolation & Policy Primitives

**Priority:** Critical
**Target:** Enable security policy enforcement

#### 1.1 User Mode (Ring 3) Implementation

**Technical Design:**
```rust
// Syscall entry (LSTAR target)
#[naked]
unsafe extern "C" fn syscall_entry() {
    asm!(
        "swapgs",                    // Switch to kernel GS
        "mov gs:[kstack], rsp",      // Save user RSP
        "mov rsp, gs:[kstack_top]",  // Load kernel RSP
        "push rcx",                  // Save user RIP
        "push r11",                  // Save user RFLAGS
        "call syscall_dispatch",
        "pop r11",
        "pop rcx",
        "mov rsp, gs:[user_rsp]",
        "swapgs",
        "sysretq",
        options(noreturn)
    )
}
```

**Tasks:**
- [ ] MSR setup (STAR, LSTAR, SFMASK, KERNEL_GSBASE)
- [ ] syscall/sysret fast path
- [ ] int 0x80 compatibility path
- [ ] iretq for signal return
- [ ] SMAP/SMEP enable (CR4.SMAP, CR4.SMEP)
- [ ] stac/clac wrappers for user memory access

#### 1.2 Capability Framework

**Technical Design:**
```rust
/// Opaque handle for userland
#[derive(Copy, Clone)]
struct CapId(u64);  // table_index (32) | generation (32)

/// Kernel capability descriptor
struct Capability {
    id: CapId,
    obj: CapObject,        // IpcEndpoint, VfsNode, Socket, Shm, Timer
    rights: CapRights,     // READ|WRITE|EXEC|IOCTL|ADMIN|BIND|CONNECT
    label: MacLabel,       // For MAC checks
    owner_pid: Pid,
    rev_gen: u32,          // Revocation generation
}

bitflags! {
    struct CapRights: u64 {
        const READ     = 1 << 0;
        const WRITE    = 1 << 1;
        const EXEC     = 1 << 2;
        const IOCTL    = 1 << 3;
        const ADMIN    = 1 << 4;
        const DELEGATE = 1 << 5;
        // ... object-specific rights
    }
}
```

**Tasks:**
- [ ] Per-process CapSpace table
- [ ] Capability allocation/lookup/revocation
- [ ] Delegation with rights restriction
- [ ] Integration with existing IPC endpoints
- [ ] Integration with future VFS/Socket

#### 1.3 MAC/LSM Hook Layer

**Technical Design:**
```rust
trait LsmPolicy: Send + Sync {
    fn cred_prepare(&self, cred: &mut Credentials) -> Result<()>;
    fn syscall_enter(&self, ctx: &SyscallCtx) -> Result<()>;
    fn file_open(&self, ctx: &TaskCtx, inode: &Inode, flags: OpenFlags) -> Result<()>;
    fn inode_permission(&self, ctx: &TaskCtx, inode: &Inode, mask: PermMask) -> Result<()>;
    fn ipc_send(&self, ctx: &TaskCtx, ep: &Endpoint, bytes: usize) -> Result<()>;
    fn signal_send(&self, ctx: &TaskCtx, target: Pid, sig: Signal) -> Result<()>;
    fn socket_create(&self, ctx: &TaskCtx, domain: Domain, ty: SockType) -> Result<()>;
    fn socket_connect(&self, ctx: &TaskCtx, sock: &Socket, addr: &SockAddr) -> Result<()>;
}

struct LsmManager {
    policies: Vec<Arc<dyn LsmPolicy>>,  // All must permit (AND)
}
```

**Hook Points:**
- Syscall entry/exit
- Process: fork, exec, exit, setuid
- VFS: lookup, open, create, unlink, chmod, mount
- IPC: mq send/recv, pipe create, futex, shm
- Signal: send_signal, ptrace
- Network: socket, bind, connect, send/recv

**Tasks:**
- [ ] Hook point infrastructure
- [ ] Policy registration API
- [ ] Default permissive policy
- [ ] Build-time feature gate

#### 1.4 Audit Subsystem

**Technical Design:**
```rust
struct AuditEvent {
    id: u64,
    timestamp: Time,
    subject: Subject,      // pid, uid, gid, cap_id
    kind: AuditKind,       // Syscall, Signal, Net, IPC, FS, Policy
    outcome: Outcome,      // Success/Error
    object: Option<Object>,// path, inode, socket, endpoint
    args: SmallVec<u64, 6>,
    prev_hash: Hash256,    // Tamper evidence
}

impl AuditSubsystem {
    fn emit(&self, event: AuditEvent) {
        let hash = hash(self.prev_hash, &event);
        self.buffer.push(event);
        self.prev_hash = hash;
    }
}
```

**Tasks:**
- [ ] Event structure and serialization
- [ ] Hash chain for tamper evidence
- [ ] Ring buffer with overflow handling
- [ ] syscall_dispatcher integration
- [ ] Reader interface with capability gate
- [ ] Persistent log flushing

#### 1.5 Seccomp/Pledge Syscall Filtering

**Technical Design:**
```rust
struct SeccompFilter {
    rules: Vec<SeccompRule>,
    default_action: SeccompAction,
}

struct SeccompRule {
    syscall: u64,
    arg_checks: Vec<ArgCheck>,
    action: SeccompAction,
}

enum SeccompAction {
    Allow,
    Kill,
    Errno(i32),
    Trace,
    Log,
}
```

**Tasks:**
- [ ] Per-process filter storage
- [ ] sys_seccomp implementation
- [ ] BPF-like rule evaluation
- [ ] Fork inheritance rules

---

### Phase 2: VFS & Storage Security

**Priority:** High
**Target:** Secure file system abstraction

#### 2.1 VFS Core

**Technical Design:**
```rust
struct Inode {
    id: InodeId,
    kind: InodeKind,       // File, Dir, Symlink, Device, Pipe, Socket
    security: InodeSecurity,
    ops: &'static dyn InodeOps,
    // ...
}

struct InodeSecurity {
    uid: Uid,
    gid: Gid,
    mode: FileMode,        // POSIX bits
    acl: Option<Acl>,      // Extended ACL
    mac_label: MacLabel,   // LSM label
    flags: InodeFlags,     // IMMUTABLE, APPEND, NOEXEC
}
```

**Permission Check Order:**
1. MAC: `lsm.inode_permission(task, inode, perm)`
2. Capability override: `CapRights::BYPASS_DAC`
3. POSIX DAC: uid/gid/mode
4. ACL: extended allow/deny
5. Flags: NOEXEC, IMMUTABLE, APPEND
6. W^X: no writable+executable mmap

**Tasks:**
- [ ] Inode abstraction
- [ ] Dentry cache with RCU
- [ ] Mount infrastructure
- [ ] Permission check framework
- [ ] ACL implementation
- [ ] xattr for labels

#### 2.2 Secure Path Resolution

**Anti-TOCTOU Design:**
```rust
fn lookup_at(dirfd: CapId, path: &[u8], flags: LookupFlags) -> Result<Inode> {
    // 1. Resolve each component with locked dentries
    // 2. Check MAC at each symlink hop
    // 3. Validate mount/rename sequence numbers
    // 4. Return O_PATH handle for later operations
}
```

**Tasks:**
- [ ] RESOLVE_NO_SYMLINKS flag
- [ ] Symlink depth limit
- [ ] Sequence number validation
- [ ] O_PATH handle support

#### 2.3 File Systems

**Tasks:**
- [ ] tmpfs (memory-backed)
- [ ] devfs (/dev/null, /dev/zero, /dev/urandom)
- [ ] procfs (/proc) with MAC labels
- [ ] initramfs (CPIO archive)
- [ ] ext2 (read-only initially)

---

### Phase 3: IPC/Process Sandboxing Maturity

**Priority:** High
**Target:** Enterprise-grade isolation

#### 3.1 Namespace Isolation

**Tasks:**
- [ ] PID namespace (isolated PID numbering)
- [ ] Mount namespace (isolated filesystem view)
- [ ] IPC namespace (isolated message queues)
- [ ] Network namespace (isolated network stack)
- [ ] User namespace (UID/GID mapping)

#### 3.2 Resource Limits (rlimits)

**Tasks:**
- [ ] RLIMIT_CPU (CPU time)
- [ ] RLIMIT_FSIZE (file size)
- [ ] RLIMIT_DATA (data segment)
- [ ] RLIMIT_STACK (stack size)
- [ ] RLIMIT_CORE (core file size)
- [ ] RLIMIT_NOFILE (open files)
- [ ] RLIMIT_NPROC (process count)

#### 3.3 Cgroup Controllers

**Tasks:**
- [ ] cpu controller (shares, quotas)
- [ ] memory controller (limits, OOM)
- [ ] pids controller (process limits)
- [ ] io controller (bandwidth limits)

#### 3.4 IPC Hardening

**Tasks:**
- [ ] Capability-gated message queues
- [ ] Per-namespace endpoint isolation
- [ ] Priority inheritance for futex
- [ ] Pipe capacity limits per cgroup

---

### Phase 4: Secure Networking Stack

**Priority:** High
**Target:** Enterprise network security

#### 4.1 Protocol Stack Architecture

**Design:**
```
NIC Driver -> L2 Validation -> L3 Firewall -> L4 Conntrack -> Socket
                   |               |              |
              MAC filter    IP validation   State tracking
              Length/CRC    TTL/hop limit   Rate limiting
```

**Tasks:**
- [ ] IP header validation
- [ ] TCP/UDP checksum verification
- [ ] Fragment reassembly with limits
- [ ] Source routing disabled

#### 4.2 Protection Mechanisms

**SYN Cookie:**
```rust
struct SynCookieState {
    secret: [u8; 32],
    timestamp_granularity: u32,
}

fn encode_syn_cookie(mss: u16, wscale: u8, ts: bool) -> u32;
fn verify_syn_cookie(cookie: u32) -> Option<(u16, u8, bool)>;
```

**Tasks:**
- [ ] SYN cookie generation/verification
- [ ] Connection rate limiting (token bucket)
- [ ] Per-source connection caps
- [ ] ISN randomization (RFC 6528)
- [ ] Ephemeral port randomization

#### 4.3 Kernel Firewall

**Design:**
```rust
enum MatchExpr {
    SrcIp(IpNet), DstIp(IpNet),
    SrcPort(u16), DstPort(u16),
    Proto(u8), State(ConnState),
    Mark(u32), Cgroup(u64),
}

enum Action {
    Accept, Drop, Log,
    Limit(RateLimiter),
    SetMark(u32),
    Redirect(IpAddr, u16),
}

struct Firewall {
    chains: Vec<Chain>,
    conntrack: ConntrackTable,
}
```

**Tasks:**
- [ ] Rule table structure
- [ ] Match expression evaluation
- [ ] Conntrack state machine
- [ ] NAT support
- [ ] IPsec SAD/SPD integration

#### 4.4 Secure Socket API

**Tasks:**
- [ ] Socket as CapId handle
- [ ] Per-socket credentials
- [ ] Zero-copy with pinned buffers
- [ ] LSM hooks for all operations

---

### Phase 5: SMP & Performance-Safe Concurrency

**Priority:** Medium-High
**Target:** Multi-core support

#### 5.1 Lock Hierarchy

**Global Order:**
```
irq_disable -> percpu -> mm -> vfs_inode -> vfs_dentry ->
file_table -> socket -> proc_table -> sched -> net_route
```

**Tasks:**
- [ ] Lock class annotations
- [ ] Runtime lockdep checker
- [ ] Deadlock detection (debug)

#### 5.2 Per-CPU Data

**Design:**
```rust
struct PerCpu<T> {
    shards: [T; MAX_CPUS],
}

fn with_local<T, R>(pcpu: &PerCpu<T>, f: impl FnOnce(&mut T) -> R) -> R;
```

**Tasks:**
- [ ] Per-CPU allocator
- [ ] Safe cross-CPU access API
- [ ] Interrupt vs process context separation

#### 5.3 RCU/Epoch GC

**Design:**
```rust
struct RcuDomain {
    global_epoch: AtomicU64,
    per_cpu_epoch: PerCpu<AtomicU64>,
    callbacks: SegQueue<Box<dyn FnOnce()>>,
}

fn rcu_read_lock() -> RcuGuard;
fn rcu_defer(cb: impl FnOnce() + 'static);
```

**Use Cases:**
- VFS dentry cache
- Routing table
- Process list snapshots
- Firewall rules

**Tasks:**
- [ ] Epoch-based RCU implementation
- [ ] Grace period detection
- [ ] Callback queue management

#### 5.4 Scheduler SMP Extensions

**Tasks:**
- [ ] Per-CPU run queues
- [ ] Load balancing with affinity
- [ ] Priority inheritance protocol
- [ ] CPU isolation (cpuset)

#### 5.5 TLB Coherence

**Design:**
```rust
struct TlbShootdownReq {
    asid: Option<Asid>,
    range: VirtRange,
}

fn tlb_shootdown(range: VirtRange, asid: Option<Asid>) {
    ipi::broadcast(IpiKind::TlbShootdown(req));
    wait_for_acks();
}
```

**Tasks:**
- [ ] IPI infrastructure
- [ ] Batched shootdown
- [ ] PCID/ASID support

---

### Phase 6: Resource Governance & QoS

**Priority:** Medium
**Target:** Fair resource allocation

#### 6.1 CPU Controller

**Tasks:**
- [ ] CPU shares (proportional weight)
- [ ] CPU quota (hard limit)
- [ ] CPU burst (temporary overdraft)
- [ ] Real-time band with budget

#### 6.2 Memory Controller

**Tasks:**
- [ ] Memory limits (hard/soft)
- [ ] OOM killer with policy
- [ ] Swap accounting (when swap added)
- [ ] Memory pressure notifications

#### 6.3 I/O Controller

**Tasks:**
- [ ] Block I/O bandwidth limits
- [ ] Network bandwidth limits
- [ ] Fair queueing (FQ-CoDel like)
- [ ] Priority classes

---

### Phase 7: Observability & Reliability

**Priority:** Medium
**Target:** Production operations support

#### 7.1 Crash Handling

**Tasks:**
- [ ] Kernel dump infrastructure
- [ ] Sensitive data redaction
- [ ] Dump encryption
- [ ] Panic-on-UB toggle

#### 7.2 Tracing

**Tasks:**
- [ ] Structured event tracing
- [ ] Sampling profiler
- [ ] Capability-gated readers
- [ ] Low-overhead counters

#### 7.3 Health Monitoring

**Tasks:**
- [ ] Hardware watchdog
- [ ] Hung task detection
- [ ] Starvation detection
- [ ] Live patching (optional)

---

## Part IV: Module Security Matrix

| Module | Capability | MAC/LSM | Audit | Sandboxing |
|--------|------------|---------|-------|------------|
| Process | Owner cap | exec hook | lifecycle | namespace |
| VFS | File cap | inode_permission | file ops | mount ns |
| IPC | Endpoint cap | ipc_send/recv | message | IPC ns |
| Network | Socket cap | socket_* | connect/send | net ns |
| Memory | SHM cap | mmap hook | alloc | cgroup |
| Scheduler | - | - | context switch | cpuset |

---

## Part V: Implementation Guidelines

### Security Gate Requirements

**Each new feature must have:**
1. Threat model document
2. LSM hook integration
3. Capability access control
4. Audit events
5. Fuzz coverage
6. Security review

### Code Quality Requirements

**All PRs must:**
1. Pass CI (build + tests)
2. Pass Miri (UB detection)
3. Pass Clippy (lint)
4. Have security review for:
   - Syscall implementations
   - Memory management changes
   - IPC/network code
   - Capability checks

### Release Tiers

| Tier | Description | Hardening |
|------|-------------|-----------|
| Secure-Preview | All hardening on | Full |
| Balanced | Default production | Standard |
| Performance | Selective hardening | Minimal (integrity only) |

---

## Part VI: Timeline & Priorities

### Immediate (Next Sprint)

1. ~~W^X enforcement~~ ✓ (W-1, W^X-1, W^X-2, 2025-12-16)
2. ~~Remove writable identity map~~ ✓ (L-5, 2025-12-16)
3. ~~Audit event infrastructure~~ ✓ (2025-12-16, hash-chained syscall audit)
4. Syscall fuzzer setup

### Short Term (1-2 Months)

1. User mode (Ring 3)
2. Basic capability framework
3. LSM hook points
4. VFS foundation

### Medium Term (3-6 Months)

1. Complete VFS with permissions
2. Network stack with firewall
3. Namespace isolation
4. SMP support

### Long Term (6-12 Months)

1. Full MAC policy modules
2. Cgroup controllers
3. IPsec/TLS
4. Production hardening

---

## Part VII: References

### Security Standards
- CIS Benchmarks for Linux
- NIST SP 800-53 (Security Controls)
- Common Criteria (EAL)
- FIPS 140-3 (Cryptography)

### Implementation References
- Linux Security Module (LSM)
- FreeBSD Capsicum
- seL4 Capabilities
- Fuchsia Zircon Security

---

## Appendix A: Current Codebase Statistics

| Metric | Value |
|--------|-------|
| Total Rust LOC | ~12,000 |
| Kernel modules | 9 (arch, mm, sched, ipc, vfs, cpu_local, security, drivers, kernel_core, bootloader) |
| Syscalls defined | 50+ |
| Syscalls implemented | ~30 |
| Security audits | 17 |
| Issues fixed | 68/79 (86%) |

## Appendix B: Existing Security Features Detail

### Memory Safety
- COW with atomic reference counting
- User pointer validation (boundary + page table)
- Page zeroing on allocation
- Guard pages for kernel stacks
- mmap rollback on failure
- **W^X enforcement in ELF loader (W-1, 2025-12-16)**

### Process Isolation
- Per-process page tables
- CR3 switching on context switch
- Per-process kernel stacks
- Resource cleanup on exit

### VFS Security (2025-12-15/16)

- POSIX DAC permissions (owner/group/other)
- Supplementary groups support
- umask enforcement
- Sticky bit semantics
- Path traversal permission checks
- readdir permission enforcement (W-2)

### IPC Security
- Capability-based endpoint access
- Per-process endpoint isolation
- Message queue quotas
- Pipe reference counting
- Futex lost-wake protection

---

*This roadmap is a living document, updated as the project evolves toward enterprise-grade security.*
