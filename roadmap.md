# Zero-OS Development Roadmap

**Last Updated:** 2025-12-17

This document outlines the development roadmap for Zero-OS, a microkernel operating system written in Rust for x86_64 architecture.

---

## Current Status: Phase 6.1 Complete, Ready for Phase 6.2

### Completed Features

- UEFI Bootloader with ELF parsing
- High-half kernel mapping (0xffffffff80000000)
- VGA text mode driver
- Serial port output (0x3F8)
- IDT with 20+ exception handlers
- Heap allocator (LockedHeap)
- Buddy physical page allocator
- Process Control Block (PCB) structure
- Enhanced scheduler (multi-level feedback queue with priority buckets)
- Context switch framework (176-byte context)
- System call framework (50+ defined)
- Fork API with COW implementation
- Memory mapping API (mmap/munmap) with per-process isolation
- PIC initialization for hardware interrupts
- User pointer validation in syscalls
- Timestamp support via timer tick
- Per-process address space isolation
- Scheduler-process state synchronization
- **Preemptive scheduling (timer connected to scheduler)**
- **IRQ-safe COW reference counting**
- **Priority-based process selection**
- **UEFI memory map integration (BootInfo)**
- **GDT/TSS for user-kernel transitions**
- **IST for double fault safety**
- **Security Audit subsystem (hash-chained events)**
- **SYSCALL/SYSRET MSR configuration (Ring 3 transition)**
- **IRETQ-based user mode entry**

### Fixed Issues (2025-12-10 Seventh Audit)

- [x] C-18: Timer interrupt CR3 switch without context switch (CRITICAL - FIXED)
  - Removed CR3 switch from schedule() to prevent wrong address space after IRQ
  - Added NEED_RESCHED atomic flag for deferred scheduling
  - All scheduler APIs wrapped with without_interrupts()
- [x] H-19: copy_to_user kernel panic on read-only pages (HIGH - FIXED)
  - verify_user_memory now checks WRITABLE or BIT_9 (COW) for writes
  - True read-only pages correctly return EFAULT
- [x] H-20: sys_mmap frame leak on error (HIGH - FIXED)
  - Added tracked vector to record mapped (page, frame) pairs
  - Proper rollback on allocate_frame or map_page failure
- [x] H-21: Potential UAF in mmap rollback (HIGH - FIXED)
  - Only deallocate frames when unmap_page succeeds
- [x] M-12: Ready queue locks not interrupt-safe (MEDIUM - FIXED)
  - All scheduler public APIs wrapped with without_interrupts()

### Fixed Issues (2025-12-10 Fourth Audit)

- [x] C-5: COW refcount deadlock (CRITICAL - FIXED)
  - Changed Mutex to RwLock + AtomicU64
  - Added `without_interrupts` for IRQ safety
- [x] C-6: munmap double-free (CRITICAL - FIXED)
  - Added PAGE_REF_COUNT check before deallocation
- [x] H-11: Timer not connected to scheduler (HIGH - FIXED)
  - Timer ISR now calls `Scheduler::on_clock_tick()`
- [x] H-12: BootInfo ignored (HIGH - FIXED)
  - Kernel `_start` now accepts BootInfo pointer
  - UEFI memory map parsed to find largest usable region
  - 4GB identity map limit enforced
- [x] H-13: Scheduler PID-order selection (HIGH - FIXED)
  - Changed to `BTreeMap<Priority, BTreeMap<Pid, PCB>>`
  - Proper priority-based selection implemented
- [x] H-15: Process resource cleanup (HIGH - FIXED)
  - Added `free_process_resources()` with page table teardown
  - Recursive page table traversal via identity mapping
  - COW pages managed by refcount, non-COW freed directly
  - Kernel stack: placeholder for future per-process allocation
- [x] H-16: Missing TSS setup (HIGH - FIXED)
  - New `kernel/arch/gdt.rs` with GDT/TSS initialization
  - IST configured for double fault handler
  - `set_kernel_stack()` for context switch integration

### Fixed Issues (2025-12-09 Third Audit)

- [x] C-3: mmap/munmap per-process isolation (CRITICAL - FIXED)
  - Removed global MMAP_REGISTRY, moved to per-process PCB
  - sys_mmap/sys_munmap now use with_current_manager()
- [x] H-9: Scheduler state synchronization (HIGH - FIXED)
  - Scheduler now uses Arc<Mutex<Process>> references
  - State changes propagate automatically
- [x] H-10: Zombie process cleanup (HIGH - FIXED)
  - cleanup_zombie() now removes from PROCESS_TABLE
  - Scheduler notified via register_cleanup_notifier()

### Fixed Issues (2025-12-09 Second Audit)

- [x] L-4: Panic handler now disables interrupts immediately
- [x] H-8: sys_fork syscall now calls real fork implementation
- [x] M-6: mmap pages zeroed before mapping (info leak fix)
- [x] M-7: mmap bounds checking against USER_SPACE_TOP
- [x] C-4: COW fault handler uses current CR3 via with_current_manager

### Previously Fixed Issues (2025-12-09 First Audit)

- [x] C-1: Process table PID indexing (Critical)
- [x] C-2: Bootloader address fallback
- [x] H-1: Interrupt enable (sti) for hardware interrupts
- [x] H-2: PIC initialization and remapping
- [x] H-3: Atomic interrupt statistics (deadlock prevention)
- [x] H-4: User pointer validation in syscalls
- [x] H-5: Buddy allocator with validation
- [x] H-6: ExitBootServices called properly
- [x] H-7: Kernel file complete read loop
- [x] M-1 - M-5: Various medium issues fixed

### Open Issues Requiring Future Work

- [ ] L-1: Many syscalls still return ENOSYS
- [x] H-12: BootInfo ignored - UEFI memory map not used ✓ FIXED
- [x] H-14: IPC lacks process isolation ✓ FIXED
- [x] H-15: Kernel stack/page tables not freed on exit ✓ FIXED
- [x] H-16: Missing TSS setup for user-kernel transition ✓ FIXED
- [x] M-8: No kernel stack guard pages ✓ FIXED
- [x] M-9: FPU/SIMD context not saved ✓ FIXED
- [x] L-5: Identity map left writable after boot ✓ FIXED (Round 18 - security hardening)

### Architectural Limitations (Partially Resolved - Dec 11)

- [x] A-1: Preemption mode - PARTIALLY RESOLVED
  - Cooperative scheduling implemented via `reschedule_now()`
  - NEED_RESCHED consumed at syscall return and sys_yield
  - True preemption (interrupt return path) still pending
- [x] A-2: Process address space isolation - RESOLVED
  - CR3 switching implemented in `reschedule_now()`
  - Context switch properly saves/restores registers + FPU
  - First schedule handled via BOOTSTRAP_CONTEXT

See [qa-2025-12-10.md](qa-2025-12-10.md) and [qa-2025-12-10-v2.md](qa-2025-12-10-v2.md) for detailed issue descriptions.

---

## Architecture Vision: Hybrid Macro/Micro Kernel

Zero-OS is evolving toward a **hybrid kernel architecture** inspired by Linux, combining the performance of a monolithic kernel with the modularity and security of a microkernel.

### Design Principles

```
+------------------------------------------------------------------+
|                        USER SPACE                                 |
|  +---------------+  +---------------+  +---------------+          |
|  | FS Server     |  | Net Server    |  | Device Mgr    |          |
|  | (ext2, FAT)   |  | (TCP/IP)      |  | (USB, etc)    |          |
|  +-------+-------+  +-------+-------+  +-------+-------+          |
|          |                  |                  |                  |
|          v                  v                  v                  |
|  +----------------------------------------------------------+    |
|  |              Capability-Based IPC Layer                   |    |
|  +----------------------------------------------------------+    |
+------------------------------------------------------------------+
|                       KERNEL SPACE                                |
|  +------------------+  +------------------+  +------------------+ |
|  | Scheduler        |  | VMM/PMM          |  | IPC Fast Path    | |
|  | (MLFQ + Priority)|  | (COW, mmap)      |  | (Ring Buffers)   | |
|  +------------------+  +------------------+  +------------------+ |
|  +------------------+  +------------------+  +------------------+ |
|  | Interrupt/Trap   |  | Basic Drivers    |  | Capability DB    | |
|  | Handlers         |  | (Timer,UART,VGA) |  | (Security)       | |
|  +------------------+  +------------------+  +------------------+ |
+------------------------------------------------------------------+
|                        HARDWARE                                   |
+------------------------------------------------------------------+
```

### In-Kernel (Macro-style) - Performance Critical

1. **Scheduler** - Direct hardware access, minimal latency
2. **Virtual/Physical Memory Manager** - Page tables, COW, buddy allocator
3. **IPC Fast Path** - Optimized send/recv for servers
4. **Interrupt Handling** - IDT, PIC, exception handlers
5. **Basic Drivers** - Timer, APIC, UART, VGA
6. **Page Fault Handler** - COW resolution
7. **Capability Database** - Security-critical access control

### User-Space Services (Micro-style) - Isolation & Modularity

1. **File Systems** - ext2, FAT, tmpfs as isolated servers
2. **Network Stack** - TCP/IP protocol implementation
3. **Block Device Drivers** - With DMA via kernel helper
4. **USB Stack** - Complex protocol handling
5. **Init/Service Manager** - Process supervision (PID 1)
6. **POSIX Compatibility Layer** - Legacy syscall translation

### IPC Design for Hybrid Architecture

- **Capability-based endpoints** - Fine-grained access control
- **Per-process endpoint tables** - Namespace isolation
- **Zero-copy shared pages** - With refcounting
- **Ring buffers with backpressure** - Quota enforcement
- **Async notifications + sync RPC** - Flexible communication

---

## Phase 2: Core Infrastructure Hardening (COMPLETED ✓)

**Priority: Critical**
**Target: Production-Ready Kernel Boot**
**Status: COMPLETE ✓**

### 2.1 Process Isolation (COMPLETED ✓)

- [x] **Per-Process Address Space**
  - ✓ Move mmap tracking into PCB (mmap_regions, next_mmap_addr)
  - ✓ Use with_current_manager for all mmap operations
  - [ ] Implement proper address space teardown on exit

- [x] **Scheduler-Process State Unification**
  - ✓ Replace READY_QUEUE copies with Arc<Mutex<Process>> references
  - ✓ Add process exit notification to scheduler (register_cleanup_notifier)
  - [ ] Implement proper priority-based selection

- [x] **Zombie Process Cleanup**
  - ✓ Implement full resource cleanup on termination
  - [ ] Free kernel stacks and page tables
  - ✓ Remove from PROCESS_TABLE and notify scheduler

### 2.2 Hardware Initialization

- [x] **PIC Configuration**
  - Remap 8259 PIC (IRQ 0-15 to vectors 32-47) ✓
  - Timer and keyboard interrupts enabled ✓

- [x] **Timer Enhancement** ✓
  - Configure PIT frequency for accurate timing ✓
  - Connect timer interrupt to scheduler tick ✓

- [ ] **Keyboard Driver Enhancement**
  - PS/2 keyboard scancode translation
  - Key event queue implementation

### 2.3 Memory Management Completion

- [ ] **UEFI Memory Map Integration**
  - Parse boot info memory map in kernel
  - Initialize buddy allocator from actual available regions
  - Avoid reserved/firmware regions

- [ ] **Page Table Manager Enhancement**
  - Per-process page table cloning
  - Proper TLB invalidation

### 2.4 Security Hardening

- [x] **User Pointer Validation** ✓
- [x] **mmap Page Zeroing** ✓
- [x] **mmap Bounds Checking** ✓
- [ ] **Implement copy_from_user/copy_to_user wrappers**

---

## Phase 3: Process Management Maturity (COMPLETED ✓)

**Priority: High**
**Target: Multi-Process Support**
**Status: COMPLETE ✓**

### 3.1 Fork/Exec Implementation

- [x] **Copy-On-Write (COW)** ✓
  - Page table duplication with shared pages
  - COW fault handler implementation
  - Physical page reference counting

- [x] **Exec System Call** ✓
  - ELF binary loading ✓
  - User-space address space setup ✓
  - Argument/environment passing ✓

### 3.2 Process Lifecycle

- [x] **Wait/Exit Semantics** ✓
  - Parent waiting for child termination ✓
  - Exit code propagation ✓
  - Zombie process cleanup ✓

- [x] **Orphan Handling** ✓
  - Reparenting to init process

### 3.3 Scheduler Enhancement (COMPLETED ✓)

- [x] **Preemptive Scheduling** ✓
  - Timer-driven context switch ✓
  - Priority recalculation (MLFQ) ✓
  - CPU accounting ✓

---

## Phase 4: Inter-Process Communication

**Priority: Medium**
**Target: Process Coordination**
**Status: In Progress**

### 4.1 Synchronization Primitives

- [x] **Kernel Wait Queue**
  - Process blocking/waking mechanism ✓
  - Foundation for blocking I/O

- [x] **Kernel Mutex (KMutex)**
  - Blocking mutex implementation ✓
  - try_lock non-blocking variant ✓

- [x] **Semaphore**
  - Counting semaphore ✓
  - wait/signal operations ✓

- [x] **Condition Variable**
  - wait/notify_one/notify_all ✓

- [x] **User-space Futex**
  - sys_futex syscall (202) ✓
  - FUTEX_WAIT: block if value matches ✓
  - FUTEX_WAKE: wake up to N waiters ✓
  - Global FutexTable with (pid, vaddr) key ✓
  - Lost-wake race protection ✓
  - Process exit cleanup ✓

### 4.2 IPC Mechanisms

- [x] **Message Queue (Capability-Based)**
  - Endpoint registration ✓
  - Send/receive with access control ✓
  - Backpressure (64 msg limit) ✓

- [x] **Pipes**
  - Anonymous pipe creation ✓
  - Ring buffer with blocking I/O ✓
  - PipeHandle with read/write/close ✓
  - sys_pipe syscall with fd_table integration ✓
  - sys_read/sys_write support for pipe fds ✓
  - Per-process file descriptor table ✓

- [x] **Blocking IPC**
  - Integration with WaitQueue ✓
  - send_message_notify, receive_message_blocking ✓
  - Retry-based timeout support ✓

### 4.3 Signal Handling

- [x] **Signal Delivery**
  - Signal definitions (SIGKILL, SIGTERM, SIGSTOP, SIGCONT, etc.) ✓
  - PendingSignals bitmap per process ✓
  - Default signal actions ✓
  - sys_kill syscall implementation ✓
  - Scheduler integration for SIGCONT resume ✓
  - [ ] User signal handlers (future)

---

## Phase 5: File System Foundation (COMPLETED ✓)

**Priority: Medium**
**Target: Basic I/O Operations**
**Status: COMPLETE ✓**

### 5.1 Virtual File System (VFS)

- [x] VFS layer design ✓
- [x] Inode abstraction ✓
- [x] File descriptor table ✓

### 5.2 Initial File Systems

- [x] RAM Disk (ramfs) ✓
- [x] Device files (/dev/null, /dev/zero, /dev/console) ✓

### 5.3 System Calls

- [x] open/close implementation ✓
- [x] read/write for files ✓
- [x] lseek support ✓

### 5.4 Security Features (2025-12-15/16)

- [x] POSIX DAC permissions (owner/group/other) ✓
- [x] Supplementary groups support ✓
- [x] umask enforcement ✓
- [x] Sticky bit semantics ✓
- [x] Path traversal permission checks ✓
- [x] readdir permission enforcement (W-2) ✓

---

## Phase 6: User Space

**Priority: Medium**
**Target: First User Program**
**Status: In Progress (6.1 Core Infrastructure Complete)**

### 6.1 User Mode Support (COMPLETED ✓)

- [x] TSS setup ✓ (GDT with TSS RSP0 for syscall return)
- [x] Ring 3 transition ✓ (IRETQ-based enter_usermode)
- [x] System call entry/exit ✓ (SYSCALL/SYSRET with proper stack switching)
- [x] SYSCALL MSR configuration ✓ (STAR, LSTAR, SFMASK, EFER.SCE)
- [x] User/kernel segment selectors ✓ (CS=0x23, SS=0x1B)

### 6.2 User Libraries

- [ ] Minimal libc
- [ ] System call wrappers

### 6.3 Initial Programs

- [ ] Init process (PID 1)
- [ ] Simple shell

---

## Phase 7: Advanced Features

**Priority: Future**
**Target: Feature Completeness**

### 7.1 Networking

- [ ] Network stack design
- [ ] TCP/IP implementation

### 7.2 Graphics

- [ ] Framebuffer support

### 7.3 Storage

- [ ] ATA/AHCI driver
- [ ] Ext2 filesystem

### 7.4 Multi-Core

- [ ] SMP boot
- [ ] Per-CPU scheduling

---

## Testing Strategy

### Current Tests

- Buddy allocator self-test
- Basic module loading verification
- Boot sequence validation

### Needed Tests

- Process creation/termination cycles
- Fork/COW stress tests
- mmap/munmap validation
- System call round-trips

### Debugging Tools

- QEMU monitor integration
- GDB remote debugging (:1234)
- Serial console logging

---

## Known Technical Debt

### Critical (RESOLVED ✓)

All critical issues have been resolved:

1. ✓ mmap/munmap now use per-process page table
2. ✓ Scheduler uses Arc references, synchronized with PROCESS_TABLE
3. ✓ Zombie cleanup removes from all data structures
4. ✓ COW refcount uses atomic operations with IRQ safety
5. ✓ munmap checks refcount before freeing

### High Priority

1. ~~**UEFI memory map not used**~~ - ✓ FIXED (init_with_bootinfo)
2. ~~**IPC lacks process isolation**~~ - ✓ FIXED (capability-based endpoints)
3. ~~**Kernel stack/page table not freed on exit**~~ - ✓ FIXED (page table teardown)
4. ~~**Missing TSS setup**~~ - ✓ FIXED (gdt.rs with GDT/TSS)

### Medium Priority

1. **Many syscalls return ENOSYS** - need implementation (exec, wait, kill, etc.)
2. **No exec() implementation** - can't load new programs
3. ~~**No kernel stack guard pages**~~ - ✓ FIXED (stack_guard.rs)
4. ~~**FPU/SIMD context not saved**~~ - ✓ FIXED (FXSAVE/FXRSTOR in context_switch.rs)

### Low Priority

1. **No file system** - required for exec and general I/O

---

## Code Quality Metrics

### Audit History

| Date | Auditor | Issues Found | Issues Fixed |
|------|---------|--------------|--------------|
| 2025-12-09 | Claude + Codex (1st) | 17 | 16 (94%) |
| 2025-12-09 | Claude + Codex (2nd) | 8 new | 5 (63%) |
| 2025-12-09 | Claude + Codex (3rd) | 0 new | 3 (100%) |
| 2025-12-10 | Claude + Codex (4th) | 11 new | 10 (91%) |
| 2025-12-10 | Claude + Codex (5th) | 5 new | 0 (audit only) |
| 2025-12-10 | Claude + Codex (6th) | 0 new | 5 (M-10, H-17, H-18, C-17, M-11) |
| 2025-12-10 | Claude + Codex (7th) | 6 new | 6 (C-18, H-19, H-20, H-21, M-12) |
| 2025-12-11 | Claude + Codex (8th) | 0 new | 2 arch limits (A-1 partial, A-2 full) |
| 2025-12-11 | Claude + Codex (9th) | 7 new | 7 (C-19, C-20, H-22, H-23, H-24, M-13, M-14) |
| 2025-12-11 | Claude + Codex (10th) | 5 new | 2 (M-15, M-16), 3 deferred (A-3, H-25, H-26) |
| 2025-12-11 | Claude + Codex (11th) | 3 new | 3 (C-21, H-27, H-28 - sys_pipe/FD) |
| 2025-12-11 | Claude + Codex (12th) | 3 new | 3 (H-29, H-30, M-17 - futex) |
| 2025-12-11 | Claude + Codex (13th) | 5 new | 2 (H-31, H-32 - signal), 3 deferred (H-33, H-34, M-18) |
| 2025-12-15 | Claude + Codex (16th) | 5 new | 4 (V-1, V-2, V-3, V-4 - VFS perms, SMP SMAP) |
| 2025-12-16 | Claude + Codex (17th) | 4 new | 2 (W-1: W^X, W-2: readdir), 2 deferred (W-3, W-4: SMP) |
| 2025-12-16 | Claude + Codex (18th) | 2 new | 2 (W^X-1, W^X-2: boot-time W^X enforcement) |
| 2025-12-16 | Claude + Codex (19th) | 0 new | Audit subsystem implemented (hash-chained events) |
| 2025-12-17 | Claude + Codex (20th) | 8 new | 4 fixed (X-2: DoS, X-4: mount perms, X-6: IPC, X-7: TLB), 4 deferred |
| 2025-12-17 | Claude + Codex (21st) | 10 new | 4 fixed (Y-1: SFMASK, Y-2: SYSRET, Y-3: DR6/DR7, Y-6: enter_usermode), 6 open |
| 2025-12-18 | Claude + Codex (22nd) | 11 new | 2 fixed (Z-6: RNG entropy, Z-7: kernel stack), 9 open |

### Current Status

- Total issues tracked: 110
- Fixed: 80 (73%)
- Open: 30 (27%)
  - 2 CRITICAL fixed this round (Z-6: RNG entropy fallback, Z-7: kernel stack allocation)
  - 5 HIGH open (Z-1: FPU/SIMD, Z-2: stack align, Z-3: user ptr, Z-4: callback len, Z-8: fork rollback, Z-9: signal perms)
  - 3 MEDIUM open (Z-5: context switch, Z-10: ELF rollback, Z-11: pipe wakeup)
  - 13 Deferred (A-3, H-25, H-26, H-33, H-34, M-18, W-3, W-4, X-1, X-5, Y-7 - mostly SMP)
  - A-1 partially resolved (cooperative scheduling)
  - A-2 fully resolved (address space isolation)

See [qa-2025-12-10.md](qa-2025-12-10.md), [qa-2025-12-10-v2.md](qa-2025-12-10-v2.md), [qa-2025-12-11.md](qa-2025-12-11.md), [qa-2025-12-15-v2.md](qa-2025-12-15-v2.md), [qa-2025-12-16.md](qa-2025-12-16.md), [qa-2025-12-17.md](qa-2025-12-17.md), [qa-2025-12-17-v2.md](qa-2025-12-17-v2.md), and [qa-2025-12-18.md](qa-2025-12-18.md) for detailed audit reports.

---

## Version History

| Version | Date | Milestone |
|---------|------|-----------|
| 0.1.0 | 2025-12 | Phase 1 - Basic kernel boot |
| 0.1.1 | 2025-12-09 | Security fixes (mmap, panic, fork) |
| 0.1.2 | 2025-12-10 | Preemptive scheduling, COW safety |
| 0.1.3 | 2025-12-10 | BootInfo integration, TSS/GDT setup |
| 0.1.4 | 2025-12-10 | User pointer safety, context switch fix |
| 0.1.5 | 2025-12-10 | Scheduler IRQ safety, mmap rollback fix |
| 0.1.6 | 2025-12-11 | Full context switch with CR3, address space isolation |
| 0.1.7 | 2025-12-11 | sys_wait, exec args, 7 security fixes (C-19, C-20, H-22, H-23, M-13, M-14) |
| 0.2.0 | 2025-12-10 | Phase 2 - Process isolation (COMPLETE) |
| 0.3.0 | 2025-12-11 | Phase 3 - Multi-process support (COMPLETE) |
| 0.3.1 | 2025-12-11 | Phase 4 IPC - Pipes, Futex, Signal handling |
| 0.4.0 | 2025-12-15 | Phase 5 VFS - ramfs, devfs, DAC permissions |
| 0.4.1 | 2025-12-16 | Security hardening - W^X enforcement, readdir perms |
| 0.4.2 | 2025-12-16 | Boot-time W^X validation - 0 violations achieved |
| 0.4.3 | 2025-12-16 | Security Audit subsystem - hash-chained syscall logging |
| 0.4.4 | 2025-12-17 | Security fixes - DoS (X-2), mount perms (X-4), IPC cleanup (X-6), TLB flush (X-7) |
| 0.5.0 | 2025-12-17 | Phase 6 foundation - SYSCALL/SYSRET, Ring 3 transition, enter_usermode |
| 0.5.1 | 2025-12-17 | Ring 3 security hardening - SYSRET canonical checks, SFMASK, DR clearing, RFLAGS sanitization |
| 0.5.2 | 2025-12-18 | Critical security fixes - RNG entropy (Z-6), kernel stack allocation (Z-7) |
| 1.0.0 | TBD | First stable release |

---

## Contributing Guidelines

1. All code changes require code review
2. Run `make build` before committing
3. New features need documentation updates
4. Bug fixes should include regression tests
5. Follow existing code style and patterns

---

*This roadmap is subject to change based on project priorities and community feedback.*
