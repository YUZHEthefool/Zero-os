[Switch to Chinese (切换到中文)](README_zh.md)

# Zero-OS

A security-first microkernel operating system written in Rust for x86_64 architecture.

**Design Principle:** Security > Efficiency > Speed

---

## 1. Overview

Zero-OS is an enterprise-grade microkernel inspired by Linux's modular design, featuring:

- **Memory Safety**: Built entirely in Rust with hardware protections (NX, W^X)
- **Process Isolation**: Per-process address spaces with COW (Copy-on-Write)
- **Preemptive Scheduling**: Multi-level feedback queue with priority-based selection
- **Capability-Based IPC**: Fine-grained access control for inter-process communication
- **Security Hardening**: W^X enforcement, identity map cleanup, CSPRNG (ChaCha20)

### Current Status (v0.6.0)

| Component | Status | Description |
|-----------|--------|-------------|
| Boot & Memory | Complete | UEFI boot, COW, guard pages, buddy allocator |
| Process Management | Complete | Per-process address space, fork/exec/wait |
| Scheduler | Complete | IRQ-safe MLFQ, preemptive scheduling |
| IPC | Complete | Pipes, message queues, futex, signals |
| Security | Phase 6 | W^X, RNG, 23 audit rounds (all issues fixed) |
| VFS | Complete | Basic VFS with stdin/stdout, blocking I/O |
| User Mode (Ring 3) | Complete | SYSCALL/SYSRET, 50+ syscalls, shell |
| Network | Not Started | - |
| SMP | Infrastructure | Per-CPU data, TLB shootdown placeholders |

---

## 2. Project Structure

```
Zero-OS/
├── bootloader/             # UEFI bootloader
│   └── src/main.rs         # ELF loader, page table setup
├── kernel/                 # Kernel workspace
│   ├── arch/               # x86_64 architecture code
│   │   ├── interrupts.rs   # IDT, exception handlers, PIC
│   │   ├── context_switch.rs # Full context save/restore
│   │   ├── syscall.rs      # SYSCALL/SYSRET entry (per-CPU)
│   │   └── gdt.rs          # GDT/TSS for user-kernel transitions
│   ├── mm/                 # Memory management
│   │   ├── memory.rs       # Heap allocator, frame allocator
│   │   ├── buddy_allocator.rs # Physical page allocator
│   │   ├── page_table.rs   # Page table manager
│   │   └── tlb_shootdown.rs # TLB invalidation (SMP-ready)
│   ├── sched/              # Scheduler
│   │   ├── scheduler.rs    # Basic round-robin
│   │   └── enhanced_scheduler.rs # MLFQ with priority
│   ├── ipc/                # Inter-process communication
│   │   ├── ipc.rs          # Capability-based endpoints
│   │   ├── pipe.rs         # Anonymous pipes
│   │   ├── futex.rs        # User-space fast mutex
│   │   └── sync.rs         # WaitQueue, KMutex, Semaphore
│   ├── drivers/            # Device drivers
│   │   ├── vga_buffer.rs   # VGA text mode / GOP framebuffer
│   │   ├── serial.rs       # UART 16550
│   │   └── keyboard.rs     # PS/2 keyboard with wait queue
│   ├── kernel_core/        # Core kernel
│   │   ├── process.rs      # PCB, process table
│   │   ├── fork.rs         # Fork with COW + TLB shootdown
│   │   ├── syscall.rs      # 50+ system calls
│   │   ├── signal.rs       # POSIX signals
│   │   └── elf_loader.rs   # ELF binary loading
│   ├── security/           # Security hardening
│   │   ├── wxorx.rs        # W^X policy validation
│   │   ├── memory_hardening.rs # Identity map cleanup, NX
│   │   └── rng.rs          # RDRAND/RDSEED, ChaCha20 CSPRNG
│   ├── cpu_local/          # Per-CPU data structures
│   ├── src/main.rs         # Kernel entry point
│   └── kernel.ld           # Linker script
├── userspace/              # User-space programs
│   └── src/
│       ├── shell.rs        # Interactive shell
│       └── syscall.rs      # Syscall wrappers
└── Makefile                # Build system
```

---

## 3. Core Components

### 3.1 Boot Flow

1. UEFI bootloader loads `kernel.elf` from ESP
2. Sets up 4-level paging with 2MB huge pages:
   - Identity maps first 4GB for hardware access
   - Maps high-half kernel at `0xFFFFFFFF80000000`
3. Kernel entry at `0xFFFFFFFF80100000`

### 3.2 Memory Management

- **Buddy Allocator**: Physical page allocation with coalescing
- **LockedHeap**: Thread-safe kernel heap
- **COW (Copy-on-Write)**: Efficient fork with shared pages
- **Guard Pages**: Stack overflow protection
- **Page Zeroing**: Prevents information leaks

### 3.3 Process Management

- **PCB**: Process Control Block with 176-byte context
- **Per-Process Address Space**: CR3 switching on context switch
- **Fork**: Full COW implementation with refcounted pages
- **Exec**: ELF loader with proper argument passing
- **Wait/Exit**: Parent-child synchronization with zombie cleanup

### 3.4 Scheduler

- **Multi-Level Feedback Queue**: Priority-based selection
- **Time Slicing**: Automatic priority adjustment
- **IRQ Safety**: All operations wrapped with `without_interrupts`
- **NEED_RESCHED**: Deferred scheduling from interrupt context

### 3.5 IPC (Inter-Process Communication)

- **Message Queues**: Capability-based endpoint access
- **Pipes**: Anonymous pipes with blocking I/O
- **Futex**: User-space fast mutex for synchronization
- **Signals**: POSIX-like signal handling (SIGKILL, SIGSTOP, SIGCONT, etc.)

### 3.6 Security (Phase 6)

- **W^X Enforcement**: Validates no pages are writable+executable
- **Identity Map Hardening**: Remove writable flag after boot
- **NX Enforcement**: No-execute bit on data pages
- **CSPRNG**: ChaCha20-based RNG seeded from RDRAND/RDSEED
- **TLB Shootdown**: Cross-CPU TLB invalidation infrastructure (SMP-ready)
- **Per-CPU Data**: Syscall scratch stacks isolated per CPU

### 3.7 User Mode (Ring 3)

- **SYSCALL/SYSRET**: Fast system call entry via MSR configuration
- **50+ Syscalls**: fork, exec, read, write, mmap, munmap, etc.
- **User-Kernel Isolation**: Separate address spaces with SMAP-ready guards
- **Interactive Shell**: Command-line interface with blocking I/O
- **FPU/SIMD Support**: FXSAVE64/FXRSTOR64 state preservation

---

## 4. Build and Run

### Prerequisites

- Rust nightly with `rust-src` and `llvm-tools-preview`
- QEMU with OVMF for UEFI boot
- GNU Make

### Build Commands

```bash
# Build everything
make build

# Build and run in QEMU (graphical)
make run

# Run with serial output to terminal
make run-serial

# Debug with GDB (connects on :1234)
make debug

# Clean build artifacts
make clean
```

### Running with Hardware RNG

To enable RDRAND/RDSEED support in QEMU:

```bash
qemu-system-x86_64 -cpu host -enable-kvm ...
# Or use a CPU model that supports RDRAND:
qemu-system-x86_64 -cpu Haswell ...
```

---

## 5. Security Audit Status

The project has undergone **23 security audit rounds**:

| Metric | Value |
|--------|-------|
| Total Issues Identified | 82+ |
| Issues Fixed | 100% |
| Latest Audit | Round 23 (2025-12-19) |

### Round 23 Highlights

- **R23-1**: COW TLB shootdown infrastructure (SMP-ready)
- **R23-2**: Per-CPU syscall scratch stacks
- **R23-3**: Two-phase munmap with TLB invalidation
- **R23-4/R23-5**: Blocking stdin implementation


---

## 6. Roadmap

### Completed (Phase 0-6)

- UEFI Boot with ELF loading
- Memory management (heap, buddy allocator, COW)
- Process management (fork, exec, wait, exit)
- Preemptive scheduler (MLFQ)
- IPC (pipes, message queues, futex, signals)
- Security hardening (W^X, NX, CSPRNG)
- User Mode (Ring 3) with SYSCALL/SYSRET
- VFS with blocking stdin/stdout
- 23 security audit rounds completed

### In Progress

- SMP foundation (per-CPU data, TLB shootdown infrastructure)
- IPI-based TLB invalidation
- Capability Framework
- MAC/LSM Security Hooks

### Future

- Network stack with firewall
- Full SMP (multi-core scheduling)
- Container/namespace isolation

See [roadmap-enterprise.md](roadmap-enterprise.md) for the complete enterprise security roadmap.

---

## 7. Contributing

1. All changes require code review
2. Run `make build` before committing
3. New features need documentation updates
4. Bug fixes should include regression tests

---

## 8. License

This project is for educational and research purposes.

---

## 9. References

- [OSDev Wiki](https://wiki.osdev.org)
- [Writing an OS in Rust](https://os.phil-opp.com)
- [Linux Kernel Source](https://kernel.org)
- [seL4 Microkernel](https://sel4.systems)
