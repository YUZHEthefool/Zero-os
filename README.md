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

### Current Status (v0.3.1)

| Component | Status | Description |
|-----------|--------|-------------|
| Boot & Memory | Complete | UEFI boot, COW, guard pages, buddy allocator |
| Process Management | Complete | Per-process address space, fork/exec/wait |
| Scheduler | Complete | IRQ-safe MLFQ, preemptive scheduling |
| IPC | Complete | Pipes, message queues, futex, signals |
| Security | Phase 0 | W^X validation, RNG, identity map hardening |
| VFS | Not Started | - |
| User Mode (Ring 3) | Not Started | - |
| Network | Not Started | - |
| SMP | Not Started | - |

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
│   │   └── gdt.rs          # GDT/TSS for user-kernel transitions
│   ├── mm/                 # Memory management
│   │   ├── memory.rs       # Heap allocator, frame allocator
│   │   ├── buddy_allocator.rs # Physical page allocator
│   │   └── page_table.rs   # Page table manager
│   ├── sched/              # Scheduler
│   │   ├── scheduler.rs    # Basic round-robin
│   │   └── enhanced_scheduler.rs # MLFQ with priority
│   ├── ipc/                # Inter-process communication
│   │   ├── ipc.rs          # Capability-based endpoints
│   │   ├── pipe.rs         # Anonymous pipes
│   │   ├── futex.rs        # User-space fast mutex
│   │   └── sync.rs         # WaitQueue, KMutex, Semaphore
│   ├── drivers/            # Device drivers
│   │   ├── vga_buffer.rs   # VGA text mode
│   │   └── serial.rs       # UART 16550
│   ├── kernel_core/        # Core kernel
│   │   ├── process.rs      # PCB, process table
│   │   ├── fork.rs         # Fork with COW
│   │   ├── syscall.rs      # 50+ system calls
│   │   ├── signal.rs       # POSIX signals
│   │   └── elf_loader.rs   # ELF binary loading
│   ├── security/           # Security hardening (NEW)
│   │   ├── wxorx.rs        # W^X policy validation
│   │   ├── memory_hardening.rs # Identity map cleanup, NX
│   │   └── rng.rs          # RDRAND/RDSEED, ChaCha20 CSPRNG
│   ├── src/main.rs         # Kernel entry point
│   └── kernel.ld           # Linker script
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

### 3.6 Security (Phase 0)

- **W^X Enforcement**: Validates no pages are writable+executable
- **Identity Map Hardening**: Remove writable flag after boot
- **NX Enforcement**: No-execute bit on data pages
- **CSPRNG**: ChaCha20-based RNG seeded from RDRAND/RDSEED

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

The project has undergone 13 security audit rounds:

| Metric | Value |
|--------|-------|
| Total Issues Identified | 70 |
| Issues Fixed | 62 (89%) |
| Open Issues | 8 (deferred to future phases) |

See [qa-2025-12-11.md](qa-2025-12-11.md) for detailed audit reports.

---

## 6. Roadmap

### Completed (Phase 0-3)
- UEFI Boot with ELF loading
- Memory management (heap, buddy allocator, COW)
- Process management (fork, exec, wait, exit)
- Preemptive scheduler (MLFQ)
- IPC (pipes, message queues, futex, signals)
- Security hardening foundation

### In Progress (Phase 4+)
- VFS (Virtual File System)
- User Mode (Ring 3) with syscall entry
- Capability Framework
- MAC/LSM Security Hooks

### Future
- Network stack with firewall
- SMP (multi-core support)
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
