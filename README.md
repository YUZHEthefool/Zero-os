[Switch to Chinese (切换到中文)](README_zh.md)

# ZERO-os

## 1. Overview

This is a simple microkernel written in Rust, designed to explore the basic principles of operating system kernels. It includes a UEFI bootloader and a kernel with basic features like memory management, process management, IPC, and scheduling. The project is structured as a Cargo workspace with two main components: `bootloader` and `kernel`.

---

## 2. Project Structure

The project workspace is organized as follows (restructured to Linux-style modular kernel):

```
ZERO-os/
├── bootloader/             # UEFI bootloader
│   ├── src/
│   │   └── main.rs
│   └── Cargo.toml
├── kernel/                 # Kernel workspace root
│   ├── arch/               # Architecture-specific code (interrupts, startup, paging, asm helpers)
│   │   └── lib.rs
│   ├── mm/                 # Memory management
│   │   └── lib.rs
│   ├── sched/              # Scheduler
│   │   └── lib.rs
│   ├── ipc/                # Inter-process communication
│   │   └── lib.rs
│   ├── drivers/            # Device drivers (VGA, serial, etc.)
│   │   └── lib.rs
│   ├── kernel_core/        # Core process management, syscalls
│   │   └── lib.rs
│   ├── src/
│   │   └── main.rs         # Kernel entry and initialization
│   ├── kernel.ld           # Linker script
│   └── Cargo.toml
├── Cargo.toml              # Workspace configuration
└── Makefile                # Build scripts
```

### 2.1. Bootloader

The `bootloader` is a UEFI application responsible for initializing the system and loading the kernel. It uses the `uefi` crate to interact with UEFI services.

### 2.2. Kernel

The `kernel` is the core of the operating system, providing fundamental services.

---

## 3. Core Components

### Kernel Modular Components (Linux-style)

#### `arch/`
Architecture-specific code, including:
- Interrupt Descriptor Table (IDT) initialization and handlers
- Page fault and double fault handling
- Paging setup and low-level assembly helpers

#### `mm/`
Memory management:
- Heap allocator initialization (`LockedHeap`)
- Physical frame allocator
- High-half kernel memory mapping

#### `sched/`
Scheduler:
- Simple round-robin scheduler
- Process switching logic

#### `ipc/`
Inter-process communication:
- Message queue implementation
- Mechanisms for sending and receiving messages between processes

#### `drivers/`
Device drivers:
- VGA text mode output
- Serial port driver

#### `kernel_core/`
Core kernel services:
- Process structure and management
- System call interface and handlers

---

## 4. Build and Run

(This section is a template. You may need to fill in specific commands based on your `Makefile`.)

To build the project, you typically need a Rust nightly toolchain and `cargo-xbuild`.

```sh
# Switch to the correct toolchain
rustup override set nightly

# Build the kernel
make build-kernel

# Build the bootloader
make build-bootloader

# Create a bootable image
make image

# Run in QEMU
make run
