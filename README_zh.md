[Switch to English (切换到英文)](README.md)

# Zero-OS

一个以安全为先的微内核操作系统，使用 Rust 编写，面向 x86_64 架构。

**设计原则：** 安全性 > 效率 > 速度

---

## 1. 概述

Zero-OS 是一个企业级微内核，灵感来自 Linux 的模块化设计，具有以下特性：

- **内存安全**：完全使用 Rust 编写，配合硬件保护（NX、W^X）
- **进程隔离**：每进程独立地址空间，支持 COW（写时复制）
- **抢占式调度**：多级反馈队列，基于优先级选择
- **基于能力的 IPC**：进程间通信的细粒度访问控制
- **安全加固**：W^X 强制执行、恒等映射清理、CSPRNG（ChaCha20）

### 当前状态 (v0.6.0)

| 组件 | 状态 | 描述 |
|------|------|------|
| 启动和内存 | 完成 | UEFI 启动、COW、守护页、伙伴分配器 |
| 进程管理 | 完成 | 每进程地址空间、fork/exec/wait |
| 调度器 | 完成 | IRQ 安全的 MLFQ、抢占式调度 |
| IPC | 完成 | 管道、消息队列、futex、信号 |
| 安全 | Phase 6 | W^X、RNG、23 轮审计（全部修复）|
| VFS | 完成 | 基础 VFS，stdin/stdout，阻塞 I/O |
| 用户模式 (Ring 3) | 完成 | SYSCALL/SYSRET、50+ 系统调用、Shell |
| 网络 | 未开始 | - |
| SMP | 基础设施 | Per-CPU 数据、TLB shootdown 占位符 |

---

## 2. 项目结构

```text
Zero-OS/
├── bootloader/             # UEFI 引导加载程序
│   └── src/main.rs         # ELF 加载器、页表设置
├── kernel/                 # 内核工作区
│   ├── arch/               # x86_64 架构代码
│   │   ├── interrupts.rs   # IDT、异常处理、PIC
│   │   ├── context_switch.rs # 完整上下文保存/恢复
│   │   ├── syscall.rs      # SYSCALL/SYSRET 入口（per-CPU）
│   │   └── gdt.rs          # 用户-内核转换的 GDT/TSS
│   ├── mm/                 # 内存管理
│   │   ├── memory.rs       # 堆分配器、帧分配器
│   │   ├── buddy_allocator.rs # 物理页分配器
│   │   ├── page_table.rs   # 页表管理器
│   │   └── tlb_shootdown.rs # TLB 失效（SMP 就绪）
│   ├── sched/              # 调度器
│   │   ├── scheduler.rs    # 基础轮转调度
│   │   └── enhanced_scheduler.rs # 带优先级的 MLFQ
│   ├── ipc/                # 进程间通信
│   │   ├── ipc.rs          # 基于能力的端点
│   │   ├── pipe.rs         # 匿名管道
│   │   ├── futex.rs        # 用户空间快速互斥锁
│   │   └── sync.rs         # WaitQueue、KMutex、Semaphore
│   ├── drivers/            # 设备驱动
│   │   ├── vga_buffer.rs   # VGA 文本模式 / GOP 帧缓冲
│   │   ├── serial.rs       # UART 16550
│   │   └── keyboard.rs     # PS/2 键盘（带等待队列）
│   ├── kernel_core/        # 核心内核
│   │   ├── process.rs      # PCB、进程表
│   │   ├── fork.rs         # 带 COW + TLB shootdown 的 Fork
│   │   ├── syscall.rs      # 50+ 系统调用
│   │   ├── signal.rs       # POSIX 信号
│   │   └── elf_loader.rs   # ELF 二进制加载
│   ├── security/           # 安全加固
│   │   ├── wxorx.rs        # W^X 策略验证
│   │   ├── memory_hardening.rs # 恒等映射清理、NX
│   │   └── rng.rs          # RDRAND/RDSEED、ChaCha20 CSPRNG
│   ├── cpu_local/          # Per-CPU 数据结构
│   ├── src/main.rs         # 内核入口点
│   └── kernel.ld           # 链接脚本
├── userspace/              # 用户空间程序
│   └── src/
│       ├── shell.rs        # 交互式 Shell
│       └── syscall.rs      # 系统调用封装
└── Makefile                # 构建系统
```

---

## 3. 核心组件

### 3.1 启动流程

1. UEFI 引导加载程序从 ESP 加载 `kernel.elf`
2. 设置 4 级分页，使用 2MB 大页：
   - 恒等映射前 4GB 用于硬件访问
   - 高半区内核映射到 `0xFFFFFFFF80000000`
3. 内核入口点在 `0xFFFFFFFF80100000`

### 3.2 内存管理

- **伙伴分配器**：物理页分配与合并
- **LockedHeap**：线程安全的内核堆
- **COW（写时复制）**：高效的 fork，共享页面
- **守护页**：栈溢出保护
- **页面清零**：防止信息泄露

### 3.3 进程管理

- **PCB**：进程控制块，176 字节上下文
- **每进程地址空间**：上下文切换时切换 CR3
- **Fork**：完整的 COW 实现，带引用计数
- **Exec**：ELF 加载器，支持参数传递
- **Wait/Exit**：父子进程同步，僵尸进程清理

### 3.4 调度器

- **多级反馈队列**：基于优先级选择
- **时间片**：自动优先级调整
- **IRQ 安全**：所有操作使用 `without_interrupts` 包装
- **NEED_RESCHED**：中断上下文中的延迟调度

### 3.5 IPC（进程间通信）

- **消息队列**：基于能力的端点访问
- **管道**：带阻塞 I/O 的匿名管道
- **Futex**：用户空间快速互斥锁
- **信号**：类 POSIX 信号处理（SIGKILL、SIGSTOP、SIGCONT 等）

### 3.6 安全（Phase 6）

- **W^X 强制执行**：验证没有页面同时可写和可执行
- **恒等映射加固**：启动后移除可写标志
- **NX 强制执行**：数据页设置不可执行位
- **CSPRNG**：基于 ChaCha20 的 RNG，由 RDRAND/RDSEED 提供种子
- **TLB Shootdown**：跨 CPU TLB 失效基础设施（SMP 就绪）
- **Per-CPU 数据**：每 CPU 独立的系统调用临时栈

### 3.7 用户模式（Ring 3）

- **SYSCALL/SYSRET**：通过 MSR 配置的快速系统调用入口
- **50+ 系统调用**：fork、exec、read、write、mmap、munmap 等
- **用户-内核隔离**：独立地址空间，SMAP 就绪的安全检查
- **交互式 Shell**：带阻塞 I/O 的命令行界面
- **FPU/SIMD 支持**：FXSAVE64/FXRSTOR64 状态保存

---

## 4. 构建和运行

### 前置条件

- Rust nightly，带 `rust-src` 和 `llvm-tools-preview`
- 带 OVMF 的 QEMU（UEFI 启动）
- GNU Make

### 构建命令

```bash
# 构建所有组件
make build

# 构建并在 QEMU 中运行（图形界面）
make run

# 串口输出到终端
make run-serial

# 使用 GDB 调试（连接到 :1234）
make debug

# 清理构建产物
make clean
```

### 启用硬件 RNG 运行

在 QEMU 中启用 RDRAND/RDSEED 支持：

```bash
qemu-system-x86_64 -cpu host -enable-kvm ...
# 或使用支持 RDRAND 的 CPU 型号：
qemu-system-x86_64 -cpu Haswell ...
```

---

## 5. 安全审计状态

项目已经过 **23 轮安全审计**：

| 指标 | 数值 |
|------|------|
| 发现的问题总数 | 82+ |
| 已修复问题 | 100% |
| 最新审计 | 第 23 轮 (2025-12-19) |

### 第 23 轮重点

- **R23-1**：COW TLB shootdown 基础设施（SMP 就绪）
- **R23-2**：Per-CPU 系统调用临时栈
- **R23-3**：两阶段 munmap 与 TLB 失效
- **R23-4/R23-5**：阻塞式 stdin 实现


---

## 6. 路线图

### 已完成 (Phase 0-6)

- UEFI 启动与 ELF 加载
- 内存管理（堆、伙伴分配器、COW）
- 进程管理（fork、exec、wait、exit）
- 抢占式调度器（MLFQ）
- IPC（管道、消息队列、futex、信号）
- 安全加固（W^X、NX、CSPRNG）
- 用户模式（Ring 3）与 SYSCALL/SYSRET
- VFS 与阻塞式 stdin/stdout
- 23 轮安全审计全部完成

### 进行中

- SMP 基础（per-CPU 数据、TLB shootdown 基础设施）
- 基于 IPI 的 TLB 失效
- 能力框架
- MAC/LSM 安全钩子

### 未来计划

- 带防火墙的网络栈
- 完整 SMP（多核调度）
- 容器/命名空间隔离

完整的企业安全路线图请参见 [roadmap-enterprise.md](roadmap-enterprise.md)。

---

## 7. 贡献指南

1. 所有更改需要代码审查
2. 提交前运行 `make build`
3. 新功能需要更新文档
4. Bug 修复应包含回归测试

---

## 8. 许可证

本项目用于教育和研究目的。

---

## 9. 参考资料

- [OSDev Wiki](https://wiki.osdev.org)
- [用 Rust 写操作系统](https://os.phil-opp.com)
- [Linux 内核源码](https://kernel.org)
- [seL4 微内核](https://sel4.systems)
