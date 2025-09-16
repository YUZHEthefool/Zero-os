[Switch to English (切换到英文)](README.md)

# ZERO-os
## 1. 概述
这是一个用 Rust 编写的简单微内核，旨在探索操作系统内核的基本原理。它包括一个 UEFI 引导加载程序和一个具有基本功能的内核，例如内存管理、进程管理、IPC 和调度。该项目被组织为一个 Cargo 工作区，包含两个主要组件：`bootloader` 和 `kernel`。
---
## 2. 项目结构
项目工作区的组织结构如下（重构为 Linux 风格的模块化内核）：
```
ZERO-os/
├── bootloader/             # UEFI 引导加载程序
│   ├── src/
│   │   └── main.rs
│   └── Cargo.toml
├── kernel/                 # 内核工作区根目录
│   ├── arch/               # 体系结构相关代码 (中断、启动、分页、汇编助手)
│   │   └── lib.rs
│   ├── mm/                 # 内存管理
│   │   └── lib.rs
│   ├── sched/              # 调度器
│   │   └── lib.rs
│   ├── ipc/                # 进程间通信
│   │   └── lib.rs
│   ├── drivers/            # 设备驱动程序 (VGA, 串口等)
│   │   └── lib.rs
│   ├── kernel_core/        # 核心进程管理、系统调用
│   │   └── lib.rs
│   ├── src/
│   │   └── main.rs         # 内核入口和初始化
│   ├── kernel.ld           # 链接脚本
│   └── Cargo.toml
├── Cargo.toml              # 工作区配置
└── Makefile                # 构建脚本
```
### 2.1. 引导加载程序 (Bootloader)
`bootloader` 是一个 UEFI 应用程序，负责初始化系统和加载内核。它使用 `uefi` crate 与 UEFI 服务交互。
### 2.2. 内核 (Kernel)
`kernel` 是操作系统的核心，提供基本服务。
---
## 3. 核心组件
### 内核模块化组件 (Linux 风格)
#### `arch/`
体系结构相关代码，包括：
- 中断描述符表 (IDT) 初始化和处理程序
- 页错误和双重错误处理
- 分页设置和底层汇编助手
#### `mm/`
内存管理:
- 堆分配器初始化 (`LockedHeap`)
- 物理帧分配器
- 高半区内核内存映射
#### `sched/`
调度器:
- 简单的循环调度器
- 进程切换逻辑
#### `ipc/`
进程间通信:
- 消息队列实现
- 用于在进程之间发送和接收消息的机制
#### `drivers/`
设备驱动程序:
- VGA 文本模式输出
- 串口驱动程序
#### `kernel_core/`
核心内核服务:
- 进程结构和管理
- 系统调用接口和处理程序
---
## 4. 构建和运行
（本节是一个模板。您可能需要根据您的 `Makefile` 填写具体的命令。）
要构建项目，您通常需要 Rust nightly 工具链和 `cargo-xbuild`。
```sh
# 切换到正确的工具链
rustup override set nightly
# 构建内核
make build-kernel
# 构建引导加载程序
make build-bootloader
# 创建可引导镜像
make image
# 在 QEMU 中运行
make run
