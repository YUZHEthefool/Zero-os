.PHONY: all build build-shell run run-shell run-shell-gui clean

OVMF_PATH = $(shell \
	if [ -f /usr/share/qemu/OVMF.fd ]; then \
		echo /usr/share/qemu/OVMF.fd; \
	elif [ -f /usr/share/ovmf/OVMF.fd ]; then \
		echo /usr/share/ovmf/OVMF.fd; \
	elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then \
		echo /usr/share/OVMF/OVMF_CODE.fd; \
	else \
		find /usr/share/OVMF/ -type f -name "OVMF_CODE*.fd" 2>/dev/null | head -n 1; \
	fi)
QEMU = qemu-system-x86_64
ESP_DIR = $(shell pwd)/esp/EFI/BOOT
KERNEL_LD = $(shell pwd)/kernel/kernel.ld

all: build

build:
	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成 ==="

# Build with interactive shell instead of hello test
build-shell:
	@echo "=== 构建 Shell 用户程序 ==="
	cd userspace && \
	cargo build --release --bin shell --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	cp userspace/target/x86_64-unknown-none/release/shell kernel/src/shell.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Shell ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features shell

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Shell模式）==="

# Build with syscall test program
build-syscall-test:
	@echo "=== 构建 Syscall Test 用户程序 ==="
	cd userspace && \
	cargo build --release --bin syscall_test --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	cp userspace/target/x86_64-unknown-none/release/syscall_test kernel/src/syscall_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Syscall Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features syscall_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Syscall Test模式）==="

# Run syscall test (serial output)
run-syscall-test: build-syscall-test
	@echo "=== 启动内核（Syscall Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Build with musl test program
build-musl-test:
	@echo "=== 编译 musl 测试程序 ==="
	cd userspace && musl-gcc -static -o hello_musl.elf hello_musl.c
	cp userspace/hello_musl.elf kernel/src/musl_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Musl Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features musl_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== musl ELF 信息 ==="
	@readelf -h kernel/src/musl_test.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Musl Test模式）==="

# Run musl test (serial output)
run-musl-test: build-musl-test
	@echo "=== 启动内核（Musl Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Build with clone test program
build-clone-test:
	@echo "=== 编译 clone 测试程序 ==="
	cd userspace && musl-gcc -static -o clone_test.elf clone_test.c
	cp userspace/clone_test.elf kernel/src/clone_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi

	@echo "=== 构建 Kernel (Bare Metal) with Clone Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C relocation-model=static -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features clone_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== clone ELF 信息 ==="
	@readelf -h kernel/src/clone_test.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Clone Test模式）==="

# Run clone test (serial output)
run-clone-test: build-clone-test
	@echo "=== 启动内核（Clone Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# 通用QEMU参数
# -vga std: 强制使用标准VGA模式，确保0xB8000文本缓冲区可用
QEMU_COMMON = -bios $(OVMF_PATH) \
	-drive format=raw,file=fat:rw:esp \
	-m 256M \
	-vga std \
	-no-reboot -no-shutdown

# 默认运行 - 图形窗口模式（可看到VGA输出）
run: build
	@echo "=== 启动内核（图形窗口模式）==="
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON)

# 串口输出模式 - 通过串口查看内核输出
run-serial: build
	@echo "=== 启动内核（串口输出模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Shell模式 - 运行交互式Shell（串口输出）
run-shell: build-shell
	@echo "=== 启动内核（Shell串口模式）==="
	@echo "提示：这是一个交互式Shell，输入 help 查看可用命令"
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Shell图形模式 - 运行交互式Shell（VGA窗口 + PS/2键盘）
run-shell-gui: build-shell
	@echo "=== 启动内核（Shell图形模式）==="
	@echo "提示：这是一个交互式Shell，输入 help 查看可用命令"
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON)

# 调试模式 - 显示详细的CPU状态和中断信息
run-debug: build
	@echo "=== 启动内核（调试模式）==="
	@echo "提示：查看详细的CPU状态、中断和内存访问信息"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-serial mon:stdio \
		-d int,cpu_reset \
		-D qemu-debug.log

# 详细调试模式 - 记录更多信息到文件
run-verbose: build
	@echo "=== 启动内核（详细调试模式）==="
	@echo "提示：所有调试信息将记录到qemu-verbose.log"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-d int,cpu,mmu,guest_errors \
		-D qemu-verbose.log

# GDB调试模式 - 等待GDB连接
debug: build
	@echo "=== 启动内核（GDB调试模式）==="
	@echo "在另一个终端运行: gdb esp/kernel.elf"
	@echo "然后在GDB中执行: target remote :1234"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-s -S

# 组合模式 - 图形窗口 + 串口输出
run-both: build
	@echo "=== 启动内核（图形+串口模式）==="
	@echo "提示：VGA输出在图形窗口，串口输出在终端"
	$(QEMU) $(QEMU_COMMON) \
		-serial stdio

# 测试模式 - 自动退出（用于CI/CD）
test: build
	@echo "=== 启动内核（测试模式）==="
	timeout 10 $(QEMU) $(QEMU_COMMON) \
		-nographic || true

clean:
	cargo clean
	rm -rf kernel-target
	rm -rf bootloader-target
	rm -rf esp
	rm -f qemu-debug.log qemu-verbose.log

# 用于连接到QEMU监视器
monitor:
	telnet localhost 45454

# 显示帮助信息
help:
	@echo "Zero-OS Makefile 使用说明"
	@echo "================================"
	@echo "构建命令:"
	@echo "  make build        - 编译bootloader和kernel（默认hello程序）"
	@echo "  make build-shell  - 编译bootloader和kernel（交互式shell）"
	@echo ""
	@echo "运行模式:"
	@echo "  make run          - 图形窗口模式（推荐，可看到VGA输出）"
	@echo "  make run-serial   - 串口输出模式（终端显示）"
	@echo "  make run-shell    - 串口模式运行交互式Shell（终端输入输出）"
	@echo "  make run-shell-gui - 图形模式运行交互式Shell（VGA+键盘）"
	@echo "  make run-debug    - 调试模式（显示中断和CPU状态）"
	@echo "  make run-verbose  - 详细调试（记录到文件）"
	@echo "  make run-both     - 图形+串口组合模式"
	@echo "  make debug        - GDB调试模式（等待GDB连接）"
	@echo "  make test         - 测试模式（10秒后自动退出）"
	@echo ""
	@echo "清理命令:"
	@echo "  make clean        - 清理所有构建文件"
	@echo ""
	@echo "提示:"
	@echo "  - 图形模式可以看到完整的VGA输出和集成测试结果"
	@echo "  - 串口模式适合通过脚本自动化测试"
	@echo "  - Shell串口模式：使用终端输入输出，按Ctrl+A X退出"
	@echo "  - Shell图形模式：使用PS/2键盘和VGA显示，Ctrl+Alt+G释放鼠标"
	@echo "  - 调试模式会在qemu-debug.log中记录详细信息"
	@echo "  - 按Ctrl+C可以随时停止QEMU"
