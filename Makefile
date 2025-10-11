.PHONY: all build run clean

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

run: build
	$(QEMU) \
		-bios $(OVMF_PATH) \
		-drive format=raw,file=fat:rw:esp \
		-m 256M \
		-nographic \
		-serial mon:stdio \
		-d int -no-reboot -no-shutdown

debug: build
	$(QEMU) \
		-bios $(OVMF_PATH) \
		-drive format=raw,file=fat:rw:esp \
		-m 256M \
		-nographic \
		-s -S

clean:
	cargo clean
	rm -rf kernel-target
	rm -rf bootloader-target
	rm -rf esp

# 用于连接到QEMU监视器
monitor:
	telnet localhost 45454
