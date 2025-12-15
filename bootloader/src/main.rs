#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use log::info;
use uefi::prelude::*;
use uefi::proto::console::text::{Key, ScanCode};
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::CStr16;
use uefi::Identify;
use xmas_elf::program::Type;
use xmas_elf::ElfFile;

/// 内存映射信息，传递给内核
#[repr(C)]
pub struct MemoryMapInfo {
    pub buffer: u64,           // 内存映射缓冲区地址
    pub size: usize,           // 缓冲区大小
    pub descriptor_size: usize, // 每个描述符的大小
    pub descriptor_version: u32, // 描述符版本
}

/// 引导信息结构，传递给内核
#[repr(C)]
pub struct BootInfo {
    pub memory_map: MemoryMapInfo,
}

#[entry]
fn efi_main(_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi::helpers::init(&mut system_table).unwrap();
    
    info!("Rust Microkernel Bootloader v0.1");
    info!("Initializing...");
    
    let entry_point = {
        let boot_services = system_table.boot_services();
        
        let fs_handle = boot_services
            .locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(
                &SimpleFileSystem::GUID,
            ))
            .expect("Failed to locate file system handles");

        let fs_handle = fs_handle[0];
        
        let mut fs = boot_services
            .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
            .expect("Failed to open file system protocol");

        let mut root_dir = fs.open_volume().expect("Failed to open root directory");

        info!("Loading kernel...");
        let kernel_path = CStr16::from_u16_with_nul(
            &[
                b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, 
                b'e' as u16, b'l' as u16, b'.' as u16, b'e' as u16,
                b'l' as u16, b'f' as u16, 0,
            ]
        ).unwrap();

        let mut kernel_file = root_dir
            .open(kernel_path, FileMode::Read, FileAttribute::empty())
            .expect("Failed to open kernel.elf")
            .into_regular_file()
            .expect("kernel.elf is not a regular file");

        let mut info_buffer = [0u8; 512];
        let info = kernel_file
            .get_info::<FileInfo>(&mut info_buffer)
            .expect("Failed to get file info");
        
        let file_size = info.file_size() as usize;

        let mut kernel_data = Vec::with_capacity(file_size);
        kernel_data.resize(file_size, 0);

        // 循环读取直到完整读取整个文件
        let mut total_read = 0usize;
        while total_read < file_size {
            let read_size = kernel_file
                .read(&mut kernel_data[total_read..])
                .expect("Failed to read kernel file");

            if read_size == 0 {
                // 读取返回0但文件未读完，说明发生了截断
                panic!("Kernel file read truncated: expected {} bytes, got {} bytes",
                       file_size, total_read);
            }
            total_read += read_size;
        }

        info!("Kernel loaded: {} bytes", total_read);

        info!("Parsing ELF...");
        let elf = ElfFile::new(&kernel_data).expect("Failed to parse ELF file");
        
        let entry_point = elf.header.pt2.entry_point();
        info!("Entry point: 0x{:x}", entry_point);
        
        assert_eq!(elf.header.pt1.magic, [0x7f, 0x45, 0x4c, 0x46], "Invalid ELF magic");

        // 首先，计算内核需要的总内存大小
        let mut min_addr = u64::MAX;
        let mut max_addr = 0u64;
        
        for program_header in elf.program_iter() {
            if program_header.get_type() != Ok(Type::Load) {
                continue;
            }
            let virt_addr = program_header.virtual_addr();
            let mem_size = program_header.mem_size();
            
            if virt_addr < min_addr {
                min_addr = virt_addr;
            }
            if virt_addr + mem_size > max_addr {
                max_addr = virt_addr + mem_size;
            }
        }
        
        // 分配一块连续的内存来容纳整个内核
        let kernel_phys_base = 0x100000u64;
        let kernel_size = (max_addr - min_addr) as usize;
        let pages = (kernel_size + 0xFFF) / 0x1000;
        
        info!("Allocating {} pages ({} bytes) for kernel at 0x{:x}", pages, kernel_size, kernel_phys_base);
        
        // 尝试在指定地址分配整块内存
        // 注意：页表映射硬编码依赖内核在 0x100000，因此必须在此地址分配成功
        let result = boot_services.allocate_pages(
            AllocateType::Address(kernel_phys_base),
            MemoryType::LOADER_DATA,
            pages,
        );

        if result.is_err() {
            panic!("FATAL: Cannot allocate kernel memory at required address 0x{:x}. \
                    Page table mappings require kernel at this fixed address. \
                    Ensure no UEFI runtime or reserved regions overlap.", kernel_phys_base);
        }

        // 使用固定的物理基址（页表映射依赖此值）
        let actual_phys_base = kernel_phys_base;

        info!("Kernel memory allocated at 0x{:x}", actual_phys_base);
        
        // 清零整块内存
        unsafe {
            core::ptr::write_bytes(actual_phys_base as *mut u8, 0, kernel_size);
        }
        
        // 加载所有程序段到物理地址 0x100000
        for program_header in elf.program_iter() {
            if program_header.get_type() != Ok(Type::Load) {
                continue;
            }

            let virt_addr = program_header.virtual_addr();
            let mem_size = program_header.mem_size();
            let file_size = program_header.file_size();
            let file_offset = program_header.offset();
            
            // 计算物理地址：虚拟地址 - 虚拟基址 + 物理基址
            // 虚拟基址是 min_addr (0xffffffff80000000)，物理基址是 actual_phys_base (0x100000)
            let phys_addr = actual_phys_base + (virt_addr - min_addr);
            
            // 清零整个段内存区域（包括.bss）
            unsafe {
                let dest = phys_addr as *mut u8;
                core::ptr::write_bytes(dest, 0, mem_size as usize);
            }
            
            // 复制段数据（file_size可能小于mem_size，剩余部分已清零）
            if file_size > 0 {
                unsafe {
                    let dest = phys_addr as *mut u8;
                    let src = kernel_data.as_ptr().add(file_offset as usize);
                    core::ptr::copy_nonoverlapping(src, dest, file_size as usize);
                }
            }
            
            info!("Loaded segment: virt=0x{:x}, phys=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
                  virt_addr, phys_addr, file_size, mem_size);
        }

        // 验证内核代码已加载到物理地址
        unsafe {
            let kernel_start = actual_phys_base as *const u8;
            let first_bytes = core::slice::from_raw_parts(kernel_start, 16);
            info!("First 16 bytes at phys 0x{:x}: {:x?}", actual_phys_base, first_bytes);
        }
        
        // 链接脚本现在将入口点设置为 0xffffffff80100000
        // 这对应物理地址 0x100000，通过页表映射正确
        info!("Using ELF entry point: 0x{:x}", entry_point);
        entry_point
    };
    
    // 测试 VGA 缓冲区是否可访问 - 在 info! 之前
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT->";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 24 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 24 * 2 + i as isize * 2 + 1) = 0x0E;
        }
    }
    
    info!("Automatically jumping to kernel...");

    // 分配 BootInfo 结构的内存（在低于 4GiB 的位置，便于恒等映射访问）
    let boot_info_ptr = {
        let boot_services = system_table.boot_services();
        let boot_info_page = boot_services
            .allocate_pages(AllocateType::MaxAddress(0xFFFF_FFFF), MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate boot info page");
        boot_info_page as *mut BootInfo
    };

    // 构建四级页表结构，将物理内核地址映射到高半区虚拟地址
    let (pml4_frame, entry_point_to_jump) = unsafe {
        // 最早的 VGA 写入 - 在任何其他操作之前
        let vga = 0xb8000 as *mut u8;
        let msg = b"SETUP";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 22 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 22 * 2 + i as isize * 2 + 1) = 0x09;
        }
        use x86_64::{
            PhysAddr,
            structures::paging::{
                PageTable, PageTableFlags as Flags, PhysFrame
            },
            registers::control::Cr3
        };

        let boot_services = system_table.boot_services();

        // 分配并清零 PML4
        let pml4_frame = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate PML4");
        let pml4_ptr = pml4_frame as *mut PageTable;
        core::ptr::write_bytes(pml4_ptr as *mut u8, 0, 4096);

        // 分配并清零 PDPT（高半区）
        let pdpt_high_frame = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate PDPT");
        let pdpt_high_ptr = pdpt_high_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_high_ptr as *mut u8, 0, 4096);

        // 分配并清零 PD
        let pd_frame = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate PD");
        let pd_ptr = pd_frame as *mut PageTable;
        core::ptr::write_bytes(pd_ptr as *mut u8, 0, 4096);

        // 使用2MB大页映射内核
        // 虚拟地址 0xffffffff80000000 映射到物理地址 0x100000
        // 由于使用2MB大页，必须从2MB边界开始，所以实际映射：
        // 虚拟 0xffffffff80000000 → 物理 0x0 (包含0x100000)
        // 这样内核在物理 0x100000 处的代码对应虚拟地址 0xffffffff80100000
        for i in 0..512usize {
            let phys_addr = PhysAddr::new((i as u64) * 0x200000);
            (&mut *pd_ptr)[i].set_addr(phys_addr, Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE);
        }

        // PDPT的第510项指向PD（对应虚拟地址的第30-38位）
        // 这映射虚拟地址 0xffffffff80000000-0xffffffffbfffffff (1GB) 到物理地址 0x0-0x3fffffff
        (&mut *pdpt_high_ptr)[510].set_addr(PhysAddr::new(pd_frame as u64), Flags::PRESENT | Flags::WRITABLE);

        // PML4的第511项指向高半区PDPT
        (&mut *pml4_ptr)[511].set_addr(PhysAddr::new(pdpt_high_frame as u64), Flags::PRESENT | Flags::WRITABLE);

        // 建立恒等映射以防止切换页表时崩溃
        let pdpt_low_frame = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate low PDPT");
        let pdpt_low_ptr = pdpt_low_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_low_ptr as *mut u8, 0, 4096);

        // 恒等映射前 4GB（需要4个PD，每个PD映射1GB）
        // 这样可以确保 bootloader 代码、UEFI 固件、硬件MMIO（包括APIC在0xfee00000）都能访问
        for pdpt_idx in 0..4usize {
            let pd_low_frame = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
                .expect("Failed to allocate low PD");
            let pd_low_ptr = pd_low_frame as *mut PageTable;
            core::ptr::write_bytes(pd_low_ptr as *mut u8, 0, 4096);

            // 每个PD映射512个2MB页（1GB）
            for i in 0..512usize {
                let phys_addr = PhysAddr::new(((pdpt_idx * 512 + i) as u64) * 0x200000);
                (&mut *pd_low_ptr)[i].set_addr(phys_addr, Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE);
            }
            
            (&mut *pdpt_low_ptr)[pdpt_idx].set_addr(PhysAddr::new(pd_low_frame as u64), Flags::PRESENT | Flags::WRITABLE);
        }
        
        (&mut *pml4_ptr)[0].set_addr(PhysAddr::new(pdpt_low_frame as u64), Flags::PRESENT | Flags::WRITABLE);

        // 设置递归页表槽 (PML4[510] → PML4 自身)
        // 这允许通过特殊虚拟地址访问任何页表帧，无论其物理地址在哪里
        // 递归映射虚拟地址计算：
        //   PML4:  0xFFFFFF7FBFDFE000
        //   PDPT:  0xFFFFFF7FBFC00000 + pml4_idx * 0x1000
        //   PD:    0xFFFFFF7F80000000 + pml4_idx * 0x200000 + pdpt_idx * 0x1000
        //   PT:    0xFFFFFF0000000000 + pml4_idx * 0x40000000 + pdpt_idx * 0x200000 + pd_idx * 0x1000
        (&mut *pml4_ptr)[510].set_addr(PhysAddr::new(pml4_frame as u64), Flags::PRESENT | Flags::WRITABLE);

        // 在切换前写 VGA 测试
        let vga = 0xb8000 as *mut u8;
        let msg1 = b"B4CR3";
        for (i, &byte) in msg1.iter().enumerate() {
            *vga.offset(80 * 23 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 23 * 2 + i as isize * 2 + 1) = 0x0A;
        }

        // 加载新的页表
        Cr3::write(PhysFrame::containing_address(PhysAddr::new(pml4_frame as u64)), Cr3::read().1);
        
        // 在切换后写 VGA 测试
        let msg2 = b"AFCR3";
        for (i, &byte) in msg2.iter().enumerate() {
            *vga.offset(80 * 23 * 2 + (i + 6) as isize * 2) = byte;
            *vga.offset(80 * 23 * 2 + (i + 6) as isize * 2 + 1) = 0x0C;
        }
        
        (pml4_frame, entry_point)
    };

    // 预先分配一块低地址缓冲区，用于在退出后保存内存映射副本，确保恒等映射可访问
    // 64 页（256 KiB）足以容纳常见的内存映射
    let (memory_map_copy_ptr, memory_map_copy_len) = {
        let pages = 64usize;
        let addr = system_table
            .boot_services()
            .allocate_pages(
                AllocateType::MaxAddress(0xFFFF_FFFF),
                MemoryType::LOADER_DATA,
                pages,
            )
            .expect("Failed to allocate low memory map copy buffer");
        (addr as *mut u8, pages * 0x1000)
    };

    // 退出 UEFI 引导服务，获取最终的内存映射
    // 这必须在页表设置之后、跳转之前完成
    let memory_map = unsafe {
        let (_runtime_system_table, memory_map) = system_table
            .exit_boot_services(MemoryType::LOADER_DATA);
        memory_map
    };

    // 将内存映射信息填充到 BootInfo 结构中
    // 需要将内存映射复制到低于4GiB的缓冲区，因为原始映射可能在高地址
    unsafe {
        let (memory_map_bytes, memory_map_meta) = memory_map.as_raw();

        // 确保预分配的缓冲区足够大
        assert!(
            memory_map_meta.map_size <= memory_map_copy_len,
            "Memory map larger than reserved copy buffer"
        );

        // 复制内存映射到低地址缓冲区
        core::ptr::copy_nonoverlapping(
            memory_map_bytes.as_ptr(),
            memory_map_copy_ptr,
            memory_map_meta.map_size,
        );

        *boot_info_ptr = BootInfo {
            memory_map: MemoryMapInfo {
                buffer: memory_map_copy_ptr as u64,
                size: memory_map_meta.map_size,
                descriptor_size: memory_map_meta.desc_size,
                descriptor_version: memory_map_meta.desc_version,
            },
        };
        // 阻止 memory_map 被释放，因为内核需要访问它
        core::mem::forget(memory_map);
    }

    // CR3 切换后，直接写 VGA（exit_boot_services 后可能无法使用 UEFI 打印）
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"EXIT->";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 24 * 2 + (i + 6) as isize * 2) = byte;
            *vga.offset(80 * 24 * 2 + (i + 6) as isize * 2 + 1) = 0x0E;
        }
    }

    // 跳转到内核入口点 - 使用内联汇编确保正确跳转
    // 通过 rdi 传递 BootInfo 指针（System V AMD64 ABI 第一个参数）
    unsafe {
        core::arch::asm!(
            "mov rdi, {boot_info}",
            "jmp {entry}",
            boot_info = in(reg) boot_info_ptr as u64,
            entry = in(reg) entry_point_to_jump,
            options(noreturn)
        );
    }
}

fn wait_for_key(system_table: &mut SystemTable<Boot>) {
    let mut events = [system_table.stdin().wait_for_key_event().unwrap()];
    let _ = system_table
        .boot_services()
        .wait_for_event(&mut events);
        
    let _ = system_table.stdin().reset(false);
    
    match system_table.stdin().read_key() {
        Ok(Some(Key::Special(ScanCode::ESCAPE))) => {},
        _ => {}
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("BOOTLOADER PANIC: {}", info);
    
    // 在屏幕上显示 panic
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT PANIC!";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(i as isize * 2) = byte;
            *vga.offset(i as isize * 2 + 1) = 0x4F;
        }
    }
    
    loop {}
}
