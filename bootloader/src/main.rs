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
        
        let read_size = kernel_file
            .read(&mut kernel_data)
            .expect("Failed to read kernel file");
        
        info!("Kernel size: {} bytes", read_size);

        info!("Parsing ELF...");
        let elf = ElfFile::new(&kernel_data).expect("Failed to parse ELF file");
        
        let entry_point = elf.header.pt2.entry_point();
        info!("Entry point: 0x{:x}", entry_point);
        
        assert_eq!(elf.header.pt1.magic, [0x7f, 0x45, 0x4c, 0x46], "Invalid ELF magic");

        // 加载所有程序段到物理地址
        for program_header in elf.program_iter() {
            if program_header.get_type() != Ok(Type::Load) {
                continue;
            }

            let virt_addr = program_header.virtual_addr();
            let mem_size = program_header.mem_size();
            let file_size = program_header.file_size();
            let file_offset = program_header.offset();

            // 将高半区虚拟地址转换为物理地址（假设内核链接在0xffffffff80000000）
            let phys_addr = if virt_addr >= 0xffffffff80000000 {
                // 高半区地址，转换为物理地址（从0x100000开始）
                0x100000 + (virt_addr - 0xffffffff80000000)
            } else {
                // 低地址保持不变
                virt_addr
            };

            let pages = ((mem_size + 0xFFF) / 0x1000) as usize;
            
            // 在物理地址分配内存
            let result = boot_services.allocate_pages(
                AllocateType::Address(phys_addr),
                MemoryType::LOADER_DATA,
                pages,
            );
            
            if result.is_err() {
                info!("Failed to allocate at 0x{:x}, trying any address", phys_addr);
                // 如果指定地址失败，尝试任意地址
                let allocated = boot_services.allocate_pages(
                    AllocateType::AnyPages,
                    MemoryType::LOADER_DATA,
                    pages,
                ).expect("Failed to allocate memory for segment");
                info!("Allocated at 0x{:x}", allocated);
            }
            
            // 复制段数据到物理地址
            unsafe {
                let dest = phys_addr as *mut u8;
                let src = kernel_data.as_ptr().add(file_offset as usize);
                core::ptr::copy_nonoverlapping(src, dest, file_size as usize);
                
                if mem_size > file_size {
                    let bss_start = dest.add(file_size as usize);
                    let bss_size = (mem_size - file_size) as usize;
                    core::ptr::write_bytes(bss_start, 0, bss_size);
                }
            }
            
            info!("Loaded segment: virt=0x{:x}, phys=0x{:x}, size=0x{:x}", virt_addr, phys_addr, mem_size);
        }

        // 验证内核代码已加载到物理地址
        unsafe {
            // 检查物理地址处的内容
            let phys_entry = if entry_point >= 0xffffffff80000000 {
                0x100000 + (entry_point - 0xffffffff80000000)
            } else {
                entry_point
            };
            let kernel_start = phys_entry as *const u8;
            let first_bytes = core::slice::from_raw_parts(kernel_start, 16);
            info!("First 16 bytes at phys entry 0x{:x}: {:x?}", phys_entry, first_bytes);
        }
        
        entry_point
    };
    
    info!("Press any key to jump to kernel...");
    wait_for_key(&mut system_table);
    
    // 测试 VGA 缓冲区是否可访问
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT->";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 24 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 24 * 2 + i as isize * 2 + 1) = 0x0E;
        }
    }
    
    info!("Setting up paging for high-half kernel...");

    // 构建四级页表结构，将物理内核地址映射到高半区虚拟地址
    unsafe {
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

        // 建立 2MiB 大页映射，映射前16MB物理内存
        // 物理地址 0x100000 -> 虚拟地址 0xffffffff80000000
        for i in 0..8usize {
            let phys_addr = PhysAddr::new(0x100000 + (i as u64) * 0x200000);  // 每个大页2MB
            (&mut *pd_ptr)[i].set_addr(phys_addr, Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE);
        }

        // PDPT的第510项指向PD（对应虚拟地址的第30-38位）
        (&mut *pdpt_high_ptr)[510].set_addr(PhysAddr::new(pd_frame as u64), Flags::PRESENT | Flags::WRITABLE);

        // PML4的第511项指向高半区PDPT
        (&mut *pml4_ptr)[511].set_addr(PhysAddr::new(pdpt_high_frame as u64), Flags::PRESENT | Flags::WRITABLE);

        // 同时建立恒等映射以防止切换页表时崩溃
        let pdpt_low_frame = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate low PDPT");
        let pdpt_low_ptr = pdpt_low_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_low_ptr as *mut u8, 0, 4096);

        let pd_low_frame = boot_services.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate low PD");
        let pd_low_ptr = pd_low_frame as *mut PageTable;
        core::ptr::write_bytes(pd_low_ptr as *mut u8, 0, 4096);

        // 恒等映射前16MB
        for i in 0..8usize {
            let phys_addr = PhysAddr::new((i as u64) * 0x200000);
            (&mut *pd_low_ptr)[i].set_addr(phys_addr, Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE);
        }
        
        (&mut *pdpt_low_ptr)[0].set_addr(PhysAddr::new(pd_low_frame as u64), Flags::PRESENT | Flags::WRITABLE);
        (&mut *pml4_ptr)[0].set_addr(PhysAddr::new(pdpt_low_frame as u64), Flags::PRESENT | Flags::WRITABLE);

        info!("Page tables set up, switching CR3...");

        // 加载新的页表
        Cr3::write(PhysFrame::containing_address(PhysAddr::new(pml4_frame as u64)), Cr3::read().1);
    }

    info!("Jumping to kernel at entry point: 0x{:x}", entry_point);

    // 跳转到内核入口点
    unsafe {
        type KernelMain = extern "C" fn() -> !;
        let kernel_main: KernelMain = core::mem::transmute(entry_point);
        kernel_main();
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
