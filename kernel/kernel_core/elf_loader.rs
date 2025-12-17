//! ELF 装载器
//!
//! 负责解析并加载 ELF64 可执行文件到用户地址空间
//!
//! 功能：
//! - 验证 ELF64 格式（x86_64, Executable）
//! - 按 PT_LOAD 段映射用户地址空间
//! - 处理 BSS（memsz > filesz 部分清零）
//! - 返回入口点和用户栈顶

use alloc::vec::Vec;
use core::{cmp, ptr};
use mm::memory::FrameAllocator;
use mm::{page_table, phys_to_virt};
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};
use xmas_elf::{
    header::{Class, Machine, Type as ElfType},
    program::Type as PhType,
    ElfFile,
};

/// 用户地址空间起始（4MB，为内核预留低地址）
pub const USER_BASE: usize = 0x0000_0000_0040_0000;

/// 用户栈顶地址（用户空间顶部 - 8KB 守护页）
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// 用户栈大小（默认 2MB）
pub const USER_STACK_SIZE: usize = 0x20_0000;

/// 页大小
const PAGE_SIZE: usize = 0x1000;

/// ELF 加载错误
#[derive(Debug, Clone, Copy)]
pub enum ElfLoadError {
    /// ELF 魔数无效
    InvalidMagic,
    /// 不支持的 ELF 类型（非 64 位）
    UnsupportedClass,
    /// 不支持的机器架构（非 x86_64）
    UnsupportedMachine,
    /// 不支持的文件类型（非可执行文件）
    UnsupportedType,
    /// 非小端格式
    NotLittleEndian,
    /// 段地址超出允许范围
    SegmentOutOfRange,
    /// 同时可写可执行的段被拒绝（W^X 安全策略）
    WritableExecutableSegment,
    /// 段与栈区域重叠
    OverlapWithStack,
    /// 页映射失败
    MapFailed,
    /// 段数据越界
    OutOfBounds,
    /// 物理内存不足
    OutOfMemory,
}

/// ELF 加载结果
pub struct ElfLoadResult {
    /// 程序入口点地址
    pub entry: u64,
    /// 用户栈顶地址
    pub user_stack_top: u64,
}

/// 为当前进程地址空间加载 ELF 映像
///
/// # 前置条件
///
/// - 调用方已切换到目标进程的地址空间（当前 CR3 是目标进程的页表）
/// - 用户空间未被映射（除内核高半区外）
///
/// # Arguments
///
/// * `image` - ELF 文件的原始字节
///
/// # Returns
///
/// 成功返回入口点和用户栈顶，失败返回错误码
pub fn load_elf(image: &[u8]) -> Result<ElfLoadResult, ElfLoadError> {
    let elf = ElfFile::new(image).map_err(|_| ElfLoadError::InvalidMagic)?;

    // 验证 ELF 头
    validate_elf_header(&elf)?;

    // 加载所有 PT_LOAD 段
    for ph in elf.program_iter() {
        if ph.get_type() == Ok(PhType::Load) {
            load_segment(&elf, &ph)?;
        }
    }

    // 分配用户栈
    allocate_user_stack()?;

    Ok(ElfLoadResult {
        entry: elf.header.pt2.entry_point(),
        user_stack_top: USER_STACK_TOP,
    })
}

/// 验证 ELF 头
fn validate_elf_header(elf: &ElfFile) -> Result<(), ElfLoadError> {
    let hdr = &elf.header;

    // 验证魔数
    if hdr.pt1.magic != [0x7F, b'E', b'L', b'F'] {
        return Err(ElfLoadError::InvalidMagic);
    }

    // 验证 64 位
    match hdr.pt1.class() {
        Class::SixtyFour => {}
        _ => return Err(ElfLoadError::UnsupportedClass),
    }

    // 验证小端
    match hdr.pt1.data() {
        xmas_elf::header::Data::LittleEndian => {}
        _ => return Err(ElfLoadError::NotLittleEndian),
    }

    // 验证 x86_64
    if hdr.pt2.machine().as_machine() != Machine::X86_64 {
        return Err(ElfLoadError::UnsupportedMachine);
    }

    // 验证可执行文件
    if hdr.pt2.type_().as_type() != ElfType::Executable {
        return Err(ElfLoadError::UnsupportedType);
    }

    Ok(())
}

/// 加载单个程序段
fn load_segment(elf: &ElfFile, ph: &xmas_elf::program::ProgramHeader) -> Result<(), ElfLoadError> {
    let vaddr = ph.virtual_addr() as usize;
    let memsz = ph.mem_size() as usize;
    let filesz = ph.file_size() as usize;
    let offset = ph.offset() as usize;

    // 跳过大小为 0 的段
    if memsz == 0 {
        return Ok(());
    }

    // 边界检查
    let end = vaddr.checked_add(memsz).ok_or(ElfLoadError::OutOfBounds)?;

    if vaddr < USER_BASE {
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    if end as u64 >= USER_STACK_TOP - USER_STACK_SIZE as u64 {
        return Err(ElfLoadError::OverlapWithStack);
    }

    // 验证文件数据边界
    if offset.saturating_add(filesz) > elf.input.len() {
        return Err(ElfLoadError::OutOfBounds);
    }

    // 【W-1 安全修复】W^X (Write XOR Execute) 检查
    // 拒绝同时可写可执行的段，防止代码注入攻击
    // 恶意程序可能利用 RWX 段在运行时注入并执行任意代码
    let writable = ph.flags().is_write();
    let executable = ph.flags().is_execute();
    if writable && executable {
        return Err(ElfLoadError::WritableExecutableSegment);
    }

    // 计算需要映射的页
    let page_base = vaddr & !(PAGE_SIZE - 1);
    let page_offset = vaddr - page_base;
    let map_len = page_offset + memsz;
    let page_count = (map_len + PAGE_SIZE - 1) / PAGE_SIZE;

    // 确定页权限
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if ph.flags().is_write() {
        flags |= PageTableFlags::WRITABLE;
    }
    if !ph.flags().is_execute() {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    // 映射页面（带回滚支持）
    let mut frame_alloc = FrameAllocator::new();
    let mut mapped: Vec<(Page<Size4KiB>, PhysFrame<Size4KiB>)> = Vec::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            for i in 0..page_count {
                let va = VirtAddr::new((page_base + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                let frame = frame_alloc
                    .allocate_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                if let Err(_) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    // 【关键修复】回滚已映射的页，避免泄漏物理帧或留下半成品映射
                    frame_alloc.deallocate_frame(frame);
                    for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                        if mgr.unmap_page(cleanup_page).is_ok() {
                            frame_alloc.deallocate_frame(cleanup_frame);
                        }
                    }
                    return Err(ElfLoadError::MapFailed);
                }

                mapped.push((page, frame));
            }
            Ok(())
        })?;
    }

    // 【修复】使用直映物理地址访问内存，避免依赖当前 CR3
    // 首先清零所有映射的页面（防止信息泄漏）
    for (_, frame) in mapped.iter() {
        let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
        unsafe { ptr::write_bytes(base, 0, PAGE_SIZE); }
    }

    // 复制文件内容到正确的偏移位置
    let mut remaining_copy = filesz;
    let mut src_off = offset;
    for (idx, (_, frame)) in mapped.iter().enumerate() {
        if remaining_copy == 0 { break; }
        let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
        let start = if idx == 0 { page_offset } else { 0 };
        let len = cmp::min(PAGE_SIZE - start, remaining_copy);
        unsafe {
            ptr::copy_nonoverlapping(
                elf.input.as_ptr().add(src_off),
                base.add(start),
                len,
            );
        }
        remaining_copy -= len;
        src_off += len;
    }

    Ok(())
}

/// 分配用户栈
fn allocate_user_stack() -> Result<(), ElfLoadError> {
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    let page_count = USER_STACK_SIZE / PAGE_SIZE;

    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    // 【修复】带回滚支持的栈分配
    let mut frame_alloc = FrameAllocator::new();
    let mut mapped: Vec<(Page<Size4KiB>, PhysFrame<Size4KiB>)> = Vec::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            for i in 0..page_count {
                let va = VirtAddr::new((stack_base + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                let frame = frame_alloc
                    .allocate_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                if let Err(_) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    // 回滚已映射的页
                    frame_alloc.deallocate_frame(frame);
                    for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                        if mgr.unmap_page(cleanup_page).is_ok() {
                            frame_alloc.deallocate_frame(cleanup_frame);
                        }
                    }
                    return Err(ElfLoadError::MapFailed);
                }

                mapped.push((page, frame));
            }
            Ok(())
        })?;
    }

    // 【修复】使用直映物理地址清零栈区域
    let mut remaining = USER_STACK_SIZE;
    for (_, frame) in mapped.iter() {
        let base = unsafe { phys_to_virt(frame.start_address()).as_mut_ptr::<u8>() };
        let len = cmp::min(PAGE_SIZE, remaining);
        unsafe { ptr::write_bytes(base, 0, len); }
        remaining -= len;
        if remaining == 0 { break; }
    }

    Ok(())
}

/// 打印 ELF 文件信息（调试用）
pub fn print_elf_info(image: &[u8]) {
    if let Ok(elf) = ElfFile::new(image) {
        let hdr = &elf.header;
        println!("=== ELF Info ===");
        println!("Entry point: 0x{:x}", hdr.pt2.entry_point());
        println!("Program headers: {}", hdr.pt2.ph_count());

        for (i, ph) in elf.program_iter().enumerate() {
            if ph.get_type() == Ok(PhType::Load) {
                println!(
                    "  Segment {}: vaddr=0x{:x}, memsz=0x{:x}, filesz=0x{:x}",
                    i,
                    ph.virtual_addr(),
                    ph.mem_size(),
                    ph.file_size()
                );
            }
        }
    }
}
