//! 页表管理器
//!
//! 提供对x86_64页表的完整管理功能

use x86_64::{
    structures::paging::{
        Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
        FrameAllocator, Mapper, OffsetPageTable, Translate,
    },
    PhysAddr, VirtAddr,
};
use spin::Mutex;

/// 页表管理器
pub struct PageTableManager {
    mapper: OffsetPageTable<'static>,
}

/// 基于当前活动的 CR3 构建临时页表管理器
///
/// 此函数在每次调用时从当前 CR3 读取页表根地址，确保始终操作正确的地址空间。
/// 这对于 COW 故障处理和 mmap/munmap 在多进程环境下正确工作至关重要。
///
/// # Safety
///
/// 调用者必须提供正确的物理内存偏移量。
/// 在回调函数执行期间，不得发生导致 CR3 切换的上下文切换。
pub unsafe fn with_current_manager<T, F>(physical_memory_offset: VirtAddr, f: F) -> T
where
    F: FnOnce(&mut PageTableManager) -> T,
{
    let level_4_table = active_level_4_table(physical_memory_offset);
    let mapper = OffsetPageTable::new(level_4_table, physical_memory_offset);
    let mut manager = PageTableManager { mapper };
    f(&mut manager)
}

impl PageTableManager {
    /// 创建新的页表管理器
    /// 
    /// # Safety
    /// 
    /// 调用者必须确保物理内存偏移量是正确的
    pub unsafe fn new(physical_memory_offset: VirtAddr) -> Self {
        let level_4_table = active_level_4_table(physical_memory_offset);
        let mapper = OffsetPageTable::new(level_4_table, physical_memory_offset);
        
        PageTableManager { mapper }
    }
    
    /// 映射虚拟页到物理帧
    pub fn map_page(
        &mut self,
        page: Page,
        frame: PhysFrame,
        flags: PageTableFlags,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), MapError> {
        use x86_64::structures::paging::mapper::MapToError;
        
        unsafe {
            self.mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(|e| match e {
                    MapToError::FrameAllocationFailed => MapError::FrameAllocationFailed,
                    MapToError::ParentEntryHugePage => MapError::ParentEntryHugePage,
                    MapToError::PageAlreadyMapped(_) => MapError::PageAlreadyMapped,
                })?
                .flush();
        }
        
        Ok(())
    }
    
    /// 取消映射虚拟页
    pub fn unmap_page(&mut self, page: Page) -> Result<PhysFrame, UnmapError> {
        use x86_64::structures::paging::mapper::UnmapError as X64UnmapError;
        
        let (frame, flush) = self.mapper
            .unmap(page)
            .map_err(|e| match e {
                X64UnmapError::PageNotMapped => UnmapError::PageNotMapped,
                X64UnmapError::ParentEntryHugePage => UnmapError::ParentEntryHugePage,
                X64UnmapError::InvalidFrameAddress(_) => UnmapError::InvalidFrameAddress,
            })?;
        
        flush.flush();
        Ok(frame)
    }
    
    /// 转换虚拟地址到物理地址
    pub fn translate_addr(&self, addr: VirtAddr) -> Option<PhysAddr> {
        use x86_64::structures::paging::mapper::TranslateResult;
        
        match self.mapper.translate(addr) {
            TranslateResult::Mapped { frame, offset, .. } => {
                Some(frame.start_address() + offset)
            }
            TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
        }
    }
    
    /// 修改页的标志位
    pub fn update_flags(
        &mut self,
        page: Page,
        flags: PageTableFlags,
    ) -> Result<(), UpdateFlagsError> {
        use x86_64::structures::paging::mapper::FlagUpdateError;
        
        unsafe {
            self.mapper
                .update_flags(page, flags)
                .map_err(|e| match e {
                    FlagUpdateError::PageNotMapped => UpdateFlagsError::PageNotMapped,
                    FlagUpdateError::ParentEntryHugePage => UpdateFlagsError::ParentEntryHugePage,
                })?
                .flush();
        }
        
        Ok(())
    }
    
    /// 映射一个连续的虚拟地址范围
    pub fn map_range(
        &mut self,
        start_virt: VirtAddr,
        start_phys: PhysAddr,
        size: usize,
        flags: PageTableFlags,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), MapError> {
        let page_count = (size + 0xfff) / 0x1000;
        
        for i in 0..page_count {
            let offset = (i * 0x1000) as u64;
            let page = Page::containing_address(start_virt + offset);
            let frame = PhysFrame::containing_address(start_phys + offset);
            
            self.map_page(page, frame, flags, frame_allocator)?;
        }
        
        Ok(())
    }
    
    /// 取消映射一个连续的虚拟地址范围
    pub fn unmap_range(
        &mut self,
        start_virt: VirtAddr,
        size: usize,
    ) -> Result<(), UnmapError> {
        let page_count = (size + 0xfff) / 0x1000;
        
        for i in 0..page_count {
            let offset = (i * 0x1000) as u64;
            let page = Page::containing_address(start_virt + offset);
            self.unmap_page(page)?;
        }
        
        Ok(())
    }
}

/// 获取活动的4级页表
/// 
/// # Safety
/// 
/// 调用者必须确保物理内存偏移量是正确的
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;
    
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();
    
    &mut *page_table_ptr
}

/// 页表映射错误
#[derive(Debug)]
pub enum MapError {
    FrameAllocationFailed,
    ParentEntryHugePage,
    PageAlreadyMapped,
}

/// 页表取消映射错误
#[derive(Debug)]
pub enum UnmapError {
    PageNotMapped,
    ParentEntryHugePage,
    InvalidFrameAddress,
}

/// 更新标志位错误
#[derive(Debug)]
pub enum UpdateFlagsError {
    PageNotMapped,
    ParentEntryHugePage,
}

/// 全局页表管理器实例
lazy_static::lazy_static! {
    pub static ref PAGE_TABLE_MANAGER: Mutex<Option<PageTableManager>> = Mutex::new(None);
}

/// 初始化页表管理器
/// 
/// # Safety
/// 
/// 只能调用一次，且必须在内核初始化早期调用
pub unsafe fn init(physical_memory_offset: VirtAddr) {
    let manager = PageTableManager::new(physical_memory_offset);
    *PAGE_TABLE_MANAGER.lock() = Some(manager);
    
    println!("Page table manager initialized");
}

/// 获取全局页表管理器
pub fn get_manager() -> Option<spin::MutexGuard<'static, Option<PageTableManager>>> {
    let guard = PAGE_TABLE_MANAGER.lock();
    if guard.is_some() {
        Some(guard)
    } else {
        None
    }
}