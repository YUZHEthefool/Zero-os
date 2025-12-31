//! Read-only ext2 filesystem implementation
//!
//! Provides read-only support for ext2 filesystems:
//! - Mount and validate superblock
//! - Directory traversal and lookup
//! - File reading with page cache integration
//!
//! Based on ext2 specification (https://www.nongnu.org/ext2-doc/)

use crate::traits::{FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use block::BlockDevice;
use core::any::Any;
use core::cmp;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::FileOps;
use mm::{buddy_allocator, page_cache, PageCacheEntry, PAGE_SIZE, PHYSICAL_MEMORY_OFFSET};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Ext2 magic number
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock offset from partition start
pub const SUPERBLOCK_OFFSET: u64 = 1024;

/// Root inode number
pub const EXT2_ROOT_INO: u32 = 2;

/// Number of direct blocks in inode
pub const EXT2_NDIR_BLOCKS: usize = 12;

/// Indirect block index
pub const EXT2_IND_BLOCK: usize = 12;

/// Double indirect block index
pub const EXT2_DIND_BLOCK: usize = 13;

/// Triple indirect block index
pub const EXT2_TIND_BLOCK: usize = 14;

/// File type in mode field
pub const EXT2_S_IFMT: u16 = 0xF000;
pub const EXT2_S_IFREG: u16 = 0x8000;
pub const EXT2_S_IFDIR: u16 = 0x4000;
pub const EXT2_S_IFLNK: u16 = 0xA000;

/// Directory entry file types
pub const EXT2_FT_REG_FILE: u8 = 1;
pub const EXT2_FT_DIR: u8 = 2;
pub const EXT2_FT_CHRDEV: u8 = 3;
pub const EXT2_FT_BLKDEV: u8 = 4;
pub const EXT2_FT_SYMLINK: u8 = 7;

/// Global filesystem ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(100);

// ============================================================================
// On-disk structures
// ============================================================================

/// Ext2 superblock (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub log_frag_size: i32,
    pub blocks_per_group: u32,
    pub frags_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub max_mnt_count: i16,
    pub magic: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub creator_os: u32,
    pub rev_level: u32,
    pub def_resuid: u16,
    pub def_resgid: u16,
    // Rev 1 fields
    pub first_ino: u32,
    pub inode_size: u16,
    pub block_group_nr: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub algo_bitmap: u32,
    // Padding to 1024 bytes
    _padding: [u8; 820],
}

/// Block group descriptor (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ext2GroupDesc {
    pub block_bitmap: u32,
    pub inode_bitmap: u32,
    pub inode_table: u32,
    pub free_blocks_count: u16,
    pub free_inodes_count: u16,
    pub used_dirs_count: u16,
    pub pad: u16,
    pub reserved: [u8; 12],
}

/// Ext2 inode (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ext2InodeRaw {
    pub mode: u16,
    pub uid: u16,
    pub size_lo: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub osd1: u32,
    pub block: [u32; 15],
    pub generation: u32,
    pub file_acl: u32,
    pub size_high_or_dir_acl: u32,
    pub faddr: u32,
    pub osd2: [u8; 12],
}

/// Directory entry header (on-disk format)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2DirEntryHead {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
}

// ============================================================================
// Ext2 Filesystem
// ============================================================================

/// Ext2 filesystem instance
pub struct Ext2Fs {
    fs_id: u64,
    dev: Arc<dyn BlockDevice>,
    superblock: Ext2Superblock,
    group_descs: Vec<Ext2GroupDesc>,
    block_size: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    root: RwLock<Option<Arc<Ext2Inode>>>,
    self_ref: Mutex<Option<Weak<Ext2Fs>>>,
}

impl Ext2Fs {
    /// Mount an ext2 filesystem from a block device
    pub fn mount(dev: Arc<dyn BlockDevice>) -> Result<Arc<Self>, FsError> {
        // Read superblock
        let (superblock, block_size) = Self::read_super(&dev)?;

        // Load block group descriptors
        let group_descs = Self::load_group_descs(&dev, &superblock, block_size)?;

        let inode_size = if superblock.rev_level >= 1 {
            superblock.inode_size
        } else {
            128 // Rev 0 uses fixed 128-byte inodes
        };

        let fs_id = NEXT_FS_ID.fetch_add(1, Ordering::SeqCst);

        let fs = Arc::new(Self {
            fs_id,
            dev,
            superblock,
            group_descs,
            block_size,
            blocks_per_group: superblock.blocks_per_group,
            inodes_per_group: superblock.inodes_per_group,
            inode_size,
            root: RwLock::new(None),
            self_ref: Mutex::new(None),
        });

        // Store self reference
        *fs.self_ref.lock() = Some(Arc::downgrade(&fs));

        // Load root inode
        let root_raw = fs.read_inode_raw(EXT2_ROOT_INO)?;
        let root = fs.wrap_inode(EXT2_ROOT_INO, root_raw);
        *fs.root.write() = Some(root);

        Ok(fs)
    }

    /// Read and validate superblock
    fn read_super(dev: &Arc<dyn BlockDevice>) -> Result<(Ext2Superblock, u32), FsError> {
        let sector_size = dev.sector_size() as u64;
        let start_sector = SUPERBLOCK_OFFSET / sector_size;

        // Read superblock (1024 bytes, may span 2 sectors)
        let mut buf = alloc::vec![0u8; 1024];
        dev.read_sync(start_sector, &mut buf)
            .map_err(|_| FsError::Io)?;

        // Parse superblock
        let sb: Ext2Superblock = unsafe { core::ptr::read(buf.as_ptr() as *const _) };

        // Validate magic
        if sb.magic != EXT2_SUPER_MAGIC {
            return Err(FsError::Invalid);
        }

        // Calculate block size
        let block_size = 1024u32 << sb.log_block_size;

        // Validate block size (1K-64K)
        if block_size < 1024 || block_size > 65536 {
            return Err(FsError::Invalid);
        }

        Ok((sb, block_size))
    }

    /// Load block group descriptor table
    fn load_group_descs(
        dev: &Arc<dyn BlockDevice>,
        sb: &Ext2Superblock,
        block_size: u32,
    ) -> Result<Vec<Ext2GroupDesc>, FsError> {
        // Calculate number of block groups
        let groups_count = (sb.blocks_count + sb.blocks_per_group - 1) / sb.blocks_per_group;

        // BGDT starts at block 2 for 1K blocks, block 1 for larger blocks
        let bgdt_block = if block_size == 1024 { 2 } else { 1 };
        let bgdt_offset = bgdt_block as u64 * block_size as u64;

        // Read BGDT
        let bgdt_size = groups_count as usize * size_of::<Ext2GroupDesc>();
        let sectors_needed = (bgdt_size + dev.sector_size() as usize - 1) / dev.sector_size() as usize;
        let mut buf = alloc::vec![0u8; sectors_needed * dev.sector_size() as usize];

        let start_sector = bgdt_offset / dev.sector_size() as u64;
        dev.read_sync(start_sector, &mut buf)
            .map_err(|_| FsError::Io)?;

        // Parse group descriptors
        let mut descs = Vec::with_capacity(groups_count as usize);
        for i in 0..groups_count as usize {
            let offset = i * size_of::<Ext2GroupDesc>();
            let gd: Ext2GroupDesc = unsafe { core::ptr::read(buf[offset..].as_ptr() as *const _) };
            descs.push(gd);
        }

        Ok(descs)
    }

    /// Read a block from the device
    fn read_block(&self, block_no: u32, buf: &mut [u8]) -> Result<(), FsError> {
        if buf.len() < self.block_size as usize {
            return Err(FsError::Invalid);
        }

        let sector_size = self.dev.sector_size() as u64;
        let block_offset = block_no as u64 * self.block_size as u64;
        let start_sector = block_offset / sector_size;

        self.dev
            .read_sync(start_sector, &mut buf[..self.block_size as usize])
            .map(|_| ())
            .map_err(|_| FsError::Io)
    }

    /// Read raw inode from disk
    fn read_inode_raw(&self, ino: u32) -> Result<Ext2InodeRaw, FsError> {
        if ino == 0 || ino > self.superblock.inodes_count {
            return Err(FsError::NotFound);
        }

        // Calculate group and index
        let (group, index) = self.inode_group_index(ino);

        // Get inode table block
        let inode_table_block = self.group_descs[group].inode_table;

        // Calculate offset within inode table
        let inode_offset = index as u64 * self.inode_size as u64;
        let block_offset = inode_offset / self.block_size as u64;
        let offset_in_block = inode_offset % self.block_size as u64;

        // Read the block containing the inode
        let mut block_buf = alloc::vec![0u8; self.block_size as usize];
        self.read_block(inode_table_block + block_offset as u32, &mut block_buf)?;

        // Parse inode
        let inode: Ext2InodeRaw = unsafe {
            core::ptr::read(block_buf[offset_in_block as usize..].as_ptr() as *const _)
        };

        Ok(inode)
    }

    /// Wrap a raw inode into an Ext2Inode
    fn wrap_inode(self: &Arc<Self>, ino: u32, raw: Ext2InodeRaw) -> Arc<Ext2Inode> {
        let size = if raw.mode & EXT2_S_IFREG != 0 {
            // Regular file: use size_high for large files
            ((raw.size_high_or_dir_acl as u64) << 32) | (raw.size_lo as u64)
        } else {
            // Directories: only use size_lo
            raw.size_lo as u64
        };

        Arc::new(Ext2Inode {
            fs: Arc::downgrade(self),
            fs_id: self.fs_id,
            ino,
            raw,
            size,
        })
    }

    /// Calculate group and index for an inode number
    fn inode_group_index(&self, ino: u32) -> (usize, usize) {
        let group = ((ino - 1) / self.inodes_per_group) as usize;
        let index = ((ino - 1) % self.inodes_per_group) as usize;
        (group, index)
    }

    /// R28-5 Fix: Validate block number against filesystem bounds
    #[inline]
    fn validate_block(&self, block: u32) -> Result<Option<u32>, FsError> {
        if block == 0 {
            Ok(None)
        } else if block >= self.superblock.blocks_count {
            Err(FsError::Invalid)
        } else {
            Ok(Some(block))
        }
    }

    /// Map a file block number to physical block number
    fn map_file_block(&self, raw: &Ext2InodeRaw, file_block: u32) -> Result<Option<u32>, FsError> {
        let ptrs_per_block = self.block_size / 4; // 4 bytes per u32 pointer

        // Direct blocks (0-11)
        if file_block < EXT2_NDIR_BLOCKS as u32 {
            let block = raw.block[file_block as usize];
            return self.validate_block(block);
        }

        let file_block = file_block - EXT2_NDIR_BLOCKS as u32;

        // Single indirect (block 12)
        if file_block < ptrs_per_block {
            // R28-5 Fix: Validate indirect block pointer
            let ind_block = match self.validate_block(raw.block[EXT2_IND_BLOCK])? {
                Some(b) => b,
                None => return Ok(None),
            };

            let mut buf = alloc::vec![0u8; self.block_size as usize];
            self.read_block(ind_block, &mut buf)?;

            let ptrs: &[u32] =
                unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u32, ptrs_per_block as usize) };
            // R28-5 Fix: Validate data block pointer
            return self.validate_block(ptrs[file_block as usize]);
        }

        let file_block = file_block - ptrs_per_block;

        // Double indirect (block 13)
        if file_block < ptrs_per_block * ptrs_per_block {
            // R28-5 Fix: Validate double indirect block pointer
            let dind_block = match self.validate_block(raw.block[EXT2_DIND_BLOCK])? {
                Some(b) => b,
                None => return Ok(None),
            };

            let mut buf = alloc::vec![0u8; self.block_size as usize];
            self.read_block(dind_block, &mut buf)?;

            let ptrs: &[u32] =
                unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u32, ptrs_per_block as usize) };

            let ind_index = file_block / ptrs_per_block;
            // R28-5 Fix: Validate indirect block pointer from double indirect table
            let ind_block = match self.validate_block(ptrs[ind_index as usize])? {
                Some(b) => b,
                None => return Ok(None),
            };

            self.read_block(ind_block, &mut buf)?;
            let ptrs: &[u32] =
                unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u32, ptrs_per_block as usize) };

            let block_index = file_block % ptrs_per_block;
            // R28-5 Fix: Validate data block pointer
            return self.validate_block(ptrs[block_index as usize]);
        }

        // Triple indirect would go here, but for simplicity we return an error
        Err(FsError::Invalid)
    }
}

impl FileSystem for Ext2Fs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "ext2"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.read().as_ref().unwrap().clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Downcast to Ext2Inode
        let parent = parent
            .as_any()
            .downcast_ref::<Ext2Inode>()
            .ok_or(FsError::Invalid)?;

        if !parent.is_dir_inner() {
            return Err(FsError::NotDir);
        }

        // Search directory entries
        parent.dir_lookup(name)
    }
}

// ============================================================================
// Ext2 Inode
// ============================================================================

/// Ext2 inode wrapper
pub struct Ext2Inode {
    fs: Weak<Ext2Fs>,
    fs_id: u64,
    ino: u32,
    raw: Ext2InodeRaw,
    size: u64,
}

impl Ext2Inode {
    /// Check if this is a directory
    fn is_dir_inner(&self) -> bool {
        (self.raw.mode & EXT2_S_IFMT) == EXT2_S_IFDIR
    }

    /// Check if this is a regular file
    fn is_file_inner(&self) -> bool {
        (self.raw.mode & EXT2_S_IFMT) == EXT2_S_IFREG
    }

    /// Look up a name in this directory
    fn dir_lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;

        let mut offset = 0u64;
        let mut block_buf = alloc::vec![0u8; fs.block_size as usize];

        while offset < self.size {
            // Calculate which block to read
            let file_block = offset / fs.block_size as u64;
            let offset_in_block = offset % fs.block_size as u64;

            // Map to physical block
            let phys_block = fs.map_file_block(&self.raw, file_block as u32)?;
            if let Some(phys) = phys_block {
                fs.read_block(phys, &mut block_buf)?;
            } else {
                // Hole - zero-filled
                block_buf.fill(0);
            }

            // Parse directory entry
            let data = &block_buf[offset_in_block as usize..];
            if data.len() < size_of::<Ext2DirEntryHead>() {
                break;
            }

            let head: Ext2DirEntryHead = unsafe { core::ptr::read(data.as_ptr() as *const _) };

            if head.rec_len == 0 {
                break;
            }

            // R28-4 Fix: Validate rec_len and name_len against buffer boundaries
            let rec_len = head.rec_len as usize;
            let min_rec = size_of::<Ext2DirEntryHead>();
            if rec_len < min_rec || (offset_in_block as usize) + rec_len > block_buf.len() {
                return Err(FsError::Invalid);
            }
            if (head.name_len as usize) > rec_len.saturating_sub(min_rec) {
                return Err(FsError::Invalid);
            }

            if head.inode != 0 && head.name_len > 0 {
                let name_bytes = &data[min_rec..min_rec + head.name_len as usize];
                if let Ok(entry_name) = core::str::from_utf8(name_bytes) {
                    if entry_name == name {
                        // Found it!
                        let raw = fs.read_inode_raw(head.inode)?;
                        return Ok(fs.wrap_inode(head.inode, raw));
                    }
                }
            }

            offset += head.rec_len as u64;
        }

        Err(FsError::NotFound)
    }

    /// Read file data at offset using page cache
    ///
    /// This implementation routes all file reads through the global page cache,
    /// providing caching and reducing disk I/O for repeated accesses.
    fn read_file_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        if offset >= self.size {
            return Ok(0);
        }

        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        let block_size = fs.block_size as usize;

        // Create unique inode_id for page cache: combine fs_id and ino
        // Use upper 32 bits for fs_id, lower 32 bits for ino
        let cache_inode_id = (self.fs_id << 32) | (self.ino as u64);
        let file_size = self.size;
        let raw_inode = self.raw;

        let to_read = buf.len().min((file_size - offset) as usize);
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;
            let page_index = file_offset / PAGE_SIZE as u64;
            let offset_in_page = (file_offset % PAGE_SIZE as u64) as usize;
            let remaining_in_page = PAGE_SIZE - offset_in_page;
            let copy_len = cmp::min(remaining_in_page, to_read - bytes_read);

            // Clone fs for the I/O closure
            let fs_for_io = fs.clone();

            // Allocate physical frame for new page
            let alloc_pfn = || -> Option<u64> {
                let frame = buddy_allocator::alloc_physical_pages(1)?;
                Some(frame.start_address().as_u64() / PAGE_SIZE as u64)
            };

            // Read page from cache, or load from disk if not cached
            let page = page_cache::read_page(
                cache_inode_id,
                page_index,
                alloc_pfn,
                |page_entry: &PageCacheEntry| {
                    // This closure populates the page from disk
                    let page_phys = page_entry.physical_address();
                    let page_virt = (page_phys + PHYSICAL_MEMORY_OFFSET) as *mut u8;

                    // Zero the page first (handles sparse files and EOF)
                    unsafe {
                        core::ptr::write_bytes(page_virt, 0, PAGE_SIZE);
                    }

                    // Calculate file offset for this page
                    let page_start_offset = page_entry.index * PAGE_SIZE as u64;
                    let mut filled = 0usize;

                    // Fill the page from disk blocks
                    while filled < PAGE_SIZE {
                        let global_offset = page_start_offset + filled as u64;

                        // Stop at end of file
                        if global_offset >= file_size {
                            break;
                        }

                        // Calculate which file block and offset within block
                        let file_block = (global_offset / block_size as u64) as u32;
                        let offset_in_block = (global_offset % block_size as u64) as usize;

                        // Read the block from disk
                        let mut block_buf = alloc::vec![0u8; block_size];
                        let phys_block = match fs_for_io.map_file_block(&raw_inode, file_block) {
                            Ok(Some(b)) => Some(b),
                            Ok(None) => None, // Hole in file
                            Err(_) => return Err(()),
                        };

                        if let Some(phys) = phys_block {
                            if fs_for_io.read_block(phys, &mut block_buf).is_err() {
                                return Err(());
                            }
                        }
                        // For holes, block_buf is already zeroed

                        // Calculate how much to copy from this block
                        let bytes_left_in_block = block_size.saturating_sub(offset_in_block);
                        let bytes_left_in_page = PAGE_SIZE - filled;
                        let bytes_left_in_file = (file_size - global_offset) as usize;
                        let chunk = cmp::min(
                            cmp::min(bytes_left_in_block, bytes_left_in_page),
                            bytes_left_in_file,
                        );

                        if chunk == 0 {
                            break;
                        }

                        // Copy data to page
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                block_buf.as_ptr().add(offset_in_block),
                                page_virt.add(filled),
                                chunk,
                            );
                        }

                        filled += chunk;
                    }

                    Ok(())
                },
            )
            .ok_or(FsError::Io)?;

            // Copy data from cached page to user buffer
            let page_virt = (page.physical_address() + PHYSICAL_MEMORY_OFFSET) as *const u8;
            let src = unsafe {
                core::slice::from_raw_parts(page_virt.add(offset_in_page), copy_len)
            };
            buf[bytes_read..bytes_read + copy_len].copy_from_slice(src);

            // R36-FIX: Balance the page cache refcount so shrink() can reclaim this page.
            // find_get_page increments refcount, we must call put() when done using the page.
            page.put();

            bytes_read += copy_len;
        }

        Ok(bytes_read)
    }

    /// Convert raw mode to FileType
    fn file_type(&self) -> FileType {
        match self.raw.mode & EXT2_S_IFMT {
            EXT2_S_IFREG => FileType::Regular,
            EXT2_S_IFDIR => FileType::Directory,
            EXT2_S_IFLNK => FileType::Symlink,
            _ => FileType::Regular, // Default
        }
    }
}

impl Inode for Ext2Inode {
    fn ino(&self) -> u64 {
        self.ino as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino as u64,
            mode: FileMode::new(self.file_type(), self.raw.mode & 0o7777),
            nlink: self.raw.links_count as u32,
            uid: self.raw.uid as u32,
            gid: self.raw.gid as u32,
            rdev: 0,
            size: self.size,
            blksize: self.fs.upgrade().map(|fs| fs.block_size).unwrap_or(4096),
            blocks: self.raw.blocks_lo as u64,
            atime: TimeSpec::new(self.raw.atime as i64, 0),
            mtime: TimeSpec::new(self.raw.mtime as i64, 0),
            ctime: TimeSpec::new(self.raw.ctime as i64, 0),
        })
    }

    fn open(&self, _flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Read-only: create a file handle
        Ok(Box::new(Ext2File {
            inode: self.fs.upgrade().ok_or(FsError::Invalid)?.wrap_inode(self.ino, self.raw),
            offset: Mutex::new(0),
        }))
    }

    fn is_dir(&self) -> bool {
        self.is_dir_inner()
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        if !self.is_dir_inner() {
            return Err(FsError::NotDir);
        }

        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        let mut block_buf = alloc::vec![0u8; fs.block_size as usize];

        let mut current_offset = 0u64;
        let mut entry_index = 0usize;

        while current_offset < self.size {
            let file_block = current_offset / fs.block_size as u64;
            let offset_in_block = current_offset % fs.block_size as u64;

            let phys_block = fs.map_file_block(&self.raw, file_block as u32)?;
            if let Some(phys) = phys_block {
                fs.read_block(phys, &mut block_buf)?;
            } else {
                block_buf.fill(0);
            }

            let data = &block_buf[offset_in_block as usize..];
            if data.len() < size_of::<Ext2DirEntryHead>() {
                break;
            }

            let head: Ext2DirEntryHead = unsafe { core::ptr::read(data.as_ptr() as *const _) };

            if head.rec_len == 0 {
                break;
            }

            // R28-4 Fix: Validate rec_len and name_len against buffer boundaries
            let rec_len = head.rec_len as usize;
            let min_rec = size_of::<Ext2DirEntryHead>();
            if rec_len < min_rec || (offset_in_block as usize) + rec_len > block_buf.len() {
                return Err(FsError::Invalid);
            }

            if head.inode != 0 && head.name_len > 0 {
                // Validate name_len before accessing
                if (head.name_len as usize) > rec_len.saturating_sub(min_rec) {
                    return Err(FsError::Invalid);
                }
                if entry_index == offset {
                    let name_bytes = &data[min_rec..min_rec + head.name_len as usize];
                    let name = String::from_utf8_lossy(name_bytes).into_owned();

                    let file_type = match head.file_type {
                        EXT2_FT_REG_FILE => FileType::Regular,
                        EXT2_FT_DIR => FileType::Directory,
                        EXT2_FT_SYMLINK => FileType::Symlink,
                        EXT2_FT_CHRDEV => FileType::CharDevice,
                        EXT2_FT_BLKDEV => FileType::BlockDevice,
                        _ => FileType::Regular,
                    };

                    return Ok(Some((
                        offset + 1,
                        DirEntry {
                            name,
                            ino: head.inode as u64,
                            file_type,
                        },
                    )));
                }
                entry_index += 1;
            }

            current_offset += head.rec_len as u64;
        }

        Ok(None)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.is_file_inner() {
            return Err(FsError::IsDir);
        }
        self.read_file_at(offset, buf)
    }

    fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<usize, FsError> {
        Err(FsError::NotSupported) // Read-only
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Ext2 File Handle
// ============================================================================

/// File handle for ext2 files
struct Ext2File {
    inode: Arc<Ext2Inode>,
    offset: Mutex<u64>,
}

impl FileOps for Ext2File {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(Ext2File {
            inode: self.inode.clone(),
            offset: Mutex::new(*self.offset.lock()),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "Ext2File"
    }
}
