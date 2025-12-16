//! Device filesystem (devfs)
//!
//! Provides /dev virtual filesystem with device files:
//! - /dev/null - Discards all writes, returns EOF on read
//! - /dev/zero - Returns infinite zeros on read, discards writes
//! - /dev/console - Kernel console (serial output)

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;
use kernel_core::FileOps;
use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};

/// Global device filesystem ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(1);

/// Device filesystem
pub struct DevFs {
    fs_id: u64,
    root: Arc<DevDirInode>,
}

impl DevFs {
    /// Create a new device filesystem with standard devices
    pub fn new() -> Arc<Self> {
        let fs_id = NEXT_FS_ID.fetch_add(1, Ordering::SeqCst);

        let mut devices: BTreeMap<String, Arc<dyn Inode>> = BTreeMap::new();

        // Create device inodes
        devices.insert("null".into(), Arc::new(NullDevInode::new(fs_id)));
        devices.insert("zero".into(), Arc::new(ZeroDevInode::new(fs_id)));
        devices.insert("console".into(), Arc::new(ConsoleDevInode::new(fs_id)));

        let root = Arc::new(DevDirInode {
            fs_id,
            ino: 1,
            entries: RwLock::new(devices),
        });

        Arc::new(Self { fs_id, root })
    }
}

impl FileSystem for DevFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "devfs"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        Arc::clone(&self.root) as Arc<dyn Inode>
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Only root directory lookup supported
        if parent.ino() != 1 {
            return Err(FsError::NotDir);
        }

        let entries = self.root.entries.read();
        entries.get(name).cloned().ok_or(FsError::NotFound)
    }
}

/// Device directory inode (/dev)
struct DevDirInode {
    fs_id: u64,
    ino: u64,
    entries: RwLock<BTreeMap<String, Arc<dyn Inode>>>,
}

impl Inode for DevDirInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::directory(0o755),
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, _flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Directories are opened for readdir, not read/write
        Err(FsError::IsDir)
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let entries = self.entries.read();
        let mut iter = entries.iter();

        // Skip to offset
        for _ in 0..offset {
            if iter.next().is_none() {
                return Ok(None);
            }
        }

        // Return next entry
        if let Some((name, inode)) = iter.next() {
            let stat = inode.stat()?;
            Ok(Some((
                offset + 1,
                DirEntry {
                    name: name.clone(),
                    ino: inode.ino(),
                    file_type: stat.mode.file_type,
                },
            )))
        } else {
            Ok(None)
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /dev/null implementation
// ============================================================================

/// /dev/null inode
struct NullDevInode {
    fs_id: u64,
    ino: u64,
}

impl NullDevInode {
    fn new(fs_id: u64) -> Self {
        Self { fs_id, ino: 2 }
    }
}

impl Inode for NullDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o666),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(1, 3), // major 1, minor 3 = /dev/null
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        Ok(Box::new(NullDevFile { flags }))
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, FsError> {
        // /dev/null always returns EOF
        Ok(0)
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // /dev/null discards all data
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// /dev/null file handle
struct NullDevFile {
    flags: OpenFlags,
}

impl FileOps for NullDevFile {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(NullDevFile { flags: self.flags })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "NullDev"
    }
}

// ============================================================================
// /dev/zero implementation
// ============================================================================

/// /dev/zero inode
struct ZeroDevInode {
    fs_id: u64,
    ino: u64,
}

impl ZeroDevInode {
    fn new(fs_id: u64) -> Self {
        Self { fs_id, ino: 3 }
    }
}

impl Inode for ZeroDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o666),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(1, 5), // major 1, minor 5 = /dev/zero
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        Ok(Box::new(ZeroDevFile { flags }))
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // /dev/zero returns infinite zeros
        buf.fill(0);
        Ok(buf.len())
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // /dev/zero discards all data
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// /dev/zero file handle
struct ZeroDevFile {
    flags: OpenFlags,
}

impl FileOps for ZeroDevFile {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(ZeroDevFile { flags: self.flags })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "ZeroDev"
    }
}

// ============================================================================
// /dev/console implementation
// ============================================================================

/// /dev/console inode
struct ConsoleDevInode {
    fs_id: u64,
    ino: u64,
}

impl ConsoleDevInode {
    fn new(fs_id: u64) -> Self {
        Self { fs_id, ino: 4 }
    }
}

impl Inode for ConsoleDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o620),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(5, 1), // major 5, minor 1 = /dev/console
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        Ok(Box::new(ConsoleDevFile { flags }))
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, FsError> {
        // Console read not implemented yet (would need keyboard input queue)
        Ok(0)
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // Write to console via print
        if let Ok(s) = core::str::from_utf8(data) {
            print!("{}", s);
        } else {
            // Write raw bytes
            for &b in data {
                print!("{}", b as char);
            }
        }
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// /dev/console file handle
struct ConsoleDevFile {
    flags: OpenFlags,
}

impl FileOps for ConsoleDevFile {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(ConsoleDevFile { flags: self.flags })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "ConsoleDev"
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Create device number from major and minor
#[inline]
fn make_dev(major: u32, minor: u32) -> u32 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & 0xFFF00) << 12)
}

/// Extended device file operations
///
/// This trait extends FileOps with device-specific operations
pub trait DevFileOps: FileOps {
    /// Read from device
    fn dev_read(&self, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Write to device
    fn dev_write(&self, data: &[u8]) -> Result<usize, FsError>;
}

impl DevFileOps for NullDevFile {
    fn dev_read(&self, _buf: &mut [u8]) -> Result<usize, FsError> {
        Ok(0) // EOF
    }

    fn dev_write(&self, data: &[u8]) -> Result<usize, FsError> {
        Ok(data.len()) // Discard
    }
}

impl DevFileOps for ZeroDevFile {
    fn dev_read(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn dev_write(&self, data: &[u8]) -> Result<usize, FsError> {
        Ok(data.len()) // Discard
    }
}

impl DevFileOps for ConsoleDevFile {
    fn dev_read(&self, _buf: &mut [u8]) -> Result<usize, FsError> {
        Ok(0) // No input yet
    }

    fn dev_write(&self, data: &[u8]) -> Result<usize, FsError> {
        if let Ok(s) = core::str::from_utf8(data) {
            print!("{}", s);
        }
        Ok(data.len())
    }
}
