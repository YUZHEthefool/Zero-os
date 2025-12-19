//! VFS type definitions
//!
//! Core types for the Virtual File System layer including:
//! - File types and modes
//! - Stat structure for file metadata
//! - VFS error types
//! - Open flags

use alloc::string::String;
use alloc::sync::Arc;

/// File type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileType {
    /// Regular file
    Regular = 0,
    /// Directory
    Directory = 1,
    /// Character device (e.g., /dev/null, /dev/console)
    CharDevice = 2,
    /// Block device (e.g., /dev/sda)
    BlockDevice = 3,
    /// Symbolic link
    Symlink = 4,
    /// Named pipe (FIFO)
    Fifo = 5,
    /// Unix domain socket
    Socket = 6,
}

impl FileType {
    /// Convert to mode bits (upper 4 bits of st_mode)
    pub fn to_mode_bits(self) -> u32 {
        match self {
            FileType::Regular => 0o100000,
            FileType::Directory => 0o040000,
            FileType::CharDevice => 0o020000,
            FileType::BlockDevice => 0o060000,
            FileType::Symlink => 0o120000,
            FileType::Fifo => 0o010000,
            FileType::Socket => 0o140000,
        }
    }
}

/// File mode (type + permissions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMode {
    /// File type
    pub file_type: FileType,
    /// Permission bits (lower 12 bits: rwxrwxrwx + setuid/setgid/sticky)
    pub perm: u16,
}

impl FileMode {
    /// Create a new file mode
    pub const fn new(file_type: FileType, perm: u16) -> Self {
        Self {
            file_type,
            perm: perm & 0o7777,
        }
    }

    /// Create mode for regular file with given permissions
    pub const fn regular(perm: u16) -> Self {
        Self::new(FileType::Regular, perm)
    }

    /// Create mode for directory with given permissions
    pub const fn directory(perm: u16) -> Self {
        Self::new(FileType::Directory, perm)
    }

    /// Create mode for character device with given permissions
    pub const fn char_device(perm: u16) -> Self {
        Self::new(FileType::CharDevice, perm)
    }

    /// Convert to raw st_mode value
    pub fn to_raw(&self) -> u32 {
        self.file_type.to_mode_bits() | (self.perm as u32)
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type == FileType::Regular
    }

    /// Check if this is a character device
    pub fn is_char_device(&self) -> bool {
        self.file_type == FileType::CharDevice
    }
}

/// Timestamp for file metadata
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeSpec {
    /// Seconds since epoch
    pub sec: i64,
    /// Nanoseconds (0-999999999)
    pub nsec: i64,
}

impl TimeSpec {
    /// Create a new timestamp
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }

    /// Create timestamp from milliseconds
    pub fn from_ms(ms: u64) -> Self {
        Self {
            sec: (ms / 1000) as i64,
            nsec: ((ms % 1000) * 1_000_000) as i64,
        }
    }

    /// Get current time from kernel timer
    pub fn now() -> Self {
        let ms = kernel_core::current_timestamp_ms();
        Self::from_ms(ms)
    }
}

/// File status structure (similar to POSIX struct stat)
#[derive(Debug, Clone)]
pub struct Stat {
    /// Device ID containing file
    pub dev: u64,
    /// Inode number
    pub ino: u64,
    /// File mode (type + permissions)
    pub mode: FileMode,
    /// Number of hard links
    pub nlink: u32,
    /// Owner user ID
    pub uid: u32,
    /// Owner group ID
    pub gid: u32,
    /// Device ID (for special files)
    pub rdev: u32,
    /// File size in bytes
    pub size: u64,
    /// Block size for filesystem I/O
    pub blksize: u32,
    /// Number of 512-byte blocks allocated
    pub blocks: u64,
    /// Last access time
    pub atime: TimeSpec,
    /// Last modification time
    pub mtime: TimeSpec,
    /// Last status change time
    pub ctime: TimeSpec,
}

impl Default for Stat {
    fn default() -> Self {
        let now = TimeSpec::now();
        Self {
            dev: 0,
            ino: 0,
            mode: FileMode::regular(0o644),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

/// VFS error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// Entry not found
    NotFound,
    /// Not a directory
    NotDir,
    /// Is a directory (when file expected)
    IsDir,
    /// Entry already exists
    Exists,
    /// Operation not supported
    NotSupported,
    /// I/O error
    Io,
    /// Invalid argument
    Invalid,
    /// Out of memory
    NoMem,
    /// Broken pipe
    Pipe,
    /// Bad file descriptor
    BadFd,
    /// Permission denied
    PermDenied,
    /// Read-only filesystem
    ReadOnly,
    /// No space left on device
    NoSpace,
    /// Name too long
    NameTooLong,
    /// Not empty (for directory removal)
    NotEmpty,
    /// Cross-device link
    CrossDev,
    /// Illegal seek (e.g., on pipe)
    Seek,
}

impl FsError {
    /// Convert to syscall error number (negative errno)
    pub fn to_errno(self) -> i64 {
        match self {
            FsError::NotFound => -2,      // ENOENT
            FsError::NotDir => -20,       // ENOTDIR
            FsError::IsDir => -21,        // EISDIR
            FsError::Exists => -17,       // EEXIST
            FsError::NotSupported => -38, // ENOSYS
            FsError::Io => -5,            // EIO
            FsError::Invalid => -22,      // EINVAL
            FsError::NoMem => -12,        // ENOMEM
            FsError::Pipe => -32,         // EPIPE
            FsError::BadFd => -9,         // EBADF
            FsError::PermDenied => -13,   // EACCES
            FsError::ReadOnly => -30,     // EROFS
            FsError::NoSpace => -28,      // ENOSPC
            FsError::NameTooLong => -36,  // ENAMETOOLONG
            FsError::NotEmpty => -39,     // ENOTEMPTY
            FsError::CrossDev => -18,     // EXDEV
            FsError::Seek => -29,         // ESPIPE
        }
    }
}

/// File open flags
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Open for reading only
    pub const O_RDONLY: u32 = 0;
    /// Open for writing only
    pub const O_WRONLY: u32 = 1;
    /// Open for reading and writing
    pub const O_RDWR: u32 = 2;
    /// Access mode mask
    pub const O_ACCMODE: u32 = 3;
    /// Create file if it doesn't exist
    pub const O_CREAT: u32 = 0o100;
    /// Fail if file exists (with O_CREAT)
    pub const O_EXCL: u32 = 0o200;
    /// Truncate file to zero length
    pub const O_TRUNC: u32 = 0o1000;
    /// Append mode
    pub const O_APPEND: u32 = 0o2000;
    /// Non-blocking mode
    pub const O_NONBLOCK: u32 = 0o4000;
    /// Open directory
    pub const O_DIRECTORY: u32 = 0o200000;

    /// Create new flags
    pub const fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Check if readable
    pub fn is_readable(&self) -> bool {
        let mode = self.0 & Self::O_ACCMODE;
        mode == Self::O_RDONLY || mode == Self::O_RDWR
    }

    /// Check if writable
    pub fn is_writable(&self) -> bool {
        let mode = self.0 & Self::O_ACCMODE;
        mode == Self::O_WRONLY || mode == Self::O_RDWR
    }

    /// Check if create flag set
    pub fn is_create(&self) -> bool {
        (self.0 & Self::O_CREAT) != 0
    }

    /// Check if truncate flag set
    pub fn is_truncate(&self) -> bool {
        (self.0 & Self::O_TRUNC) != 0
    }

    /// Check if append flag set
    pub fn is_append(&self) -> bool {
        (self.0 & Self::O_APPEND) != 0
    }

    /// Check if non-blocking flag set
    pub fn is_nonblock(&self) -> bool {
        (self.0 & Self::O_NONBLOCK) != 0
    }

    /// Check if exclusive creation is requested (O_EXCL)
    pub fn is_exclusive(&self) -> bool {
        (self.0 & Self::O_EXCL) != 0
    }
}

/// Seek origin for lseek
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SeekWhence {
    /// Seek from beginning of file
    Set = 0,
    /// Seek from current position
    Cur = 1,
    /// Seek from end of file
    End = 2,
}

impl SeekWhence {
    /// Convert from raw value
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            0 => Some(SeekWhence::Set),
            1 => Some(SeekWhence::Cur),
            2 => Some(SeekWhence::End),
            _ => None,
        }
    }
}

/// Directory entry for readdir
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name
    pub name: String,
    /// Inode number
    pub ino: u64,
    /// File type
    pub file_type: FileType,
}
