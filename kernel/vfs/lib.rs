//! Virtual File System (VFS) Layer
//!
//! This module provides a unified interface for different filesystems:
//! - Device filesystem (devfs) for /dev
//! - RAM filesystem (ramfs) for temporary storage
//! - Future: disk-based filesystems
//!
//! # Architecture
//!
//! ```text
//! +-------------------+
//! |   Syscalls        |  sys_open, sys_read, sys_write, sys_stat, etc.
//! +-------------------+
//!          |
//!          v
//! +-------------------+
//! |   VFS Manager     |  Path resolution, mount table, caching
//! +-------------------+
//!          |
//!    +-----+-----+
//!    |           |
//!    v           v
//! +------+   +-------+
//! | devfs|   | ramfs |   FileSystem trait implementations
//! +------+   +-------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize VFS (sets up devfs at /dev)
//! vfs::init();
//!
//! // Open a device file
//! let fd = vfs::open("/dev/null", OpenFlags::new(OpenFlags::O_RDWR))?;
//!
//! // Get file status
//! let stat = vfs::stat("/dev/console")?;
//! ```

#![no_std]
extern crate alloc;

#[macro_use]
extern crate drivers;

pub mod devfs;
pub mod manager;
pub mod ramfs;
pub mod traits;
pub mod types;

// Re-exports for convenience
pub use devfs::DevFs;
pub use manager::{init, mount, open, readdir, stat, umount, VFS};
pub use ramfs::{RamFs, RamFsInode};
pub use traits::{FileHandle, FileSystem, Inode};
pub use types::{DirEntry, FileMode, FileType, FsError, OpenFlags, SeekWhence, Stat, TimeSpec};

/// Initialize the VFS subsystem
///
/// This sets up:
/// - The global VFS instance
/// - Device filesystem mounted at /dev
/// - Standard device files (null, zero, console)
pub fn vfs_init() {
    manager::init();
    println!("VFS subsystem initialized");
}
