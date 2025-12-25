//! Process filesystem (procfs)
//!
//! Provides /proc virtual filesystem with process information:
//! - /proc/self - Symlink to current process directory
//! - /proc/[pid]/ - Per-process directory
//! - /proc/[pid]/status - Process status
//! - /proc/[pid]/cmdline - Command line
//! - /proc/[pid]/stat - Process statistics
//! - /proc/meminfo - System memory information
//! - /proc/cpuinfo - CPU information

use crate::traits::{FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::FileOps;
use spin::RwLock;

/// Global procfs ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(200);

// ============================================================================
// ProcFs
// ============================================================================

/// Process filesystem
pub struct ProcFs {
    fs_id: u64,
    root: Arc<ProcRootInode>,
}

impl ProcFs {
    /// Create a new procfs
    pub fn new() -> Arc<Self> {
        let fs_id = NEXT_FS_ID.fetch_add(1, Ordering::SeqCst);

        let root = Arc::new(ProcRootInode { fs_id });

        Arc::new(Self { fs_id, root })
    }
}

impl FileSystem for ProcFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "proc"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Check if parent is root
        if parent.ino() == 1 {
            return self.root.lookup_child(name);
        }

        // Check if parent is a PID directory
        if let Some(proc_dir) = parent.as_any().downcast_ref::<ProcPidDirInode>() {
            return proc_dir.lookup_child(name);
        }

        // Traverse /proc/self/<...> by delegating to the current PID directory
        if let Some(self_link) = parent.as_any().downcast_ref::<ProcSelfSymlink>() {
            let alias_dir = ProcPidDirInode {
                fs_id: self.fs_id,
                pid: self_link.target_pid,
            };
            return alias_dir.lookup_child(name);
        }

        // Resolve entries under /proc/[pid]/fd
        if let Some(fd_dir) = parent.as_any().downcast_ref::<ProcPidFdDirInode>() {
            return fd_dir.lookup_child(name);
        }

        Err(FsError::NotFound)
    }
}

// ============================================================================
// Root Directory (/proc)
// ============================================================================

/// /proc root directory inode
struct ProcRootInode {
    fs_id: u64,
}

impl ProcRootInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "self" => {
                // Symlink to current process
                let pid = get_current_pid();
                Ok(Arc::new(ProcSelfSymlink {
                    fs_id: self.fs_id,
                    target_pid: pid,
                }))
            }
            "meminfo" => Ok(Arc::new(ProcMeminfoInode { fs_id: self.fs_id })),
            "cpuinfo" => Ok(Arc::new(ProcCpuinfoInode { fs_id: self.fs_id })),
            "uptime" => Ok(Arc::new(ProcUptimeInode { fs_id: self.fs_id })),
            "version" => Ok(Arc::new(ProcVersionInode { fs_id: self.fs_id })),
            _ => {
                // Try to parse as PID
                if let Ok(pid) = name.parse::<u32>() {
                    if process_exists(pid) {
                        return Ok(Arc::new(ProcPidDirInode {
                            fs_id: self.fs_id,
                            pid,
                        }));
                    }
                }
                Err(FsError::NotFound)
            }
        }
    }
}

impl Inode for ProcRootInode {
    fn ino(&self) -> u64 {
        1
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 1,
            mode: FileMode::directory(0o555),
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
        Err(FsError::IsDir)
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // Static entries
        let static_entries = ["self", "meminfo", "cpuinfo", "uptime", "version"];

        if offset < static_entries.len() {
            let name = static_entries[offset];
            let file_type = if name == "self" {
                FileType::Symlink
            } else {
                FileType::Regular
            };
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: String::from(name),
                    ino: (offset + 2) as u64,
                    file_type,
                },
            )));
        }

        // List PIDs
        let pids = list_pids();
        let pid_offset = offset - static_entries.len();

        if pid_offset < pids.len() {
            let pid = pids[pid_offset];
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: format!("{}", pid),
                    ino: 1000 + pid as u64,
                    file_type: FileType::Directory,
                },
            )));
        }

        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/self Symlink
// ============================================================================

struct ProcSelfSymlink {
    fs_id: u64,
    target_pid: u32,
}

impl ProcSelfSymlink {
    fn pid_dir(&self) -> ProcPidDirInode {
        ProcPidDirInode {
            fs_id: self.fs_id,
            pid: self.target_pid,
        }
    }
}

impl Inode for ProcSelfSymlink {
    fn ino(&self) -> u64 {
        2
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let target = format!("{}", self.target_pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: 2,
            mode: FileMode::new(FileType::Symlink, 0o777),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: target.len() as u64,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, _flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        Err(FsError::Invalid)
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Return the symlink target
        let target = format!("{}", self.target_pid);
        let bytes = target.as_bytes();
        let len = buf.len().min(bytes.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }

    fn is_dir(&self) -> bool {
        // Allow traversal through /proc/self/<...> before global symlink support exists
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        if !process_exists(self.target_pid) {
            return Err(FsError::NotFound);
        }
        self.pid_dir().readdir(offset)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/ Directory
// ============================================================================

struct ProcPidDirInode {
    fs_id: u64,
    pid: u32,
}

impl ProcPidDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "status" => Ok(Arc::new(ProcPidStatusInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "cmdline" => Ok(Arc::new(ProcPidCmdlineInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "stat" => Ok(Arc::new(ProcPidStatInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "maps" => Ok(Arc::new(ProcPidMapsInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "fd" => Ok(Arc::new(ProcPidFdDirInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            _ => Err(FsError::NotFound),
        }
    }
}

impl Inode for ProcPidDirInode {
    fn ino(&self) -> u64 {
        1000 + self.pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: 1000 + self.pid as u64,
            mode: FileMode::directory(0o555),
            nlink: 2,
            uid,
            gid,
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
        Err(FsError::IsDir)
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let entries = ["status", "cmdline", "stat", "maps", "fd"];

        if offset < entries.len() {
            let name = entries[offset];
            let file_type = if name == "fd" {
                FileType::Directory
            } else {
                FileType::Regular
            };
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: String::from(name),
                    ino: self.ino() * 10 + offset as u64,
                    file_type,
                },
            )));
        }

        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/status
// ============================================================================

struct ProcPidStatusInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidStatusInode {
    fn ino(&self) -> u64 {
        10000 + self.pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: generate_status(self.pid),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_status(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/cmdline
// ============================================================================

struct ProcPidCmdlineInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidCmdlineInode {
    fn ino(&self) -> u64 {
        20000 + self.pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: get_process_cmdline(self.pid),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = get_process_cmdline(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/stat
// ============================================================================

struct ProcPidStatInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidStatInode {
    fn ino(&self) -> u64 {
        30000 + self.pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: generate_stat(self.pid),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_stat(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/maps
// ============================================================================

struct ProcPidMapsInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidMapsInode {
    fn ino(&self) -> u64 {
        40000 + self.pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: generate_maps(self.pid),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_maps(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/fd/ Directory
// ============================================================================

struct ProcPidFdDirInode {
    fs_id: u64,
    pid: u32,
}

impl ProcPidFdDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let fd: u32 = name.parse().map_err(|_| FsError::NotFound)?;
        let fds = list_process_fds(self.pid);
        if !fds.iter().any(|&n| n == fd) {
            return Err(FsError::NotFound);
        }
        Ok(Arc::new(ProcPidFdSymlink {
            fs_id: self.fs_id,
            pid: self.pid,
            fd,
        }))
    }
}

impl Inode for ProcPidFdDirInode {
    fn ino(&self) -> u64 {
        50000 + self.pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::directory(0o500),
            nlink: 2,
            uid,
            gid,
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
        Err(FsError::IsDir)
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let fds = list_process_fds(self.pid);
        if offset < fds.len() {
            let fd = fds[offset];
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: format!("{}", fd),
                    ino: self.ino() * 1000 + fd as u64,
                    file_type: FileType::Symlink,
                },
            )));
        }
        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/fd/<n> Symlink
// ============================================================================

struct ProcPidFdSymlink {
    fs_id: u64,
    pid: u32,
    fd: u32,
}

impl Inode for ProcPidFdSymlink {
    fn ino(&self) -> u64 {
        (50000 + self.pid as u64) * 1000 + self.fd as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        let target = get_fd_target(self.pid, self.fd);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::new(FileType::Symlink, 0o777),
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: target.len() as u64,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, _flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        Err(FsError::Invalid)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let target = get_fd_target(self.pid, self.fd);
        read_from_content(&target, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/meminfo
// ============================================================================

struct ProcMeminfoInode {
    fs_id: u64,
}

impl Inode for ProcMeminfoInode {
    fn ino(&self) -> u64 {
        3
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 3,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: generate_meminfo(),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_meminfo();
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/cpuinfo
// ============================================================================

struct ProcCpuinfoInode {
    fs_id: u64,
}

impl Inode for ProcCpuinfoInode {
    fn ino(&self) -> u64 {
        4
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 4,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: generate_cpuinfo(),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_cpuinfo();
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/uptime
// ============================================================================

struct ProcUptimeInode {
    fs_id: u64,
}

impl Inode for ProcUptimeInode {
    fn ino(&self) -> u64 {
        5
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 5,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: generate_uptime(),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_uptime();
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/version
// ============================================================================

struct ProcVersionInode {
    fs_id: u64,
}

impl Inode for ProcVersionInode {
    fn ino(&self) -> u64 {
        6
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 6,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        Ok(Box::new(ProcReadOnlyFile {
            content: String::from("Zero-OS version 0.1.0 (rustc)\n"),
            offset: RwLock::new(0),
        }))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = "Zero-OS version 0.1.0 (rustc)\n";
        read_from_content(content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Read-only file handle
// ============================================================================

struct ProcReadOnlyFile {
    content: String,
    offset: RwLock<u64>,
}

impl FileOps for ProcReadOnlyFile {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(ProcReadOnlyFile {
            content: self.content.clone(),
            offset: RwLock::new(*self.offset.read()),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "ProcFile"
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn read_from_content(content: &str, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
    let bytes = content.as_bytes();
    if offset >= bytes.len() as u64 {
        return Ok(0);
    }
    let start = offset as usize;
    let len = buf.len().min(bytes.len() - start);
    buf[..len].copy_from_slice(&bytes[start..start + len]);
    Ok(len)
}

/// Get current process ID
fn get_current_pid() -> u32 {
    // TODO: Get actual current PID from scheduler
    1
}

/// Check if a process exists
fn process_exists(pid: u32) -> bool {
    // TODO: Check actual process table
    pid == 1 || pid == 0
}

/// List all PIDs
fn list_pids() -> Vec<u32> {
    // TODO: Get actual PID list from scheduler
    alloc::vec![1]
}

/// Get process owner (uid, gid)
fn get_process_owner(_pid: u32) -> (u32, u32) {
    // TODO: Get actual process owner
    (0, 0)
}

/// Get process command line
fn get_process_cmdline(pid: u32) -> String {
    // TODO: Get actual command line from process
    if pid == 1 {
        String::from("init\0")
    } else {
        String::new()
    }
}

/// List file descriptors for a process
fn list_process_fds(_pid: u32) -> Vec<u32> {
    // TODO: Get actual FD list from process
    alloc::vec![0, 1, 2]
}

/// Resolve a file descriptor target for /proc/[pid]/fd/<n>
fn get_fd_target(pid: u32, fd: u32) -> String {
    // TODO: Look up the real path or descriptor type from the process table
    match fd {
        0 => String::from("/dev/console"),
        1 => String::from("/dev/console"),
        2 => String::from("/dev/console"),
        _ => format!("(pid {} fd {})", pid, fd),
    }
}

/// Generate /proc/[pid]/status content
fn generate_status(pid: u32) -> String {
    // TODO: Get actual process info
    format!(
        "Name:\tinit\n\
         Umask:\t0022\n\
         State:\tS (sleeping)\n\
         Tgid:\t{pid}\n\
         Pid:\t{pid}\n\
         PPid:\t0\n\
         Uid:\t0\t0\t0\t0\n\
         Gid:\t0\t0\t0\t0\n\
         VmSize:\t    1024 kB\n\
         VmRSS:\t     512 kB\n\
         Threads:\t1\n"
    )
}

/// Generate /proc/[pid]/stat content
fn generate_stat(pid: u32) -> String {
    // Minimal stat format: pid (comm) state ppid pgrp session tty_nr ...
    format!(
        "{pid} (init) S 0 {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
}

/// Generate /proc/[pid]/maps content
fn generate_maps(_pid: u32) -> String {
    // TODO: Get actual memory maps from process
    String::from(
        "00400000-00401000 r-xp 00000000 00:00 0    [code]\n\
         7fffffffe000-7ffffffff000 rw-p 00000000 00:00 0    [stack]\n",
    )
}

/// Generate /proc/meminfo content
fn generate_meminfo() -> String {
    // TODO: Get actual memory info from mm
    format!(
        "MemTotal:      131072 kB\n\
         MemFree:        65536 kB\n\
         MemAvailable:   65536 kB\n\
         Buffers:            0 kB\n\
         Cached:          4096 kB\n\
         SwapTotal:          0 kB\n\
         SwapFree:           0 kB\n"
    )
}

/// Generate /proc/cpuinfo content
fn generate_cpuinfo() -> String {
    String::from(
        "processor\t: 0\n\
         vendor_id\t: Zero-OS\n\
         cpu family\t: 6\n\
         model\t\t: 0\n\
         model name\t: Zero-OS Virtual CPU\n\
         stepping\t: 0\n\
         cpu MHz\t\t: 1000.000\n\
         cache size\t: 0 KB\n\
         flags\t\t: fpu vme de pse tsc msr pae mce cx8\n\
         bogomips\t: 2000.00\n\n",
    )
}

/// Generate /proc/uptime content
fn generate_uptime() -> String {
    // TODO: Get actual uptime from timer
    String::from("0.00 0.00\n")
}
