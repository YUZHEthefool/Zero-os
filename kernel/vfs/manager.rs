//! VFS Manager
//!
//! Provides the central VFS operations including:
//! - Mount table management
//! - Path resolution
//! - Global file operations (open, stat, etc.)
//! - Syscall callback registration
//! - DAC (Discretionary Access Control) permission enforcement

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;
use kernel_core::{
    FileOps, FileDescriptor, SyscallError, VfsStat,
    current_euid, current_egid, current_supplementary_groups, current_umask,
};
use crate::devfs::DevFs;
use crate::ramfs::RamFs;
use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FsError, OpenFlags, Stat};

/// Check if current process has required access permissions on a file
///
/// Implements POSIX-style DAC (Discretionary Access Control):
/// 1. Root (euid == 0) has all permissions
/// 2. File owner uses owner permission bits (0o700)
/// 3. File group member (primary or supplementary) uses group permission bits (0o070)
/// 4. Others use other permission bits (0o007)
///
/// # Arguments
/// * `stat` - File status containing uid, gid, and permission mode
/// * `need_read` - Whether read access is required
/// * `need_write` - Whether write access is required
/// * `need_exec` - Whether execute access is required
///
/// # Returns
/// `true` if access is permitted, `false` otherwise
fn check_access_permission(stat: &Stat, need_read: bool, need_write: bool, need_exec: bool) -> bool {
    // Get current process credentials (default to root if no process context)
    let euid = current_euid().unwrap_or(0);
    let egid = current_egid().unwrap_or(0);
    let supplementary = current_supplementary_groups().unwrap_or_default();

    // Root (euid 0) bypasses all permission checks
    if euid == 0 {
        return true;
    }

    let perm = stat.mode.perm;

    // Determine which permission bits to check based on uid/gid
    // Check supplementary groups in addition to primary group
    let check_bits = if euid == stat.uid {
        // Owner: use high bits (0o700)
        (perm >> 6) & 0o7
    } else if egid == stat.gid || supplementary.iter().any(|&g| g == stat.gid) {
        // Group (primary or supplementary): use middle bits (0o070)
        (perm >> 3) & 0o7
    } else {
        // Others: use low bits (0o007)
        perm & 0o7
    };

    // Check each requested permission
    if need_read && (check_bits & 0o4) == 0 {
        return false;
    }
    if need_write && (check_bits & 0o2) == 0 {
        return false;
    }
    if need_exec && (check_bits & 0o1) == 0 {
        return false;
    }

    true
}

/// Apply current process umask to requested permission bits
///
/// The umask bits are cleared from the requested permissions:
/// effective_perm = requested_perm & !umask
///
/// # Arguments
/// * `perm` - Requested permission bits (e.g., 0o666 for files, 0o777 for directories)
///
/// # Returns
/// Permission bits after applying umask
#[inline]
fn apply_umask(perm: u16) -> u16 {
    let mask = current_umask().unwrap_or(0) & 0o777;
    perm & !mask & 0o7777
}

/// Strip setuid/setgid bits from permission if caller is not root
///
/// # Security
///
/// Prevents unprivileged users from creating setuid/setgid executables.
/// - setuid (04000) is always stripped for non-root
/// - setgid (02000) is stripped for regular files for non-root
///   (but allowed on directories for proper setgid inheritance)
///
/// # Arguments
/// * `perm` - Permission bits to sanitize
/// * `is_dir` - Whether the target is a directory
///
/// # Returns
/// Sanitized permission bits
#[inline]
fn strip_suid_sgid_if_needed(perm: u16, is_dir: bool) -> u16 {
    let euid = current_euid().unwrap_or(0);

    if euid == 0 {
        // Root can create setuid/setgid files
        return perm;
    }

    let mut sanitized = perm;

    // Always strip setuid bit for non-root
    sanitized &= !0o4000;

    // Strip setgid bit for regular files (not directories)
    // Directories can keep setgid for proper inheritance
    if !is_dir {
        sanitized &= !0o2000;
    }

    sanitized
}

/// Mount point information
struct Mount {
    /// Absolute path where this filesystem is mounted
    path: String,
    /// The mounted filesystem
    fs: Arc<dyn FileSystem>,
}

/// Global VFS state
pub struct Vfs {
    /// Mount table: path -> filesystem
    mounts: RwLock<BTreeMap<String, Mount>>,
    /// Root filesystem
    root_fs: RwLock<Option<Arc<dyn FileSystem>>>,
}

impl Vfs {
    /// Create a new VFS instance
    pub const fn new() -> Self {
        Self {
            mounts: RwLock::new(BTreeMap::new()),
            root_fs: RwLock::new(None),
        }
    }

    /// Initialize the VFS with default mounts
    pub fn init(&self) {
        // Create ramfs as root filesystem
        let ramfs = RamFs::new();

        // Set ramfs as root
        *self.root_fs.write() = Some(ramfs.clone());

        // Mount ramfs at / first
        self.mount("/", ramfs).expect("Failed to mount ramfs at /");

        // Create and mount devfs at /dev
        let devfs = DevFs::new();
        self.mount("/dev", devfs).expect("Failed to mount devfs");

        println!("VFS initialized: ramfs at /, devfs at /dev");
    }

    /// Mount a filesystem at the given path
    pub fn mount(&self, path: &str, fs: Arc<dyn FileSystem>) -> Result<(), FsError> {
        let path = normalize_path(path);

        let mut mounts = self.mounts.write();
        if mounts.contains_key(&path) {
            return Err(FsError::Exists);
        }

        mounts.insert(path.clone(), Mount { path, fs });
        Ok(())
    }

    /// Unmount filesystem at path
    pub fn umount(&self, path: &str) -> Result<(), FsError> {
        let path = normalize_path(path);
        let mut mounts = self.mounts.write();

        if mounts.remove(&path).is_some() {
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    /// Resolve a path to an inode
    ///
    /// Enforces execute/search permission on each directory component during traversal.
    /// This prevents unauthorized access to files in directories without "x" permission.
    pub fn lookup_path(&self, path: &str) -> Result<Arc<dyn Inode>, FsError> {
        let path = normalize_path(path);

        // Find the mount point that covers this path
        let (_mount_path, fs, relative_path) = self.find_mount(&path)?;

        // Start from the filesystem root
        let mut current = fs.root_inode();

        // Handle empty relative path (mount point itself)
        if relative_path.is_empty() || relative_path == "/" {
            return Ok(current);
        }

        // Walk path components
        let components: Vec<&str> = relative_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        for (idx, component) in components.iter().enumerate() {
            if !current.is_dir() {
                return Err(FsError::NotDir);
            }

            // Check execute/search permission on directory before traversing
            // This is required for all intermediate directories (not the final component)
            // For the final component, we only need execute if it will be traversed further
            if idx < components.len() - 1 || components.len() == 1 {
                // For intermediate dirs, or single-component paths that are dirs
                let dir_stat = current.stat()?;
                if !check_access_permission(&dir_stat, false, false, true) {
                    return Err(FsError::PermDenied);
                }
            }

            current = fs.lookup(&current, component)?;
        }

        Ok(current)
    }

    /// Open a file by path
    ///
    /// Supports O_CREAT for file creation and O_EXCL for exclusive creation.
    pub fn open(&self, path: &str, flags: OpenFlags, create_mode: u16) -> Result<Box<dyn FileOps>, FsError> {
        let path = normalize_path(path);

        // Resolve existing path or create on demand
        let inode = match self.lookup_path(&path) {
            Ok(inode) => {
                // File exists - check O_EXCL
                if flags.is_create() && flags.is_exclusive() {
                    return Err(FsError::Exists);
                }
                inode
            }
            Err(FsError::NotFound) if flags.is_create() => {
                // File doesn't exist and O_CREAT is set - create it
                let (parent_path, filename) = split_path(&path)?;
                let parent = self.lookup_path(&parent_path)?;
                if !parent.is_dir() {
                    return Err(FsError::NotDir);
                }

                // DAC check: need write+execute on parent directory to create files
                let parent_stat = parent.stat()?;
                if !check_access_permission(&parent_stat, false, true, true) {
                    return Err(FsError::PermDenied);
                }

                let (_, fs, _) = self.find_mount(&path)?;
                // Apply umask and strip setuid/setgid bits for non-root
                let requested = create_mode & 0o7777;
                let masked = apply_umask(requested);
                let sanitized = strip_suid_sgid_if_needed(masked, false);
                let mode = FileMode::regular(sanitized);
                fs.create(&parent, filename, mode)?
            }
            Err(e) => return Err(e),
        };

        // V-1 fix: Enforce DAC permissions before opening
        //
        // Full POSIX-style permission model:
        // 1. If euid == 0 (root), allow all access
        // 2. If euid == file owner, check owner bits (0o700)
        // 3. If egid == file group, check group bits (0o070)
        // 4. Otherwise, check other bits (0o007)
        let stat = inode.stat()?;
        if !check_access_permission(&stat, flags.is_readable(), flags.is_writable(), false) {
            return Err(FsError::PermDenied);
        }

        // Check if opening a directory for writing
        if inode.is_dir() && flags.is_writable() {
            return Err(FsError::IsDir);
        }

        // Handle truncate for writable regular files
        if flags.is_truncate() && flags.is_writable() && !inode.is_dir() {
            inode.truncate(0)?;
        }

        inode.open(flags)
    }

    /// Get file status by path
    pub fn stat(&self, path: &str) -> Result<Stat, FsError> {
        let inode = self.lookup_path(path)?;
        inode.stat()
    }

    /// Read directory entries
    pub fn readdir(&self, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let inode = self.lookup_path(path)?;

        if !inode.is_dir() {
            return Err(FsError::NotDir);
        }

        let mut entries = Vec::new();
        let mut offset = 0usize;

        loop {
            match inode.readdir(offset)? {
                Some((next_offset, entry)) => {
                    entries.push(entry);
                    offset = next_offset;
                }
                None => break,
            }
        }

        Ok(entries)
    }

    /// Create a file or directory
    pub fn create(&self, path: &str, mode: FileMode) -> Result<Arc<dyn Inode>, FsError> {
        let path = normalize_path(path);

        // Get parent directory and filename
        let (parent_path, filename) = split_path(&path)?;

        // Lookup parent
        let parent = self.lookup_path(&parent_path)?;
        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        // DAC check: need write+execute on parent directory to create entries
        let parent_stat = parent.stat()?;
        if !check_access_permission(&parent_stat, false, true, true) {
            return Err(FsError::PermDenied);
        }

        // Find the filesystem
        let (_, fs, _) = self.find_mount(&path)?;

        // Apply umask and strip setuid/setgid bits for non-root
        let masked = apply_umask(mode.perm);
        let sanitized = strip_suid_sgid_if_needed(masked, mode.is_dir());
        let masked_mode = FileMode::new(mode.file_type, sanitized);

        // Create the entry with sanitized permissions
        fs.create(&parent, filename, masked_mode)
    }

    /// Remove a file or directory
    ///
    /// Enforces sticky-bit semantics: in a directory with sticky bit set (mode & 0o1000),
    /// only root, the directory owner, or the file owner may delete files.
    pub fn unlink(&self, path: &str) -> Result<(), FsError> {
        let path = normalize_path(path);

        let (parent_path, filename) = split_path(&path)?;
        let parent = self.lookup_path(&parent_path)?;

        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        let parent_stat = parent.stat()?;

        // DAC check: need write+execute on parent directory to unlink entries
        if !check_access_permission(&parent_stat, false, true, true) {
            return Err(FsError::PermDenied);
        }

        let (_, fs, _) = self.find_mount(&path)?;

        // Look up the child to check sticky bit permissions
        let child = fs.lookup(&parent, filename)?;

        // Enforce sticky-bit semantics:
        // If parent directory has sticky bit set, only root, directory owner,
        // or file owner may delete the file
        if parent_stat.mode.perm & 0o1000 != 0 {
            let euid = current_euid().unwrap_or(0);
            if euid != 0 {
                let child_stat = child.stat()?;
                if euid != child_stat.uid && euid != parent_stat.uid {
                    return Err(FsError::PermDenied);
                }
            }
        }

        fs.unlink(&parent, filename)
    }

    /// Find the mount point for a given path
    fn find_mount(&self, path: &str) -> Result<(String, Arc<dyn FileSystem>, String), FsError> {
        let mounts = self.mounts.read();

        // Helper to check if path matches mount point with proper boundaries
        // e.g., /dev matches /dev and /dev/null, but not /device
        let mount_matches = |target: &str, mount_path: &str| -> bool {
            if mount_path == "/" {
                true
            } else if target == mount_path {
                true
            } else {
                target.starts_with(mount_path)
                    && target.as_bytes().get(mount_path.len()) == Some(&b'/')
            }
        };

        // Find longest matching mount point
        let mut best_match: Option<(&String, &Mount)> = None;

        for (mount_path, mount) in mounts.iter() {
            if mount_matches(path, mount_path.as_str()) {
                match best_match {
                    None => best_match = Some((mount_path, mount)),
                    Some((current_path, _)) => {
                        if mount_path.len() > current_path.len() {
                            best_match = Some((mount_path, mount));
                        }
                    }
                }
            }
        }

        if let Some((mount_path, mount)) = best_match {
            let relative = if path.len() > mount_path.len() {
                &path[mount_path.len()..]
            } else {
                "/"
            };
            Ok((mount_path.clone(), Arc::clone(&mount.fs), relative.to_string()))
        } else {
            // No mount found, check if we have a root fs
            let root_fs = self.root_fs.read();
            if let Some(fs) = root_fs.as_ref() {
                Ok(("/".to_string(), Arc::clone(fs), path.to_string()))
            } else {
                Err(FsError::NotFound)
            }
        }
    }
}

/// Global VFS instance
lazy_static::lazy_static! {
    pub static ref VFS: Vfs = Vfs::new();
}

/// Initialize the global VFS
pub fn init() {
    VFS.init();
    register_syscall_callbacks();
}

// ============================================================================
// Path utilities
// ============================================================================

/// Normalize a path (remove . and .., ensure leading /)
fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {} // Skip empty and current dir
            ".." => {
                components.pop(); // Go up one level
            }
            _ => components.push(component),
        }
    }

    if components.is_empty() {
        "/".to_string()
    } else {
        let mut result = String::new();
        for c in components {
            result.push('/');
            result.push_str(c);
        }
        result
    }
}

/// Split path into parent directory and filename
fn split_path(path: &str) -> Result<(String, &str), FsError> {
    let path = path.trim_end_matches('/');

    if path.is_empty() || path == "/" {
        return Err(FsError::Invalid);
    }

    match path.rfind('/') {
        Some(pos) => {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let filename = &path[pos + 1..];
            if filename.is_empty() {
                Err(FsError::Invalid)
            } else {
                Ok((parent.to_string(), filename))
            }
        }
        None => Ok(("/".to_string(), path)),
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Open a file by path (global convenience function)
///
/// # Arguments
/// * `path` - Path to the file
/// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - Permission mode for file creation (only used with O_CREAT)
pub fn open(path: &str, flags: OpenFlags, mode: u16) -> Result<Box<dyn FileOps>, FsError> {
    VFS.open(path, flags, mode)
}

/// Get file status by path
pub fn stat(path: &str) -> Result<Stat, FsError> {
    VFS.stat(path)
}

/// Read directory entries
pub fn readdir(path: &str) -> Result<Vec<DirEntry>, FsError> {
    VFS.readdir(path)
}

/// Mount a filesystem
pub fn mount(path: &str, fs: Arc<dyn FileSystem>) -> Result<(), FsError> {
    VFS.mount(path, fs)
}

/// Unmount a filesystem
pub fn umount(path: &str) -> Result<(), FsError> {
    VFS.umount(path)
}

// ============================================================================
// Syscall callbacks
// ============================================================================

/// Convert VFS FsError to kernel SyscallError
fn fs_error_to_syscall(e: FsError) -> SyscallError {
    match e {
        FsError::NotFound => SyscallError::ENOENT,
        FsError::PermDenied => SyscallError::EACCES,
        FsError::Exists => SyscallError::EEXIST,
        FsError::NotDir => SyscallError::ENOTDIR,
        FsError::IsDir => SyscallError::EISDIR,
        FsError::NotEmpty => SyscallError::EBUSY,
        FsError::ReadOnly => SyscallError::EACCES,
        FsError::NoSpace | FsError::NoMem => SyscallError::ENOMEM,
        FsError::Io => SyscallError::EIO,
        FsError::Invalid | FsError::NameTooLong | FsError::CrossDev | FsError::Seek => SyscallError::EINVAL,
        FsError::NotSupported => SyscallError::ENOSYS,
        FsError::BadFd => SyscallError::EBADF,
        FsError::Pipe => SyscallError::EPIPE,
    }
}

/// VFS open callback for syscall registration
///
/// Called by sys_open to open a file through VFS
fn vfs_open_callback(path: &str, flags: u32, mode: u32) -> Result<FileDescriptor, SyscallError> {
    let open_flags = OpenFlags::from_bits(flags);
    let perm = (mode & 0o7777) as u16;

    VFS.open(path, open_flags, perm).map_err(fs_error_to_syscall)
}

/// VFS stat callback for syscall registration
///
/// Called by sys_stat to get file status through VFS
fn vfs_stat_callback(path: &str) -> Result<VfsStat, SyscallError> {
    let stat = VFS.stat(path).map_err(fs_error_to_syscall)?;

    Ok(VfsStat {
        dev: stat.dev,
        ino: stat.ino,
        mode: stat.mode.to_raw(),
        nlink: stat.nlink,
        uid: stat.uid,
        gid: stat.gid,
        rdev: stat.rdev,
        size: stat.size,
        blksize: stat.blksize,
        blocks: stat.blocks,
        atime_sec: stat.atime.sec,
        atime_nsec: stat.atime.nsec,
        mtime_sec: stat.mtime.sec,
        mtime_nsec: stat.mtime.nsec,
        ctime_sec: stat.ctime.sec,
        ctime_nsec: stat.ctime.nsec,
    })
}

/// VFS lseek callback for syscall registration
///
/// Called by sys_lseek to seek within a file
/// Receives a &dyn Any reference and attempts to downcast to FileHandle
fn vfs_lseek_callback(file_any: &dyn core::any::Any, offset: i64, whence: i32) -> Result<u64, SyscallError> {
    use crate::traits::FileHandle;
    use crate::types::SeekWhence;

    // Try to downcast to FileHandle
    if let Some(file_handle) = file_any.downcast_ref::<FileHandle>() {
        let seek_whence = match whence {
            0 => SeekWhence::Set,
            1 => SeekWhence::Cur,
            2 => SeekWhence::End,
            _ => return Err(SyscallError::EINVAL),
        };

        file_handle.seek(offset, seek_whence)
            .map_err(|e| match e {
                FsError::Seek => SyscallError::EINVAL,
                FsError::Invalid => SyscallError::EINVAL,
                _ => SyscallError::EIO,
            })
    } else {
        // Not a VFS FileHandle (e.g., pipe), seek not supported
        Err(SyscallError::EINVAL)
    }
}

/// Register VFS callbacks with kernel_core
pub fn register_syscall_callbacks() {
    kernel_core::register_vfs_open_callback(vfs_open_callback);
    kernel_core::register_vfs_stat_callback(vfs_stat_callback);
    kernel_core::register_vfs_lseek_callback(vfs_lseek_callback);
    println!("VFS syscall callbacks registered");
}
