//! macOS / Linux live mount via `fuser` (macFUSE on macOS, libfuse on Linux).
//!
//! The counterpart of `winmount.rs`: it exposes the whole folder tree of a
//! `Store`, so a drive written on Windows reads identically on a Mac and vice
//! versa. FUSE addresses everything by inode number; `cloak::inodes::Inodes`
//! maps those to the store's logical paths and survives renames/moves.
//!
//! Usage (the GUI launches this; it also runs by hand):
//!     CLOAK_PASSPHRASE=... cloak-mount <backing-store-dir> <mount-point>
//! The process holds the mount until stdin hits EOF (Enter / closed), then
//! unmounts cleanly — the same contract as `cloak-winmount`, so the app's
//! "lock" (close stdin) works on every OS.
//!
//! Build: `cargo build --release --features mount --bin cloak-mount` on the
//! target OS (macOS needs macFUSE installed; Linux needs libfuse3-dev).

#[cfg(all(feature = "mount", unix))]
fn main() {
    imp::run();
}

#[cfg(not(all(feature = "mount", unix)))]
fn main() {
    eprintln!(
        "cloak-mount is built with `--features mount` on macOS/Linux (needs macFUSE/libfuse).\n\
         On Windows use cloak-winmount (`--features winfsp`)."
    );
    std::process::exit(1);
}

#[cfg(all(feature = "mount", unix))]
mod imp {
    use cloak::inodes::{join, parent_of, Inodes, ROOT_INO};
    use cloak::{Metadata, Store};
    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
        ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
        Request, TimeOrNow,
    };
    use std::ffi::OsStr;
    use std::io;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const TTL: Duration = Duration::from_secs(1);
    const BLOCK: u64 = 4096;

    /// "No such attribute": ENOATTR on macOS, ENODATA on Linux.
    #[cfg(target_os = "macos")]
    const NO_XATTR: i32 = libc::ENOATTR;
    #[cfg(not(target_os = "macos"))]
    const NO_XATTR: i32 = libc::ENODATA;

    /// renameat2/renamex_np flags. Linux: RENAME_NOREPLACE=1, RENAME_EXCHANGE=2.
    /// macOS: RENAME_SWAP=2, RENAME_EXCL=4.
    #[cfg(target_os = "macos")]
    const RENAME_NOREPLACE: u32 = 0x4;
    #[cfg(not(target_os = "macos"))]
    const RENAME_NOREPLACE: u32 = 0x1;
    const RENAME_EXCHANGE: u32 = 0x2;

    /// Map an engine error to this OS's errno.
    fn errno(e: &io::Error) -> i32 {
        use io::ErrorKind::*;
        if let Some(code) = e.raw_os_error() {
            return code;
        }
        match e.kind() {
            NotFound => libc::ENOENT,
            PermissionDenied => libc::EACCES,
            AlreadyExists => libc::EEXIST,
            InvalidInput => libc::EINVAL,
            InvalidFilename => libc::ENAMETOOLONG,
            IsADirectory => libc::EISDIR,
            NotADirectory => libc::ENOTDIR,
            DirectoryNotEmpty => libc::ENOTEMPTY,
            StorageFull => libc::ENOSPC,
            _ => libc::EIO,
        }
    }

    /// Finder litter that macFUSE's `noappledouble` normally blocks; refused here
    /// too so FUSE-T (which may ignore that option) can't write it into the
    /// store, where it would show up on Windows.
    #[cfg(target_os = "macos")]
    fn is_mac_litter(name: &str) -> bool {
        name == ".DS_Store" || name.starts_with("._")
    }
    #[cfg(not(target_os = "macos"))]
    fn is_mac_litter(_name: &str) -> bool {
        false
    }

    struct CloakFs {
        store: Store,
        inodes: Inodes,
        uid: u32,
        gid: u32,
    }

    impl CloakFs {
        fn attr(&self, ino: u64, m: Metadata) -> FileAttr {
            FileAttr {
                ino,
                size: m.size,
                blocks: m.size.div_ceil(512),
                // The store keeps no timestamps (Windows shows them as 1601).
                atime: UNIX_EPOCH,
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
                kind: if m.is_dir { FileType::Directory } else { FileType::RegularFile },
                perm: if m.is_dir { 0o755 } else { 0o644 },
                nlink: if m.is_dir { 2 } else { 1 },
                uid: self.uid,
                gid: self.gid,
                rdev: 0,
                blksize: BLOCK as u32,
                flags: 0,
            }
        }

        /// Path and metadata for an inode.
        fn node(&self, ino: u64) -> Result<(String, Metadata), i32> {
            let path = self.inodes.path(ino).ok_or(libc::ENOENT)?.to_string();
            let m = self
                .store
                .metadata(&path)
                .map_err(|e| errno(&e))?
                .ok_or(libc::ENOENT)?;
            Ok((path, m))
        }

        /// Logical path of `name` inside directory `parent`.
        fn child(&self, parent: u64, name: &OsStr) -> Result<String, i32> {
            let dir = self.inodes.path(parent).ok_or(libc::ENOENT)?;
            let name = name.to_str().ok_or(libc::EINVAL)?;
            Ok(join(dir, name))
        }

        /// Look up an existing path: its stored spelling, inode and attributes.
        fn entry(&mut self, path: &str) -> Result<FileAttr, i32> {
            let m = self
                .store
                .metadata(path)
                .map_err(|e| errno(&e))?
                .ok_or(libc::ENOENT)?;
            let canonical = self
                .store
                .canonical_path(path)
                .ok()
                .flatten()
                .unwrap_or_else(|| path.to_string());
            let ino = self.inodes.ino(&canonical);
            Ok(self.attr(ino, m))
        }

        fn canonical(&self, path: &str) -> String {
            self.store
                .canonical_path(path)
                .ok()
                .flatten()
                .unwrap_or_else(|| path.to_string())
        }
    }

    impl Filesystem for CloakFs {
        fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
            match self.child(parent, name).and_then(|p| self.entry(&p)) {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(e) => reply.error(e),
            }
        }

        fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
            match self.node(ino) {
                Ok((_, m)) => reply.attr(&TTL, &self.attr(ino, m)),
                Err(e) => reply.error(e),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn setattr(
            &mut self,
            _req: &Request,
            ino: u64,
            _mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            size: Option<u64>,
            _atime: Option<TimeOrNow>,
            _mtime: Option<TimeOrNow>,
            _ctime: Option<SystemTime>,
            _fh: Option<u64>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            let (path, m) = match self.node(ino) {
                Ok(n) => n,
                Err(e) => return reply.error(e),
            };
            // Size is the one attribute stored; mode/owner/times are accepted
            // and ignored so `cp -p`, `touch` and Finder copies succeed.
            if let Some(new_size) = size {
                if m.is_dir {
                    return reply.error(libc::EISDIR);
                }
                if let Err(e) = self.store.truncate(&path, new_size) {
                    return reply.error(errno(&e));
                }
            }
            match self.node(ino) {
                Ok((_, m)) => reply.attr(&TTL, &self.attr(ino, m)),
                Err(e) => reply.error(e),
            }
        }

        fn mkdir(
            &mut self,
            _req: &Request,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            reply: ReplyEntry,
        ) {
            if name.to_str().is_some_and(is_mac_litter) {
                return reply.error(libc::EACCES);
            }
            let result = self.child(parent, name).and_then(|path| {
                self.store.mkdir(&path).map_err(|e| errno(&e))?;
                self.entry(&path)
            });
            match result {
                Ok(attr) => reply.entry(&TTL, &attr, 0),
                Err(e) => reply.error(e),
            }
        }

        fn create(
            &mut self,
            _req: &Request,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            flags: i32,
            reply: ReplyCreate,
        ) {
            if name.to_str().is_some_and(is_mac_litter) {
                return reply.error(libc::EACCES);
            }
            let result = self.child(parent, name).and_then(|path| {
                let exists = self.store.metadata(&path).map_err(|e| errno(&e))?.is_some();
                if exists && flags & libc::O_EXCL != 0 {
                    return Err(libc::EEXIST);
                }
                self.store.create(&path).map_err(|e| errno(&e))?;
                if exists && flags & libc::O_TRUNC != 0 {
                    self.store.truncate(&path, 0).map_err(|e| errno(&e))?;
                }
                self.entry(&path)
            });
            match result {
                Ok(attr) => reply.created(&TTL, &attr, 0, 0, 0),
                Err(e) => reply.error(e),
            }
        }

        fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
            match self.node(ino) {
                Ok((_, m)) if m.is_dir => reply.error(libc::EISDIR),
                Ok((path, _)) => {
                    if flags & libc::O_TRUNC != 0 {
                        if let Err(e) = self.store.truncate(&path, 0) {
                            return reply.error(errno(&e));
                        }
                    }
                    reply.opened(0, 0)
                }
                Err(e) => reply.error(e),
            }
        }

        fn read(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock: Option<u64>,
            reply: ReplyData,
        ) {
            let Some(path) = self.inodes.path(ino) else {
                return reply.error(libc::ENOENT);
            };
            match self.store.read_at(path, offset.max(0) as u64, size as usize) {
                Ok(bytes) => reply.data(&bytes),
                Err(e) => reply.error(errno(&e)),
            }
        }

        fn write(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            data: &[u8],
            _write_flags: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyWrite,
        ) {
            let Some(path) = self.inodes.path(ino).map(str::to_string) else {
                return reply.error(libc::ENOENT);
            };
            match self.store.write_at(&path, offset.max(0) as u64, data) {
                Ok(()) => reply.written(data.len() as u32),
                Err(e) => reply.error(errno(&e)),
            }
        }

        fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
            match self.node(ino) {
                Ok((_, m)) if m.is_dir => reply.opened(0, 0),
                Ok(_) => reply.error(libc::ENOTDIR),
                Err(e) => reply.error(e),
            }
        }

        fn readdir(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            mut reply: ReplyDirectory,
        ) {
            let Some(dir) = self.inodes.path(ino).map(str::to_string) else {
                return reply.error(libc::ENOENT);
            };
            let mut children = match self.store.list_dir(&dir) {
                Ok(c) => c,
                Err(e) => return reply.error(errno(&e)),
            };
            // Stable order so a listing resumed at `offset` doesn't skip or repeat.
            children.sort_by_cached_key(|(name, _, _)| cloak::names::fold(name));

            let parent_ino = if ino == ROOT_INO {
                ROOT_INO
            } else {
                self.inodes.ino(parent_of(&dir))
            };
            let mut entries = vec![
                (ino, FileType::Directory, ".".to_string()),
                (parent_ino, FileType::Directory, "..".to_string()),
            ];
            for (name, is_dir, _) in children {
                let child_ino = self.inodes.ino(&join(&dir, &name));
                let kind = if is_dir { FileType::Directory } else { FileType::RegularFile };
                entries.push((child_ino, kind, name));
            }
            for (i, (child_ino, kind, name)) in
                entries.into_iter().enumerate().skip(offset.max(0) as usize)
            {
                if reply.add(child_ino, (i + 1) as i64, kind, &name) {
                    break; // reply buffer full; the kernel resumes at this offset
                }
            }
            reply.ok();
        }

        fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let result = self.child(parent, name).and_then(|path| {
                let m = self.store.metadata(&path).map_err(|e| errno(&e))?;
                match m {
                    None => Err(libc::ENOENT),
                    // POSIX: unlink(2) on a directory is EISDIR (Linux) / EPERM (macOS).
                    Some(m) if m.is_dir => Err(if cfg!(target_os = "macos") {
                        libc::EPERM
                    } else {
                        libc::EISDIR
                    }),
                    Some(_) => {
                        let canonical = self.canonical(&path);
                        self.store.remove(&path).map_err(|e| errno(&e))?;
                        self.inodes.forget(&canonical);
                        Ok(())
                    }
                }
            });
            match result {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(e),
            }
        }

        fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let result = self.child(parent, name).and_then(|path| {
                let m = self
                    .store
                    .metadata(&path)
                    .map_err(|e| errno(&e))?
                    .ok_or(libc::ENOENT)?;
                if !m.is_dir {
                    return Err(libc::ENOTDIR);
                }
                // The engine deletes subtrees; rmdir(2) must only remove empty ones.
                if !self.store.list_dir(&path).map_err(|e| errno(&e))?.is_empty() {
                    return Err(libc::ENOTEMPTY);
                }
                let canonical = self.canonical(&path);
                self.store.remove(&path).map_err(|e| errno(&e))?;
                self.inodes.forget(&canonical);
                Ok(())
            });
            match result {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(e),
            }
        }

        fn rename(
            &mut self,
            _req: &Request,
            parent: u64,
            name: &OsStr,
            newparent: u64,
            newname: &OsStr,
            flags: u32,
            reply: ReplyEmpty,
        ) {
            if flags & RENAME_EXCHANGE != 0 {
                return reply.error(libc::EINVAL); // atomic swap isn't supported
            }
            if newname.to_str().is_some_and(is_mac_litter) {
                return reply.error(libc::EACCES);
            }
            let result = (|| {
                let old = self.child(parent, name)?;
                let new = self.child(newparent, newname)?;
                let old_canonical = self.canonical(&old);
                // A different entry already at `new` is replaced (POSIX rename),
                // which is how most Mac apps save. Forget its inodes first.
                let replaced = self
                    .store
                    .metadata(&new)
                    .map_err(|e| errno(&e))?
                    .is_some()
                    && !cloak::names::same(&old_canonical, &self.canonical(&new));
                if flags & RENAME_NOREPLACE != 0 {
                    self.store.rename_path(&old, &new).map_err(|e| errno(&e))?;
                } else {
                    let new_canonical = self.canonical(&new);
                    self.store.rename_replace(&old, &new).map_err(|e| errno(&e))?;
                    if replaced {
                        self.inodes.forget(&new_canonical);
                    }
                }
                let new_canonical = self.canonical(&new);
                self.inodes.rename(&old_canonical, &new_canonical);
                Ok(())
            })();
            match result {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(e),
            }
        }

        fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
            // Nominal sizes, as on Windows. Finder refuses to copy onto a volume
            // reporting zero free space, which is fuser's default.
            let total = (1u64 << 40) / BLOCK;
            let free = (1u64 << 39) / BLOCK;
            reply.statfs(total, free, free, 1 << 20, 1 << 20, BLOCK as u32, 255, BLOCK as u32);
        }

        // Extended attributes aren't stored. Answer like a filesystem without
        // any rather than ENOSYS, which makes Finder abort copies with -36.
        fn getxattr(&mut self, _req: &Request, _ino: u64, _name: &OsStr, _size: u32, reply: ReplyXattr) {
            reply.error(NO_XATTR);
        }

        fn listxattr(&mut self, _req: &Request, _ino: u64, size: u32, reply: ReplyXattr) {
            if size == 0 {
                reply.size(0);
            } else {
                reply.data(&[]);
            }
        }

        fn setxattr(
            &mut self,
            _req: &Request,
            _ino: u64,
            _name: &OsStr,
            _value: &[u8],
            _flags: i32,
            _position: u32,
            reply: ReplyEmpty,
        ) {
            reply.error(libc::ENOTSUP);
        }

        fn removexattr(&mut self, _req: &Request, _ino: u64, _name: &OsStr, reply: ReplyEmpty) {
            reply.error(NO_XATTR);
        }

        fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
            reply.ok(); // writes go straight to the backing store
        }

        fn fsync(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
            reply.ok();
        }

        fn fsyncdir(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
            reply.ok();
        }
    }

    pub fn run() {
        let mut args = std::env::args().skip(1);
        let (store_dir, mount_point) = match (args.next(), args.next()) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                eprintln!("usage: cloak-mount <backing-store-dir> <mount-point>");
                std::process::exit(2);
            }
        };

        // Passphrase from the environment keeps it off the command line / argv.
        let passphrase = std::env::var("CLOAK_PASSPHRASE").unwrap_or_else(|_| {
            eprintln!("set CLOAK_PASSPHRASE to the store passphrase");
            std::process::exit(2);
        });
        let store = Store::open_with_passphrase(&store_dir, &passphrase).expect("open store");
        let fs = CloakFs {
            store,
            inodes: Inodes::default(),
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };

        #[allow(unused_mut)]
        let mut options = vec![MountOption::FSName("cloak".to_string())];
        #[cfg(target_os = "macos")]
        {
            let volname = std::path::Path::new(&mount_point)
                .file_name()
                .map_or_else(|| "cloak".into(), |n| n.to_string_lossy().into_owned());
            options.extend([
                MountOption::CUSTOM(format!("volname={volname}")),
                // Keep Finder's ._* / .DS_Store files and com.apple.* xattrs out
                // of the store (they'd appear as junk files on Windows).
                MountOption::CUSTOM("noappledouble".into()),
                MountOption::CUSTOM("noapplexattr".into()),
            ]);
        }

        let session = fuser::spawn_mount2(fs, &mount_point, &options).expect("mount failed");
        println!("mounted {store_dir} at {mount_point}; press Enter (or close stdin) to unmount");

        // Hold the mount until stdin closes, like cloak-winmount: the app locks
        // a drive by closing our stdin. (macFUSE has no auto-unmount on exit, so
        // this explicit unmount is what keeps a lock from leaving a stale mount.)
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        drop(session); // unmounts
    }
}
