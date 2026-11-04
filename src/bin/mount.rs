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
    use std::sync::{
        mpsc, Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
    };
    use std::time::{Duration, SystemTime};

    /// How long the kernel may reuse a name lookup without asking. Kept
    /// short: it caches each spelling separately while the store's names are
    /// case-insensitive, so a deleted `a.txt` can linger as `A.txt` this long.
    const ENTRY_TTL: Duration = Duration::from_secs(5);
    /// How long the kernel may reuse a file's details without asking. Every
    /// change goes through this mount and the kernel keeps its copy current
    /// for its own changes (the Windows adapter's cache never expires), so
    /// this can be long; Finder otherwise re-asks for every item it shows.
    const ATTR_TTL: Duration = Duration::from_secs(60);
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
        shared: Shared,
        /// Threads that run reads, lookups and listings (fuser hands us one
        /// request at a time).
        workers: Workers,
    }

    impl std::ops::Deref for CloakFs {
        type Target = Shared;
        fn deref(&self) -> &Shared {
            &self.shared
        }
    }

    /// What the request handlers work on, shared with the workers. The store
    /// and the inode table have a lock each, never held together.
    #[derive(Clone)]
    struct Shared {
        /// Reads, lookups and listings can run side by side, changes one at a
        /// time. Also shared with the thread that saves directory lists
        /// (`saver`).
        store: Arc<RwLock<Store>>,
        inodes: Arc<Mutex<Inodes>>,
        uid: u32,
        gid: u32,
    }

    impl Shared {
        fn store(&self) -> RwLockWriteGuard<'_, Store> {
            lock(&self.store)
        }

        /// The store for a call that changes nothing (runs alongside reads).
        fn reader(&self) -> RwLockReadGuard<'_, Store> {
            self.store.read().unwrap_or_else(PoisonError::into_inner)
        }

        fn inodes(&self) -> MutexGuard<'_, Inodes> {
            self.inodes.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn attr(&self, ino: u64, m: Metadata) -> FileAttr {
            FileAttr {
                ino,
                size: m.size,
                blocks: m.size.div_ceil(512),
                atime: m.accessed,
                mtime: m.modified,
                ctime: m.modified,
                crtime: m.created,
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
            let path = self.inodes().path(ino).ok_or(libc::ENOENT)?.to_string();
            let m = self
                .reader()
                .metadata(&path)
                .map_err(|e| errno(&e))?
                .ok_or(libc::ENOENT)?;
            Ok((path, m))
        }

        /// Logical path of `name` inside directory `parent`.
        fn child(&self, parent: u64, name: &OsStr) -> Result<String, i32> {
            let name = name.to_str().ok_or(libc::EINVAL)?;
            let inodes = self.inodes();
            let dir = inodes.path(parent).ok_or(libc::ENOENT)?;
            Ok(join(dir, name))
        }

        /// Look up an existing path: its stored spelling, inode and attributes.
        /// Counts a lookup on the inode, so only for a reply that hands it to
        /// the kernel (lookup, create, mkdir), which later `forget`s it.
        fn entry(&self, path: &str) -> Result<FileAttr, i32> {
            let m = self
                .reader()
                .metadata(path)
                .map_err(|e| errno(&e))?
                .ok_or(libc::ENOENT)?;
            let canonical = self
                .reader()
                .canonical_path(path)
                .ok()
                .flatten()
                .unwrap_or_else(|| path.to_string());
            let ino = self.inodes().looked_up(&canonical);
            Ok(self.attr(ino, m))
        }

        fn canonical(&self, path: &str) -> String {
            self.reader()
                .canonical_path(path)
                .ok()
                .flatten()
                .unwrap_or_else(|| path.to_string())
        }

        /// Answer a readdir: directory `ino`'s entries from `offset` on.
        fn list(&self, ino: u64, offset: i64, mut reply: ReplyDirectory) {
            let Some(dir) = self.inodes().path(ino).map(str::to_string) else {
                return reply.error(libc::ENOENT);
            };
            let mut children = match self.reader().list_entries(&dir) {
                Ok(c) => c,
                Err(e) => return reply.error(errno(&e)),
            };
            // Stable order so a listing resumed at `offset` doesn't skip or repeat.
            children.sort_by_cached_key(|e| cloak::names::fold(&e.name));

            let mut inodes = self.inodes();
            inodes.trim();
            let parent_ino = if ino == ROOT_INO {
                ROOT_INO
            } else {
                inodes.ino(parent_of(&dir))
            };
            let mut entries = vec![
                (ino, FileType::Directory, ".".to_string()),
                (parent_ino, FileType::Directory, "..".to_string()),
            ];
            for e in children {
                let child_ino = inodes.ino(&join(&dir, &e.name));
                let kind = if e.is_dir { FileType::Directory } else { FileType::RegularFile };
                entries.push((child_ino, kind, e.name));
            }
            drop(inodes);
            for (i, (child_ino, kind, name)) in
                entries.into_iter().enumerate().skip(offset.max(0) as usize)
            {
                if reply.add(child_ino, (i + 1) as i64, kind, &name) {
                    break; // reply buffer full; the kernel resumes at this offset
                }
            }
            reply.ok();
        }
    }

    impl Filesystem for CloakFs {
        // Lookups, details and listings change nothing in the store, so like
        // reads they run on the workers, side by side, and a slow one doesn't
        // hold up the requests queued behind it.

        fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
            let s = self.shared.clone();
            let name = name.to_owned();
            self.workers.run(move || match s.child(parent, &name).and_then(|p| s.entry(&p)) {
                Ok(attr) => reply.entry(&ENTRY_TTL, &attr, 0),
                Err(e) => reply.error(e),
            });
        }

        /// The kernel is done with `nlookup` of the times it was given `ino`;
        /// once it has none left the inode table lets the entry go, which
        /// keeps the table from growing for as long as the drive is mounted.
        fn forget(&mut self, _req: &Request, ino: u64, nlookup: u64) {
            self.inodes().forget(ino, nlookup);
        }

        fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
            let s = self.shared.clone();
            self.workers.run(move || match s.node(ino) {
                Ok((_, m)) => reply.attr(&ATTR_TTL, &s.attr(ino, m)),
                Err(e) => reply.error(e),
            });
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
            atime: Option<TimeOrNow>,
            mtime: Option<TimeOrNow>,
            _ctime: Option<SystemTime>,
            fh: Option<u64>,
            crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            let (path, m) = match self.node(ino) {
                Ok(n) => n,
                Err(e) => return reply.error(e),
            };
            // Size and times are applied; mode/owner are accepted and ignored
            // so `cp -p`, `touch` and Finder copies succeed.
            if let Some(new_size) = size {
                if m.is_dir {
                    return reply.error(libc::EISDIR);
                }
                let result = match fh {
                    Some(fh) if fh != 0 => self.store().truncate_file(fh, new_size),
                    _ => self.store().truncate(&path, new_size),
                };
                if let Err(e) = result {
                    return reply.error(errno(&e));
                }
            }
            let when = |t: TimeOrNow| match t {
                TimeOrNow::SpecificTime(t) => t,
                TimeOrNow::Now => SystemTime::now(),
            };
            if atime.is_some() || mtime.is_some() || crtime.is_some() {
                if let Err(e) = self.store().set_times(&path, atime.map(when), mtime.map(when), crtime) {
                    return reply.error(errno(&e));
                }
            }
            match self.node(ino) {
                Ok((_, m)) => reply.attr(&ATTR_TTL, &self.attr(ino, m)),
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
                self.store().mkdir(&path).map_err(|e| errno(&e))?;
                self.entry(&path)
            });
            match result {
                Ok(attr) => reply.entry(&ENTRY_TTL, &attr, 0),
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
                let exists = self.reader().metadata(&path).map_err(|e| errno(&e))?.is_some();
                if exists && flags & libc::O_EXCL != 0 {
                    return Err(libc::EEXIST);
                }
                self.store().create(&path).map_err(|e| errno(&e))?;
                let fh = self.store().open_file(&path).map_err(|e| errno(&e))?;
                if exists && flags & libc::O_TRUNC != 0 {
                    self.store().truncate_file(fh, 0).map_err(|e| errno(&e))?;
                }
                Ok((self.entry(&path)?, fh))
            });
            match result {
                Ok((attr, fh)) => reply.created(&ENTRY_TTL, &attr, 0, fh, 0),
                Err(e) => reply.error(e),
            }
        }

        fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
            match self.node(ino) {
                Ok((_, m)) if m.is_dir => reply.error(libc::EISDIR),
                Ok((path, _)) => {
                    let mut store = self.store();
                    let fh = match store.open_file(&path) {
                        Ok(fh) => fh,
                        Err(e) => return reply.error(errno(&e)),
                    };
                    if flags & libc::O_TRUNC != 0 {
                        if let Err(e) = store.truncate_file(fh, 0) {
                            store.release_file(fh);
                            return reply.error(errno(&e));
                        }
                    }
                    reply.opened(fh, 0)
                }
                Err(e) => reply.error(e),
            }
        }

        fn read(
            &mut self,
            _req: &Request,
            _ino: u64,
            fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock: Option<u64>,
            reply: ReplyData,
        ) {
            // On a worker, under the shared lock: reads of different files (or
            // of one file, ahead of the app) run side by side, and a slow read
            // doesn't hold up the requests queued behind it.
            let store = self.store.clone();
            self.workers.run(move || {
                let result = store
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .read_file(fh, offset.max(0) as u64, size as usize);
                match result {
                    Ok(bytes) => reply.data(&bytes),
                    Err(e) => reply.error(errno(&e)),
                }
            });
        }

        fn write(
            &mut self,
            _req: &Request,
            _ino: u64,
            fh: u64,
            offset: i64,
            data: &[u8],
            _write_flags: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyWrite,
        ) {
            match self.store().write_file(fh, offset.max(0) as u64, data) {
                Ok(()) => reply.written(data.len() as u32),
                Err(e) => reply.error(errno(&e)),
            }
        }

        fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
            let s = self.shared.clone();
            self.workers.run(move || match s.node(ino) {
                Ok((path, m)) if m.is_dir => {
                    // Opening a folder checks it for strays (the drive's own
                    // are taken back in before the listing).
                    if let Err(e) = s.reader().check_folder(&path) {
                        warn(format!("checking {path} for moved-in files failed: {e}"));
                    }
                    reply.opened(0, 0)
                }
                Ok(_) => reply.error(libc::ENOTDIR),
                Err(e) => reply.error(e),
            });
        }

        fn readdir(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            reply: ReplyDirectory,
        ) {
            let s = self.shared.clone();
            self.workers.run(move || s.list(ino, offset, reply));
        }

        fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let result = self.child(parent, name).and_then(|path| {
                let m = self.reader().metadata(&path).map_err(|e| errno(&e))?;
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
                        self.store().remove(&path).map_err(|e| errno(&e))?;
                        self.inodes().remove(&canonical);
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
                    .reader()
                    .metadata(&path)
                    .map_err(|e| errno(&e))?
                    .ok_or(libc::ENOENT)?;
                if !m.is_dir {
                    return Err(libc::ENOTDIR);
                }
                // The engine deletes subtrees; rmdir(2) must only remove empty ones.
                if !self.reader().list_entries(&path).map_err(|e| errno(&e))?.is_empty() {
                    return Err(libc::ENOTEMPTY);
                }
                let canonical = self.canonical(&path);
                self.store().remove(&path).map_err(|e| errno(&e))?;
                self.inodes().remove(&canonical);
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
                    .reader()
                    .metadata(&new)
                    .map_err(|e| errno(&e))?
                    .is_some()
                    && !cloak::names::same(&old_canonical, &self.canonical(&new));
                if flags & RENAME_NOREPLACE != 0 {
                    self.store().rename_path(&old, &new).map_err(|e| errno(&e))?;
                } else {
                    let new_canonical = self.canonical(&new);
                    self.store().rename_replace(&old, &new).map_err(|e| errno(&e))?;
                    if replaced {
                        self.inodes().remove(&new_canonical);
                    }
                }
                let new_canonical = self.canonical(&new);
                self.inodes().rename(&old_canonical, &new_canonical);
                Ok(())
            })();
            match result {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(e),
            }
        }

        /// The drive's size and free space are those of the disk its folder is
        /// on: its files are ordinary files there, and nothing is set aside, so
        /// whatever else is on that disk shares the same free space.
        fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
            let dir = self.reader().backing_dir().to_path_buf();
            // Nominal sizes if the disk can't be asked: Finder refuses to copy
            // onto a volume reporting no free space (fuser's default).
            let (total, free) = disk_space(&dir).unwrap_or((1 << 40, 1 << 39));
            let (total, free) = (total / BLOCK, free / BLOCK);
            reply.statfs(total, free, free, 1 << 20, 1 << 20, BLOCK as u32, 255, BLOCK as u32);
        }

        // Extended attributes aren't stored. Reads answer like a filesystem
        // without any rather than ENOSYS, which makes Finder abort copies with
        // -36; writes are accepted and dropped, since refusing them fails the
        // copy (or sends Finder to ._* files, which are refused too).
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
            reply.ok();
        }

        fn removexattr(&mut self, _req: &Request, _ino: u64, _name: &OsStr, reply: ReplyEmpty) {
            reply.error(NO_XATTR);
        }

        fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
            reply.ok(); // writes go straight to the backing store
        }

        /// fsync(2): make the file's writes durable.
        fn fsync(&mut self, _req: &Request, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
            match self.store().flush_file(fh) {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno(&e)),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn release(
            &mut self,
            _req: &Request,
            _ino: u64,
            fh: u64,
            _flags: i32,
            _lock_owner: Option<u64>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            self.store().release_file(fh);
            reply.ok();
        }

        fn fsyncdir(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
            reply.ok();
        }
    }

    /// Total size and space free to this user, in bytes, of the disk holding
    /// `dir`.
    fn disk_space(dir: &std::path::Path) -> Option<(u64, u64)> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        // SAFETY: statvfs fills the zeroed struct; checked for failure below.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
            return None;
        }
        let unit = s.f_frsize as u64;
        Some((s.f_blocks as u64 * unit, s.f_bavail as u64 * unit))
    }

    /// Print a line, ignoring failure. Started by the desktop app, the adapter
    /// can have nowhere to print, and `println!` would abort the mount over
    /// it.
    fn say(msg: impl std::fmt::Display) {
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), "{msg}");
    }

    /// The same for errors (the desktop app shows these if the mount fails).
    fn warn(msg: impl std::fmt::Display) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{msg}");
    }

    /// Report `msg` and exit.
    fn fail(msg: impl std::fmt::Display) -> ! {
        warn(msg);
        std::process::exit(1)
    }

    pub fn run() {
        let mut args = std::env::args().skip(1);
        let (store_dir, mount_point) = match (args.next(), args.next()) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                warn("usage: cloak-mount <backing-store-dir> <mount-point>");
                std::process::exit(2);
            }
        };

        // Passphrase from the environment keeps it off the command line / argv.
        let passphrase = std::env::var("CLOAK_PASSPHRASE").unwrap_or_else(|_| {
            warn("set CLOAK_PASSPHRASE to the store passphrase");
            std::process::exit(2);
        });
        let store = Store::open_with_passphrase(&store_dir, &passphrase)
            .unwrap_or_else(|e| fail(format!("couldn't open the drive: {e}")));
        let store = Arc::new(RwLock::new(store));
        saver(&store);
        watcher(&store);
        let new_fs = || CloakFs {
            shared: Shared {
                store: store.clone(),
                inodes: Arc::new(Mutex::new(Inodes::default())),
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
            },
            workers: Workers::new(8),
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
                // Keep Finder's ._* / .DS_Store files out of the store (they'd
                // appear as junk files on Windows). Not `noapplexattr`: it
                // refuses com.apple.* attributes with EPERM, which nearly every
                // file carries, so Finder copies failed with "you don't have
                // permission"; setxattr discards them instead.
                MountOption::CUSTOM("noappledouble".into()),
            ]);
        }

        let mounted = match fuser::spawn_mount2(new_fs(), &mount_point, &options) {
            Ok(session) => Mounted::Fuser(session),
            // macFUSE 5.3+ no longer supports the call fuser mounts with
            // (fuser#752); its regular libfuse mount still works.
            #[cfg(target_os = "macos")]
            Err(e) => macfuse::mount(new_fs(), &mount_point, &options).unwrap_or_else(|e2| {
                fail(format!(
                    "couldn't mount at {mount_point} (is macFUSE installed and allowed?): {e}; then {e2}\n\
                     mount options tried: {options:?}"
                ))
            }),
            #[cfg(not(target_os = "macos"))]
            Err(e) => fail(format!(
                "couldn't mount at {mount_point} (is FUSE installed?): {e}\n\
                 mount options tried: {options:?}"
            )),
        };
        say(format!("mounted {store_dir} at {mount_point}; press Enter (or close stdin) to unmount"));

        // Hold the mount until stdin closes, like cloak-winmount: the app locks
        // a drive by closing our stdin. (macFUSE has no auto-unmount on exit, so
        // this explicit unmount is what keeps a lock from leaving a stale mount.)
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        match mounted {
            Mounted::Fuser(session) => drop(session), // unmounts
            #[cfg(target_os = "macos")]
            Mounted::Channel(m) => m.unmount(&mount_point),
        }
        let saved = lock(&store).sync();
        if let Err(e) = saved {
            warn(format!("saving on unmount failed: {e}"));
        }
    }

    /// A live mount, made by whichever route worked.
    enum Mounted {
        Fuser(fuser::BackgroundSession),
        #[cfg(target_os = "macos")]
        Channel(macfuse::Channel),
    }

    /// Mounting through macFUSE's own libfuse calls, for macFUSE 5.3 and
    /// later where fuser's mount call fails without a reason (fuser#752):
    /// `fuse_mount` makes the mount, and fuser serves its device handle.
    #[cfg(target_os = "macos")]
    mod macfuse {
        use super::CloakFs;
        use fuser::{MountOption, Session, SessionACL};
        use libc::{c_char, c_int, c_void};
        use std::ffi::CString;
        use std::io;
        use std::os::fd::{BorrowedFd, OwnedFd};

        #[repr(C)]
        struct FuseArgs {
            argc: c_int,
            argv: *const *const c_char,
            allocated: c_int,
        }

        // libfuse 2, which fuser already links.
        extern "C" {
            fn fuse_mount(mountpoint: *const c_char, args: *mut FuseArgs) -> *mut c_void;
            fn fuse_chan_fd(ch: *mut c_void) -> c_int;
            fn fuse_chan_destroy(ch: *mut c_void);
        }

        /// The mount's libfuse channel, and fuser serving it in the background.
        pub struct Channel {
            ch: *mut c_void,
            _session: fuser::BackgroundSession,
        }

        pub fn mount(fs: CloakFs, mount_point: &str, options: &[MountOption]) -> io::Result<super::Mounted> {
            let opts: Vec<String> = options
                .iter()
                .map(|o| match o {
                    MountOption::FSName(name) => format!("fsname={name}"),
                    MountOption::CUSTOM(o) => o.clone(),
                    other => format!("{other:?}").to_lowercase(),
                })
                .collect();
            let argv_owned = [c"cloak".to_owned(), c"-o".to_owned(), cstr(&opts.join(","))?];
            let argv: Vec<*const c_char> = argv_owned.iter().map(|a| a.as_ptr()).collect();
            let mut args = FuseArgs { argc: argv.len() as c_int, argv: argv.as_ptr(), allocated: 0 };
            let path = cstr(mount_point)?;

            // SAFETY: the strings outlive the call; a null channel is a failure.
            let ch = unsafe { fuse_mount(path.as_ptr(), &mut args) };
            if ch.is_null() {
                return Err(io::Error::other("macFUSE's fuse_mount failed"));
            }
            // The channel keeps its descriptor, so fuser gets its own copy.
            // SAFETY: a live channel's descriptor stays open until it's destroyed.
            let fd = unsafe { fuse_chan_fd(ch) };
            let owned: io::Result<OwnedFd> = if fd < 0 {
                Err(io::Error::other("macFUSE gave no device for the mount"))
            } else {
                unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()
            };
            let session = owned.and_then(|fd| Session::from_fd(fs, fd, SessionACL::Owner).spawn());
            match session {
                Ok(session) => Ok(super::Mounted::Channel(Channel { ch, _session: session })),
                Err(e) => {
                    unmount_path(&path);
                    // SAFETY: the channel is live and released exactly once.
                    unsafe { fuse_chan_destroy(ch) };
                    Err(e)
                }
            }
        }

        impl Channel {
            /// Unmount, which ends fuser's loop, then release the channel.
            pub fn unmount(self, mount_point: &str) {
                if let Ok(path) = cstr(mount_point) {
                    unmount_path(&path);
                }
                // SAFETY: the channel is live and released exactly once.
                unsafe { fuse_chan_destroy(self.ch) };
            }
        }

        fn unmount_path(path: &CString) {
            // SAFETY: a valid C string; failure leaves nothing to clean up here.
            if unsafe { libc::unmount(path.as_ptr(), 0) } != 0 {
                super::warn(format!("unmounting failed: {}", io::Error::last_os_error()));
            }
        }

        fn cstr(s: &str) -> io::Result<CString> {
            CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
        }
    }

    /// The store, even if a thread panicked while holding it: its state is
    /// all on disk or in its own consistent lists, so carrying on is safe.
    fn lock(store: &RwLock<Store>) -> RwLockWriteGuard<'_, Store> {
        store.write().unwrap_or_else(PoisonError::into_inner)
    }

    type Job = Box<dyn FnOnce() + Send>;

    /// A few threads that run jobs handed to them, each answering its own
    /// request (fuser's replies can be sent from any thread).
    struct Workers(mpsc::Sender<Job>);

    impl Workers {
        fn new(threads: usize) -> Workers {
            let (tx, rx) = mpsc::channel::<Job>();
            let rx = Arc::new(Mutex::new(rx));
            for _ in 0..threads {
                let rx = rx.clone();
                std::thread::spawn(move || loop {
                    let job = match rx.lock().unwrap_or_else(PoisonError::into_inner).recv() {
                        Ok(job) => job,
                        Err(_) => return, // unmounted
                    };
                    // A panic fails only its own request (the unsent reply
                    // answers EIO when dropped), never the worker.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                });
            }
            Workers(tx)
        }

        fn run(&self, job: impl FnOnce() + Send + 'static) {
            let _ = self.0.send(Box::new(job));
        }
    }

    /// Check the whole drive for strays once it's mounted, then every minute
    /// (folders that haven't changed are skipped), and tell the app how many
    /// files and folders from other drives are waiting and how many items
    /// have gone missing, as a `{"strays": n, "missing": m}` line, whenever
    /// either changes.
    fn watcher(store: &Arc<RwLock<Store>>) {
        let store = Arc::downgrade(store);
        std::thread::spawn(move || {
            let mut told = None;
            loop {
                let Some(s) = store.upgrade() else { return };
                let store = s.read().unwrap_or_else(PoisonError::into_inner);
                let found = store.sweep().map(|n| (n, store.missing_count()));
                drop(store);
                drop(s);
                match found {
                    Ok((n, m)) if told != Some((n, m)) => {
                        say(serde_json::json!({ "strays": n, "missing": m }));
                        told = Some((n, m));
                    }
                    Ok(_) => {}
                    Err(e) => warn(format!("checking the drive for moved-in files failed: {e}")),
                }
                std::thread::sleep(Duration::from_secs(60));
            }
        });
    }

    /// Save changed directory lists shortly after they change, even when
    /// nothing else is happening on the drive.
    fn saver(store: &Arc<RwLock<Store>>) {
        let store = Arc::downgrade(store);
        std::thread::spawn(move || {
            while let Some(store) = store.upgrade() {
                if let Err(e) = lock(&store).tick() {
                    warn(format!("saving directory lists failed: {e}"));
                }
                drop(store);
                std::thread::sleep(Duration::from_millis(100));
            }
        });
    }
}
