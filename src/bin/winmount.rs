//! Windows live mount via WinFsp.
//!
//! Implements WinFsp's `FileSystemContext` over the `Store`, exposing the full
//! folder tree: directories stay directories, nested paths resolve, and the
//! obfuscation + header/footer crypto are the engine's, unchanged.
//!
//! BUILD REQUIREMENTS:
//!   * WinFsp runtime installed (`winget install WinFsp.WinFsp`).
//!   * The **MSVC** Rust toolchain (`x86_64-pc-windows-msvc`) + Visual Studio
//!     Build Tools + LLVM. The CI Windows job builds this; a standalone local
//!     LLVM may fail to parse the Windows SDK headers (see project history).
//!
//! Usage (the GUI launches this; it also runs by hand):
//!     set CLOAK_PASSPHRASE=...  &  cloak-winmount <backing-store-dir> <X:>
//! The process holds the mount until stdin hits EOF (Enter / closed) or it is
//! terminated. It needs winfsp-x64.dll reachable (WinFsp's bin dir on PATH).

#[cfg(not(all(feature = "winfsp", windows)))]
fn main() {
    eprintln!(
        "cloak-winmount requires --features winfsp on the MSVC toolchain (see this file's docs)."
    );
    std::process::exit(1);
}

#[cfg(all(feature = "winfsp", windows))]
fn main() {
    imp::run();
}

#[cfg(all(feature = "winfsp", windows))]
mod imp {
    use cloak::{names, Metadata, Store};
    use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use widestring::U16CStr;
    use winfsp::filesystem::{
        DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, ModificationDescriptor,
        OpenFileInfo, VolumeInfo, WideNameInfo,
    };
    use winfsp::host::{FileSystemHost, FileSystemParams, VolumeParams};
    use winfsp::{winfsp_init_or_die, FspError, Result as FspResult};
    use winfsp_sys::{FspCleanupDelete, FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FSP_FSCTL_VOLUME_PARAMS};

    const ATTR_DIRECTORY: u32 = 0x10; // FILE_ATTRIBUTE_DIRECTORY
    const ATTR_NORMAL: u32 = 0x80; // FILE_ATTRIBUTE_NORMAL
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001; // create_options bit = "make a directory"

    // Change notifications (what Explorer / Directory Opus watch to refresh live)
    // come from WinFsp's driver itself for every create/rename/delete made through
    // the mount, so the adapter sends none of its own; doing so duplicated every
    // event. The driver needs two things from us for them to be usable: true-case
    // names (`set_normalized_name`) and NUL-free entry names (`wide`).

    /// An open handle, carrying the logical path it refers to. A directory
    /// handle also holds its listing while it is being enumerated.
    enum Handle {
        Root(DirBuffer),
        Dir(String, DirBuffer),
        /// A file: its path, and its id in the store (see `Store::open_file`),
        /// which reads and writes use and which follows renames.
        File(String, u64),
    }

    struct CloakWinFs {
        // WinFsp calls back on many threads with only &self. The Store lives
        // behind a read-write lock: reads, lookups and listings run side by
        // side, changes one at a time. Shared with the thread that saves
        // directory lists (`saver`).
        store: Arc<RwLock<Store>>,
    }

    impl CloakWinFs {
        /// The store, even if an earlier callback panicked while holding it.
        /// WinFsp catches the panic and fails just that request; without this,
        /// the poisoned lock would fail every request after it and the drive
        /// would be dead until remounted. The store's state is all on disk, so
        /// carrying on is safe.
        fn store(&self) -> RwLockWriteGuard<'_, Store> {
            lock(&self.store)
        }

        /// The store for a call that changes nothing (several at once).
        fn reader(&self) -> RwLockReadGuard<'_, Store> {
            self.store.read().unwrap_or_else(PoisonError::into_inner)
        }

        fn meta(&self, path: &str) -> Option<Metadata> {
            self.reader().metadata(path).ok().flatten()
        }

        /// Fill `info` with the current state of open file `id`.
        fn file_info(&self, id: u64, info: &mut FileInfo) -> FspResult<()> {
            let m = self.reader().file_metadata(id).map_err(fsp)?;
            fill_file_info(info, &m);
            Ok(())
        }

        /// Fill `info` with the current state of `path`.
        fn info(&self, path: &str, info: &mut FileInfo) -> FspResult<()> {
            let m = self.meta(path).ok_or_else(not_found)?;
            fill_file_info(info, &m);
            Ok(())
        }

        /// `path` with each component in its stored case, falling back to the
        /// path as given.
        fn canonical(&self, path: &str) -> String {
            self.reader()
                .canonical_path(path)
                .ok()
                .flatten()
                .unwrap_or_else(|| path.to_string())
        }
    }

    // Win32 error codes (winerror.h) for `fsp`.
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_DISK_FULL: u32 = 112;
    const ERROR_INVALID_NAME: u32 = 123;
    const ERROR_DIR_NOT_EMPTY: u32 = 145;
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const ERROR_DIRECTORY: u32 = 267;
    const ERROR_IO_DEVICE: u32 = 1117;

    fn not_found() -> FspError {
        FspError::WIN32(ERROR_FILE_NOT_FOUND)
    }

    /// Map an engine error to a Win32 code. Done explicitly because the winfsp
    /// crate's own `From<io::Error>` panics on any ErrorKind it doesn't list
    /// (DirectoryNotEmpty, StorageFull, InvalidData from a corrupt manifest…).
    fn fsp(e: std::io::Error) -> FspError {
        use std::io::ErrorKind::*;
        if let Some(code) = e.raw_os_error() {
            return FspError::WIN32(code as u32);
        }
        FspError::WIN32(match e.kind() {
            NotFound => ERROR_FILE_NOT_FOUND,
            // Windows reports moving a file onto a directory as access denied.
            PermissionDenied | IsADirectory => ERROR_ACCESS_DENIED,
            AlreadyExists => ERROR_ALREADY_EXISTS,
            InvalidInput => ERROR_INVALID_PARAMETER,
            InvalidFilename => ERROR_INVALID_NAME,
            NotADirectory => ERROR_DIRECTORY,
            DirectoryNotEmpty => ERROR_DIR_NOT_EMPTY,
            StorageFull => ERROR_DISK_FULL,
            _ => ERROR_IO_DEVICE,
        })
    }

    /// Convert a WinFsp path (`\`, `\name`, `\a\b`) to a logical store path
    /// (`""`, `name`, `a/b`), undoing the display mapping of each component.
    fn path_of(file_name: &U16CStr) -> String {
        file_name
            .to_string_lossy()
            .split('\\')
            .filter(|c| !c.is_empty())
            .map(names::from_windows)
            .collect::<Vec<_>>()
            .join("/")
    }

    /// A logical store path as Windows sees it (`a/b` -> `a\b`), with each
    /// component mapped by `names::to_windows`.
    fn windows_path(path: &str) -> String {
        path.split('/').map(names::to_windows).collect::<Vec<_>>().join("\\")
    }

    /// Report the true-case name of an opened/created file. On a case-insensitive
    /// volume WinFsp otherwise keys its file node by an UPPERCASED copy of the
    /// name and uses that in change notifications (`NEW FOLDER` for `New folder`),
    /// which Directory Opus can't match against its listing, so new items never
    /// appear there. `path` is a logical store path in its stored case;
    /// `requested` is the name the caller opened.
    ///
    /// WinFsp rejects a normalized name that differs from the requested one by
    /// more than case (STATUS_OBJECT_NAME_INVALID), so when they differ in length
    /// (an NFD name from a Mac-style app vs the stored NFC) we report nothing and
    /// WinFsp keeps the requested spelling.
    fn set_normalized_name(file_info: &mut OpenFileInfo, path: &str, requested: &U16CStr) {
        let mut name = wide(&windows_path(path));
        name.insert(0, b'\\' as u16);
        if name.len() == requested.len() {
            file_info.set_normalized_name(&name, None);
        }
    }

    /// A name as UTF-16 *without* a trailing NUL, for `set_name_raw`. The crate's
    /// `set_name` appends a NUL and counts it in the entry's name length, so every
    /// listed name and notification became `name\0`: `*` listings still matched,
    /// but exact-name lookups (FindFirstFile on one path, which Directory Opus
    /// does for each notified item) all failed with "file not found".
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// 100 ns ticks between 1601-01-01 (FILETIME's epoch) and 1970-01-01.
    const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

    fn filetime(t: SystemTime) -> u64 {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => FILETIME_UNIX_EPOCH + (d.as_nanos() / 100) as u64,
            Err(e) => FILETIME_UNIX_EPOCH.saturating_sub((e.duration().as_nanos() / 100) as u64),
        }
    }

    /// A FILETIME from SetFileInformationByHandle. 0 means "leave unchanged",
    /// and -1/-2 are the "stop/resume automatic updates" sentinels, which the
    /// disk underneath handles by itself.
    fn systime(ft: u64) -> Option<SystemTime> {
        if ft == 0 || ft >= u64::MAX - 1 {
            return None;
        }
        Some(match ft.checked_sub(FILETIME_UNIX_EPOCH) {
            Some(after) => UNIX_EPOCH + Duration::from_nanos(after.saturating_mul(100)),
            None => UNIX_EPOCH - Duration::from_nanos((FILETIME_UNIX_EPOCH - ft) * 100),
        })
    }

    fn fill_file_info(info: &mut FileInfo, m: &Metadata) {
        let size = if m.is_dir { 0 } else { m.size };
        info.file_attributes = if m.is_dir { ATTR_DIRECTORY } else { ATTR_NORMAL };
        info.file_size = size;
        info.allocation_size = (size + 4095) / 4096 * 4096;
        info.creation_time = filetime(m.created);
        info.last_access_time = filetime(m.accessed);
        info.last_write_time = filetime(m.modified);
        info.change_time = filetime(m.modified);
    }

    impl FileSystemContext for CloakWinFs {
        type FileContext = Handle;

        fn get_security_by_name(
            &self,
            file_name: &U16CStr,
            _security_descriptor: Option<&mut [std::ffi::c_void]>,
            _resolve: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
        ) -> FspResult<FileSecurity> {
            let path = path_of(file_name);
            let attributes = if path.is_empty() {
                ATTR_DIRECTORY
            } else {
                match self.meta(&path) {
                    Some(m) if m.is_dir => ATTR_DIRECTORY,
                    Some(_) => ATTR_NORMAL,
                    None => return Err(not_found()),
                }
            };
            Ok(FileSecurity {
                reparse: false,
                sz_security_descriptor: 0,
                attributes,
            })
        }

        fn open(
            &self,
            file_name: &U16CStr,
            _create_options: u32,
            _granted_access: FILE_ACCESS_RIGHTS,
            file_info: &mut OpenFileInfo,
        ) -> FspResult<Self::FileContext> {
            let path = path_of(file_name);
            let m = self.meta(&path).ok_or_else(not_found)?;
            fill_file_info(file_info.as_mut(), &m);
            if path.is_empty() {
                return Ok(Handle::Root(DirBuffer::new()));
            }
            let path = self.canonical(&path);
            set_normalized_name(file_info, &path, file_name);
            if m.is_dir {
                return Ok(Handle::Dir(path, DirBuffer::new()));
            }
            let id = self.store().open_file(&path).map_err(fsp)?;
            Ok(Handle::File(path, id))
        }

        fn close(&self, context: Self::FileContext) {
            if let Handle::File(_, id) = context {
                self.store().release_file(id);
            }
        }

        fn get_file_info(
            &self,
            context: &Self::FileContext,
            file_info: &mut FileInfo,
        ) -> FspResult<()> {
            match context {
                Handle::Root(_) => self.info("", file_info),
                Handle::Dir(path, _) => self.info(path, file_info),
                Handle::File(_, id) => self.file_info(*id, file_info),
            }
        }

        // The next three are accepted as no-ops rather than left at the crate's
        // default (STATUS_INVALID_DEVICE_REQUEST, "Incorrect function"), which
        // broke ReplaceFile, FlushFileBuffers (Office, SQLite, most editors) and
        // copies that preserve dates/attributes. Writes reach disk immediately,
        // and the store keeps no attributes or ACLs to update (times go to the
        // boring file on disk).

        fn flush(
            &self,
            context: Option<&Self::FileContext>,
            file_info: &mut FileInfo,
        ) -> FspResult<()> {
            match context {
                Some(c) => {
                    // FlushFileBuffers: make the file's writes durable.
                    if let Handle::File(_, id) = c {
                        self.store().flush_file(*id).map_err(fsp)?;
                    }
                    self.get_file_info(c, file_info)
                }
                // The whole volume: save every pending change.
                None => self.store().sync().map_err(fsp),
            }
        }

        fn set_basic_info(
            &self,
            context: &Self::FileContext,
            _file_attributes: u32,
            creation_time: u64,
            last_access_time: u64,
            last_write_time: u64,
            _last_change_time: u64,
            file_info: &mut FileInfo,
        ) -> FspResult<()> {
            let (accessed, modified, created) =
                (systime(last_access_time), systime(last_write_time), systime(creation_time));
            if accessed.is_some() || modified.is_some() || created.is_some() {
                let store = self.reader();
                match context {
                    Handle::Root(_) => store.set_times("", accessed, modified, created),
                    Handle::Dir(p, _) => store.set_times(p, accessed, modified, created),
                    Handle::File(_, id) => store.set_file_times(*id, accessed, modified, created),
                }
                .map_err(fsp)?;
            }
            self.get_file_info(context, file_info)
        }

        fn set_security(
            &self,
            _context: &Self::FileContext,
            _security_information: u32,
            _modification_descriptor: ModificationDescriptor,
        ) -> FspResult<()> {
            Ok(())
        }

        fn read(
            &self,
            context: &Self::FileContext,
            buffer: &mut [u8],
            offset: u64,
        ) -> FspResult<u32> {
            let Handle::File(_, id) = context else {
                return Err(not_found());
            };
            let data = self.reader().read_file(*id, offset, buffer.len()).map_err(fsp)?;
            buffer[..data.len()].copy_from_slice(&data);
            Ok(data.len() as u32)
        }

        fn read_directory(
            &self,
            context: &Self::FileContext,
            _pattern: Option<&U16CStr>,
            marker: DirMarker,
            buffer: &mut [u8],
        ) -> FspResult<u32> {
            let (dir, listing) = match context {
                Handle::Root(b) => (String::new(), b),
                Handle::Dir(p, b) => (p.clone(), b),
                Handle::File(..) => return Err(not_found()),
            };
            // The whole listing is built when an enumeration starts (no marker)
            // and later pages are served from it, so a big folder is read
            // once per listing rather than once per page. A new enumeration
            // always rebuilds it, so file managers see changes immediately.
            if let Ok(lock) = listing.acquire(marker.is_none(), None) {
                let (this, children) = {
                    let store = self.reader();
                    let this = store.metadata(&dir).ok().flatten().ok_or_else(not_found)?;
                    (this, store.list_dir_meta(&dir).unwrap_or_default())
                };
                let mut dir_info = DirInfo::<255>::new();
                let dots = [(".".to_string(), this), ("..".to_string(), this)];
                let entries = children.into_iter().map(|(name, m)| (names::to_windows(&name), m));
                for (name, m) in dots.into_iter().chain(entries) {
                    dir_info.reset();
                    // A legacy name too long for Windows (over 255 UTF-16 units)
                    // is skipped rather than failing the whole listing.
                    if dir_info.set_name_raw(wide(&name).as_slice()).is_err() {
                        continue;
                    }
                    fill_file_info(dir_info.file_info_mut(), &m);
                    lock.write(&mut dir_info)?;
                }
            }
            Ok(listing.read(marker, buffer))
        }

        /// Exact-name lookup within a directory (FindFirstFile("X:\dir\name")).
        /// Directory Opus issues one for every item a change notification
        /// announces; if it fails, Opus drops the new item until a manual refresh.
        /// Answering it directly avoids listing the whole directory per lookup.
        fn get_dir_info_by_name(
            &self,
            context: &Self::FileContext,
            file_name: &U16CStr,
            out_dir_info: &mut DirInfo,
        ) -> FspResult<()> {
            let dir = match context {
                Handle::Root(_) => String::new(),
                Handle::Dir(p, _) => p.clone(),
                Handle::File(..) => return Err(not_found()),
            };
            let name = names::from_windows(&file_name.to_string_lossy());
            let path = if dir.is_empty() { name } else { format!("{dir}/{name}") };
            let m = self.meta(&path).ok_or_else(not_found)?;
            let canonical = self.canonical(&path);
            let real = canonical.rsplit('/').next().unwrap_or(&canonical);
            out_dir_info.reset();
            out_dir_info.set_name_raw(wide(&names::to_windows(real)).as_slice())?;
            fill_file_info(out_dir_info.file_info_mut(), &m);
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        fn create(
            &self,
            file_name: &U16CStr,
            create_options: u32,
            _granted_access: FILE_ACCESS_RIGHTS,
            _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
            _security_descriptor: Option<&[std::ffi::c_void]>,
            _allocation_size: u64,
            _extra_buffer: Option<&[u8]>,
            _extra_is_reparse: bool,
            file_info: &mut OpenFileInfo,
        ) -> FspResult<Self::FileContext> {
            let path = path_of(file_name);
            if path.is_empty() {
                return Err(FspError::WIN32(ERROR_INVALID_PARAMETER));
            }
            let mut store = self.store();
            if create_options & FILE_DIRECTORY_FILE != 0 {
                store.mkdir(&path).map_err(fsp)?;
                drop(store);
                let path = self.canonical(&path);
                set_normalized_name(file_info, &path, file_name);
                self.info(&path, file_info.as_mut())?;
                Ok(Handle::Dir(path, DirBuffer::new()))
            } else {
                store.create(&path).map_err(fsp)?;
                drop(store);
                let path = self.canonical(&path);
                set_normalized_name(file_info, &path, file_name);
                let id = self.store().open_file(&path).map_err(fsp)?;
                self.file_info(id, file_info.as_mut())?;
                Ok(Handle::File(path, id))
            }
        }

        fn write(
            &self,
            context: &Self::FileContext,
            buffer: &[u8],
            offset: u64,
            write_to_eof: bool,
            constrained_io: bool,
            file_info: &mut FileInfo,
        ) -> FspResult<u32> {
            let Handle::File(_, id) = context else {
                return Err(not_found());
            };
            let id = *id;
            let mut store = self.store();
            let size = || store.file_metadata(id).map_or(0, |m| m.size);
            let mut buffer = buffer;
            let at = if constrained_io {
                // Windows' cache writing back whole pages: these must never
                // grow the file, so the part past the end is dropped.
                let size = size();
                if offset >= size {
                    return Ok(0);
                }
                buffer = &buffer[..buffer.len().min((size - offset) as usize)];
                offset
            } else if write_to_eof {
                size()
            } else {
                offset
            };
            store.write_file(id, at, buffer).map_err(fsp)?;
            drop(store);
            self.file_info(id, file_info)?;
            Ok(buffer.len() as u32)
        }

        fn set_file_size(
            &self,
            context: &Self::FileContext,
            new_size: u64,
            set_allocation_size: bool,
            file_info: &mut FileInfo,
        ) -> FspResult<()> {
            let Handle::File(_, id) = context else {
                return Err(not_found());
            };
            let id = *id;
            let mut store = self.store();
            // An allocation size is disk space reserved (rounded up to whole
            // sectors), not the file's length: it only matters if it's less
            // than the length, which then shrinks to fit.
            let size = store.file_metadata(id).map_or(0, |m| m.size);
            if !set_allocation_size || new_size < size {
                store.truncate_file(id, new_size).map_err(fsp)?;
            }
            drop(store);
            self.file_info(id, file_info)
        }

        fn overwrite(
            &self,
            context: &Self::FileContext,
            _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
            _replace_file_attributes: bool,
            _allocation_size: u64,
            _extra_buffer: Option<&[u8]>,
            file_info: &mut FileInfo,
        ) -> FspResult<()> {
            let Handle::File(_, id) = context else {
                return Err(not_found());
            };
            self.store().truncate_file(*id, 0).map_err(fsp)?;
            self.file_info(*id, file_info)
        }

        fn rename(
            &self,
            _context: &Self::FileContext,
            file_name: &U16CStr,
            new_file_name: &U16CStr,
            replace_if_exists: bool,
        ) -> FspResult<()> {
            let old = path_of(file_name);
            let new = path_of(new_file_name);
            let mut store = self.store();
            // MoveFileEx(REPLACE_EXISTING) is how many editors save (write a
            // temp file, rename it over the original).
            if replace_if_exists {
                store.rename_replace(&old, &new).map_err(fsp)
            } else {
                store.rename_path(&old, &new).map_err(fsp)
            }
        }

        fn set_delete(
            &self,
            context: &Self::FileContext,
            _file_name: &U16CStr,
            delete_file: bool,
        ) -> FspResult<()> {
            match context {
                Handle::Root(_) => Err(FspError::WIN32(ERROR_ACCESS_DENIED)),
                // Like NTFS, a directory can only be deleted once it's empty;
                // otherwise `rd folder` (no /s) would wipe the whole subtree.
                Handle::Dir(p, _) if delete_file => {
                    let empty = self.reader()
                        .list_entries(p)
                        .map(|c| c.is_empty())
                        .unwrap_or(true);
                    if empty {
                        Ok(())
                    } else {
                        Err(FspError::WIN32(ERROR_DIR_NOT_EMPTY))
                    }
                }
                _ => Ok(()),
            }
        }

        fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
            if flags & (FspCleanupDelete as u32) != 0 {
                if let Handle::File(p, _) | Handle::Dir(p, _) = context {
                    let _ = self.store().remove(p);
                }
            }
        }

        fn get_volume_info(&self, out: &mut VolumeInfo) -> FspResult<()> {
            out.total_size = 1 << 40; // 1 TiB nominal
            out.free_size = 1 << 39; // 512 GiB nominal
            out.set_volume_label("cloak");
            Ok(())
        }
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
                warn("usage: cloak-winmount <backing-store-dir> <mount-point e.g. X:>");
                std::process::exit(2);
            }
        };
        let passphrase = std::env::var("CLOAK_PASSPHRASE").unwrap_or_else(|_| {
            warn("set CLOAK_PASSPHRASE to the store passphrase");
            std::process::exit(2);
        });

        let _init = winfsp_init_or_die();
        let store = Store::open_with_passphrase(&store_dir, &passphrase)
            .unwrap_or_else(|e| fail(format!("couldn't open the drive: {e}")));

        let mut params = VolumeParams::new();
        params
            .filesystem_name("cloak")
            .case_preserved_names(true)
            .case_sensitive_search(false)
            .unicode_on_disk(true)
            .persistent_acls(false)
            // Let Windows cache file data and file details: reads get its
            // read-ahead and small writes are gathered, instead of every 4 KiB
            // going through us. Every change goes through this volume, so the
            // cache stays correct.
            .file_info_timeout(u32::MAX)
            // ...but hand a file's cached writes to us as soon as the app
            // closes it, so closed files are on the backing store like before
            // (an unmount or a crash can't lose data the app has finished
            // writing and closed).
            .flush_and_purge_on_cleanup(true)
            // Route exact-name directory queries to get_dir_info_by_name.
            .pass_query_directory_filename(true);
        // But never cache directory listings: file managers (Explorer,
        // Directory Opus) must see created/renamed/deleted entries immediately
        // on re-enumeration. A cached listing shows new folders late
        // (Explorer) or not at all (Opus). winfsp-rs has no setter for the
        // "valid" flag that makes the separate listing timeout apply.
        {
            // SAFETY: VolumeParams is a #[repr(transparent)] wrapper around
            // FSP_FSCTL_VOLUME_PARAMS.
            let raw = unsafe { &mut *(&mut params as *mut VolumeParams).cast::<FSP_FSCTL_VOLUME_PARAMS>() };
            raw.set_DirInfoTimeoutValid(1);
            raw.DirInfoTimeout = 0;
        }

        let store = Arc::new(RwLock::new(store));
        saver(&store);
        let context = CloakWinFs {
            store: store.clone(),
        };
        let mut fs_params = FileSystemParams::default_params(params);
        fs_params.use_dir_info_by_name = true;
        let mut host =
            FileSystemHost::new_with_options(fs_params, context)
                .unwrap_or_else(|e| fail(format!("couldn't start the file system (is WinFsp installed?): {e:?}")));
        if let Err(e) = host.mount(mount_point.as_str()) {
            fail(format!("couldn't mount at {mount_point} (is it free?): {e:?}"));
        }
        if let Err(e) = host.start() {
            fail(format!("couldn't start the file system: {e:?}"));
        }
        say(format!("mounted {store_dir} at {mount_point}; press Enter (or terminate) to unmount"));

        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);

        host.stop();
        host.unmount();
        let saved = lock(&store).sync();
        if let Err(e) = saved {
            warn(format!("saving on unmount failed: {e}"));
        }
    }

    /// The store, even if a thread panicked while holding it (see
    /// `CloakWinFs::store`).
    fn lock(store: &RwLock<Store>) -> RwLockWriteGuard<'_, Store> {
        store.write().unwrap_or_else(PoisonError::into_inner)
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
