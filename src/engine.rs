//! The storage engine: a path-addressed tree store (Approach A).
//!
//! The backing store mirrors the logical directory tree using boring-named
//! directories, and each directory carries its own encrypted manifest (see
//! [`crate::manifest`]). A logical path like `Documents/Taxes/Return.pdf` is
//! resolved by walking manifests from the root, descending into each child's
//! boring on-disk directory, until the final component.
//!
//! A file's ends are encrypted with its own key (see `docs/FORMAT.md`), and
//! every file ends with an envelope describing it, so a file found in a
//! folder whose list doesn't name it can be recognized and taken back in
//! ([`Store::check_folder`]). Directories hold no blob; their real names live
//! in the parent's list and in their own.
//!
//! All operations are plain file I/O, so the engine runs and is fully tested
//! without any FUSE/WinFsp driver.

use crate::boring::{generate_unique, Contains};
use crate::crypto::{self, protected_ranges, transform_region, Key, Nonce};
use crate::dircache::{read_listing, write_listing, Dir, DirCache};
use crate::durable;
use crate::envelope::{self, Envelope, LEN as ENVELOPE};
use crate::lock::{self, Keys};
use crate::manifest::{self, Child};
use crate::names;
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The drive format this engine reads and writes (see `docs/FORMAT.md`).
pub const FORMAT: u32 = 3;

const JOURNAL_LABEL: &[u8] = b"cloak-journal-v3";

/// The keys of the drive in `dir`, with its password, from the lock any of
/// its files or folders carries (see [`crate::lock`]). `NotFound` ("no drive
/// here") if nothing in the folder carries one, `PermissionDenied` for a
/// wrong password (or one replaced by a password change).
pub fn unlock(dir: &Path, password: &str) -> io::Result<Keys> {
    match crate::lock::unlock_drive(dir, password) {
        Err(e) if e.kind() == io::ErrorKind::NotFound && dir.join("meta.json").exists() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "this drive was made by an earlier test version of cloak, which this version can't open",
        )),
        r => r,
    }
}

/// Change a drive's password: every file's envelope and every folder's list
/// gets the master key locked with `new` (its data is untouched). The top
/// folder's list goes first, so from then on only `new` opens the drive; if
/// the change is interrupted, opening with `new` finishes it.
pub fn change_password(dir: &Path, old: &str, new: &str, progress: &mut dyn FnMut(u64, u64)) -> io::Result<()> {
    if new.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the new password is empty"));
    }
    let keys = unlock(dir, old)?.relocked(new)?;
    let mut store = Store::open_with_keys(dir, keys)?;
    store.relock(progress)
}

/// What a path points at. The times are those of its boring file or directory
/// on disk: the store records none of its own, and the disk already shows them
/// to anyone looking at the backing folder, so passing them through reveals
/// nothing new.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub is_dir: bool,
    pub size: u64,
    pub accessed: SystemTime,
    pub modified: SystemTime,
    pub created: SystemTime,
}

/// One entry of a directory listing. Its metadata comes from the disk, so
/// it's read only when asked for: a file manager pages through a big folder
/// a screenful at a time.
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    size_hint: u64,
    disk: PathBuf,
}

impl DirEntry {
    pub fn metadata(&self) -> Metadata {
        Metadata::new(self.is_dir, self.size_hint, &self.disk)
    }
}

impl Metadata {
    /// `size` is the manifest's hint, used only if the disk can't be read; a
    /// file's real size is its boring file's length.
    fn new(is_dir: bool, size: u64, disk: &Path) -> Self {
        Self::from_disk(is_dir, size, std::fs::metadata(disk).ok().as_ref())
    }

    /// From the boring entry's metadata as read from the disk, if it could be.
    fn from_disk(is_dir: bool, size: u64, disk: Option<&std::fs::Metadata>) -> Self {
        let (size, accessed, modified, created) = match disk {
            Some(d) => {
                let modified = d.modified().unwrap_or(UNIX_EPOCH);
                (
                    // A file's real length is its length on disk less its envelope.
                    if is_dir { 0 } else { d.len().saturating_sub(ENVELOPE) },
                    d.accessed().unwrap_or(modified),
                    modified,
                    // Not every filesystem records a birth time (some Linux ones).
                    d.created().unwrap_or(modified),
                )
            }
            None => (size, UNIX_EPOCH, UNIX_EPOCH, UNIX_EPOCH),
        };
        Self { is_dir, size, accessed, modified, created }
    }
}

/// Set a boring file's or folder's times; `None` leaves that time alone.
fn set_disk_times(
    disk: &Path,
    accessed: Option<SystemTime>,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
) -> io::Result<()> {
    let mut times = std::fs::FileTimes::new();
    if let Some(t) = accessed {
        times = times.set_accessed(t);
    }
    if let Some(t) = modified {
        times = times.set_modified(t);
    }
    if let Some(t) = created {
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileTimesExt;
            times = times.set_created(t);
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::macos::fs::FileTimesExt;
            times = times.set_created(t);
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        let _ = t;
    }
    open_for_times(disk)?.set_times(times)
}

/// Open a boring file or directory just to change its times.
fn open_for_times(disk: &Path) -> io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        // Needed to open a directory at all.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(disk)
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(disk)
    }
}

pub struct Store {
    backing_dir: PathBuf,
    /// The drive's master key (`keys.master`), kept at hand.
    key: Key,
    /// The drive's keys: what new envelopes and lists are locked with.
    keys: Keys,
    region: u64,
    /// For each file written since it was last flushed: its length at that
    /// flush. Bytes below it were on disk before; bytes above are new and, like
    /// any unflushed write, may be lost in a crash. See `update_blob`.
    durable_len: HashMap<PathBuf, u64>,
    /// Open handles on files being written, kept until the app closes the
    /// file. Opening and closing per write is very slow on Windows (a freshly
    /// written file is rescanned on every close), so this is what makes
    /// writes run at disk speed.
    handles: HashMap<PathBuf, std::fs::File>,
    /// The same for files being read. Reads take `&self` and may run on
    /// several threads at once, hence the lock (held only to find a handle).
    readers: Mutex<HashMap<PathBuf, Arc<std::fs::File>>>,
    /// Files opened through a mount adapter, by the id handed out for each
    /// open, so reads and writes go straight to the boring file without
    /// resolving the path again.
    open: HashMap<u64, Opened>,
    next_id: u64,
    /// Directory lists, checked against the disk on every use and saved a
    /// moment after they change (see [`crate::dircache`] and [`Store::sync`]).
    dirs: DirCache,
    /// Boring files and folders removed from their lists but not yet from
    /// the disk: they go once the lists are saved (see [`Store::sync`]).
    doomed: Vec<(PathBuf, String)>,
    /// Envelopes of files being written, so a resize can put it back at the
    /// new end without reading it again.
    envelopes: HashMap<PathBuf, [u8; ENVELOPE as usize]>,
    /// Files that already have a fresh nonce for the editing session under
    /// way (until their last close).
    renonced: HashSet<PathBuf>,
    /// Open files already made sparse for a jump in size (see `update_blob`).
    sparse: HashSet<PathBuf>,
    /// New files still empty, whose envelope (in `envelopes`) isn't on disk
    /// yet: it's written with their first data, or by `write_unwritten`.
    unwritten: HashSet<PathBuf>,
    /// Files and folders found in each folder that belong to another drive
    /// (see [`Store::check_folder`]).
    foreign: Mutex<HashMap<PathBuf, BTreeSet<String>>>,
    /// Items found gone from the disk, kept (sealed, in `missing.idx`) until
    /// they come back or are dismissed.
    missing: Mutex<Vec<Missing>>,
    /// Items taken back in from elsewhere in the drive since the last full
    /// check (file ID, boring name): their old entry's disappearance, found
    /// later in another folder, is a move, not a loss.
    arrived: Mutex<Vec<(crate::envelope::FileId, String)>>,
    /// Folders whose unreadable list was set aside and rebuilt.
    repaired: Mutex<Vec<PathBuf>>,
    /// Each folder's modified time when last checked for strays.
    checked: Mutex<HashMap<PathBuf, SystemTime>>,
}

/// A file's key and its current content nonce.
type Crypt = (Key, Nonce);

/// The drive's record of items that went missing (sealed, at the top).
const MISSING_LABEL: &[u8] = b"cloak-missing-v3";

/// Something listed in the drive whose file or folder was found gone from
/// the disk (moved out or deleted outside cloak). See [`Store::missing`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Missing {
    /// Where it was in the drive, real names, `/`-separated.
    pub path: String,
    pub is_dir: bool,
    /// When it was found gone, in seconds since 1970.
    pub since: u64,
    /// A file's ID (to clear the record if it comes back).
    #[serde(skip)]
    id: crate::envelope::FileId,
    /// Its boring name (how a folder is recognized if it comes back).
    boring: String,
}

/// Something from another drive waiting in this one (see
/// [`Store::preview_from`]).
#[derive(Debug, Clone, Serialize)]
pub struct Found {
    /// Where it would appear in this drive, real names, `/`-separated.
    pub path: String,
    /// Its own real name.
    pub name: String,
    pub is_dir: bool,
    /// For a folder: how many items it holds directly.
    pub items: usize,
}

/// A file opened with [`Store::open_file`].
struct Opened {
    blob: PathBuf,
    crypt: Crypt,
}

/// How long a changed directory list may wait before it is saved.
pub const SAVE_DELAY: Duration = Duration::from_millis(500);

/// Boring names not to hand out in a directory: those in its list, and any
/// file or folder already there (one waiting to be deleted, or left by a
/// crash).
struct Taken<'a> {
    dir: &'a Dir,
    at: &'a Path,
}

impl Contains for Taken<'_> {
    fn contains(&self, name: &str) -> bool {
        name.starts_with("manifest") || self.dir.has_boring(name) || self.at.join(name).exists()
    }
}

/// Handles kept open at most; past this they're all dropped and reopened as
/// needed (correctness never depends on one being cached).
const MAX_HANDLES: usize = 128;

/// Name of the journal at the backing root (never a boring name: those always
/// contain `_`).
const JOURNAL: &str = "journal.idx";

/// A multi-step change, written (encrypted) before it starts and deleted once
/// it is done, so a crash part-way is finished or undone on the next open.
/// Paths are relative to the backing root, `/`-separated.
#[derive(Serialize, Deserialize)]
enum Journal {
    /// Delete each `(dir, boring)` file or folder that `dir`'s list no longer
    /// names (written while saving lists that dropped them).
    Purge { items: Vec<(String, String)> },
    /// Move entry `from_boring` in `from_dir` to `child` (its new boring and
    /// real name) in `to_dir`, deleting `replaced` there first. Covers
    /// renames within a directory too (`from_dir == to_dir`).
    Move {
        from_dir: String,
        from_boring: String,
        to_dir: String,
        child: Child,
        replaced: Option<String>,
    },
    /// Original bytes of a file whose encrypted end is being moved; restoring
    /// them and the length rolls the file back to before the write.
    Undo { blob: String, len: u64, ranges: Vec<(u64, Vec<u8>)> },
    /// A file's ends being re-encrypted under `nonce`: done once its list
    /// entry has that nonce, otherwise undone with the original bytes.
    Renonce { dir: String, boring: String, nonce: Nonce, len: u64, ranges: Vec<(u64, Vec<u8>)> },
}

/// Split a logical path into non-empty components, each in NFC. Only `/`
/// separates: `\` is an ordinary character in a macOS name (the Windows adapter
/// converts its own `\` separators before calling in).
fn components(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(names::normalize)
        .collect()
}

/// Split into (parent components, final name). Errors on an empty path.
fn parent_and_name(path: &str) -> io::Result<(Vec<String>, String)> {
    let mut comps = components(path);
    let name = comps
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty path"))?;
    Ok((comps, name))
}

fn not_found() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no such path")
}

impl Store {
    /// Open (or create) a store with a raw master key and no password (its
    /// files' locks then open with nothing but that key): for tests.
    pub fn open(backing_dir: impl AsRef<Path>, key: Key, region: u64) -> io::Result<Self> {
        Self::open_with_keys(backing_dir, Keys::bare(key, region))
    }

    /// Open (or create) a store with its keys.
    pub fn open_with_keys(backing_dir: impl AsRef<Path>, keys: Keys) -> io::Result<Self> {
        let backing_dir = backing_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&backing_dir)?;
        let store = Self {
            backing_dir,
            key: keys.master,
            region: keys.region,
            keys,
            durable_len: HashMap::new(),
            handles: HashMap::new(),
            readers: Default::default(),
            open: HashMap::new(),
            next_id: 1,
            dirs: DirCache::default(),
            doomed: Vec::new(),
            envelopes: HashMap::new(),
            renonced: HashSet::new(),
            sparse: HashSet::new(),
            unwritten: HashSet::new(),
            foreign: Mutex::default(),
            missing: Mutex::default(),
            arrived: Mutex::default(),
            repaired: Mutex::default(),
            checked: Mutex::default(),
        };
        store.recover()?;
        *lock(&store.missing) = store.load_missing();
        store.merge_all_conflicts()?;
        Ok(store)
    }

    /// Create a brand-new drive protected by `passphrase` in `backing_dir`,
    /// which must be empty (so Create never clobbers anything). The drive is
    /// its top folder's list: it carries the locked master key.
    pub fn create_with_passphrase(
        backing_dir: impl AsRef<Path>,
        passphrase: &str,
        region: u64,
    ) -> io::Result<Self> {
        let backing_dir = backing_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&backing_dir)?;
        if std::fs::read_dir(&backing_dir)?.next().is_some() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "that folder isn't empty"));
        }
        let keys = Keys::new(passphrase, region)?;
        write_listing(&backing_dir, &keys, None, &[], 0, &mut Vec::new(), None)?;
        Self::open_with_keys(backing_dir, keys)
    }

    /// Open an existing drive. Errors if there is no drive at `backing_dir`
    /// ("no drive here"), or if the passphrase is wrong ("wrong password").
    /// Finishes a password change that was interrupted.
    pub fn open_with_passphrase(
        backing_dir: impl AsRef<Path>,
        passphrase: &str,
    ) -> io::Result<Self> {
        let backing_dir = backing_dir.as_ref().to_path_buf();
        if crate::convert::in_progress(&backing_dir) {
            return Err(io::Error::other(
                "this folder is part-way through being converted; finish converting it first",
            ));
        }
        let keys = unlock(&backing_dir, passphrase)?;
        let mut store = Self::open_with_keys(backing_dir, keys)?;
        if store.relock_marker().exists() {
            store.relock(&mut |_, _| {})?;
        }
        Ok(store)
    }

    /// Where a password change under way is marked (a name the drive works
    /// out from its key, like its lists).
    fn relock_marker(&self) -> PathBuf {
        self.backing_dir.join(format!("{}.new", lock::names(&self.key).missing))
    }

    /// Put this store's lock (its keys, after a password change) on every
    /// list and envelope in the drive. The top list goes first; the rest
    /// follow, marked as under way so a stopped change is finished on the
    /// next open.
    fn relock(&mut self, progress: &mut dyn FnMut(u64, u64)) -> io::Result<()> {
        self.sync()?;
        durable::write_synced(&self.relock_marker(), b"")?;
        let mut folders = vec![self.backing_dir.clone()];
        let mut files = Vec::new();
        let mut lists = Vec::new();
        while let Some(folder) = folders.pop() {
            lists.push(folder.clone());
            let dir = self.dir(&folder)?;
            for c in dir.children() {
                let p = folder.join(&c.boring);
                if c.is_dir() {
                    folders.push(p);
                } else {
                    files.push(p);
                }
            }
        }
        let total = (lists.len() + files.len()) as u64;
        let mut done = 0;
        for folder in &lists {
            // Rewritten whole (one file), with the new lock.
            let l = read_listing(folder, &self.keys)?;
            write_listing(folder, &self.keys, l.name.as_deref(), &l.children, 0, &mut Vec::new(), None)?;
            for i in 0..l.parts {
                let _ = std::fs::remove_file(folder.join(manifest::part_name(&self.keys, i)));
            }
            self.dirs.forget(folder);
            done += 1;
            progress(done, total);
        }
        for file in &files {
            // A file's lock is the first part of its envelope: only those bytes
            // change. A torn write there leaves the rest of the envelope, and
            // the file's entry in its list, as they were.
            if let Ok(f) = std::fs::OpenOptions::new().read(true).write(true).open(file) {
                let len = f.metadata()?.len();
                if len >= ENVELOPE && Envelope::open(&self.key, &envelope::read_tail(file)?).is_ok() {
                    write_all_at(&f, &self.keys.lock(), len - ENVELOPE)?;
                }
            }
            done += 1;
            progress(done, total);
        }
        self.envelopes.clear();
        std::fs::remove_file(self.relock_marker())?;
        durable::sync_dir(&self.backing_dir)
    }

    /// The folder the drive lives in.
    pub fn backing_dir(&self) -> &Path {
        &self.backing_dir
    }

    // ---- path resolution -------------------------------------------------

    /// Resolve a sequence of directory components to their on-disk path.
    fn resolve_dir(&self, comps: &[String]) -> io::Result<PathBuf> {
        let mut cur = self.backing_dir.clone();
        for name in comps {
            let manifest = self.dir(&cur)?;
            let child = manifest
                .find(name)
                .filter(|c| c.is_dir())
                .ok_or_else(not_found)?;
            cur = cur.join(&child.boring);
        }
        Ok(cur)
    }

    // ---- queries ---------------------------------------------------------

    /// Metadata for a path. The root (`""`/`"/"`) is a directory.
    pub fn metadata(&self, path: &str) -> io::Result<Option<Metadata>> {
        let comps = components(path);
        if comps.is_empty() {
            return Ok(Some(Metadata::new(true, 0, &self.backing_dir)));
        }
        let (parent, name) = (comps[..comps.len() - 1].to_vec(), comps[comps.len() - 1].clone());
        let parent_disk = match self.resolve_dir(&parent) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let manifest = self.dir(&parent_disk)?;
        Ok(manifest.find(&name).map(|c| self.disk_metadata(c.is_dir(), c.size, &parent_disk.join(&c.boring))))
    }

    /// Metadata of a boring entry, from the handle it's being written
    /// through if there is one: that's cheaper than looking it up by path
    /// (Windows writes a cached file back in many small pieces, each asking
    /// for the size), and NTFS updates the by-path copy of an open file's size
    /// and dates only lazily.
    fn disk_metadata(&self, is_dir: bool, size_hint: u64, blob: &Path) -> Metadata {
        match self.handles.get(blob).and_then(|f| f.metadata().ok()) {
            Some(m) => Metadata::from_disk(is_dir, size_hint, Some(&m)),
            None => Metadata::new(is_dir, size_hint, blob),
        }
    }

    /// The boring file or directory behind a path (the backing root for `""`).
    fn disk_path(&self, path: &str) -> io::Result<PathBuf> {
        let comps = components(path);
        let Some((name, parent)) = comps.split_last() else {
            return Ok(self.backing_dir.clone());
        };
        let parent_disk = self.resolve_dir(parent)?;
        let manifest = self.dir(&parent_disk)?;
        let child = manifest.find(name).ok_or_else(not_found)?;
        Ok(parent_disk.join(&child.boring))
    }

    /// Set a path's times; `None` leaves that time as it is. The creation time
    /// can be set on Windows and macOS only and is ignored elsewhere.
    pub fn set_times(
        &self,
        path: &str,
        accessed: Option<SystemTime>,
        modified: Option<SystemTime>,
        created: Option<SystemTime>,
    ) -> io::Result<()> {
        set_disk_times(&self.disk_path(path)?, accessed, modified, created)
    }

    /// [`set_times`](Self::set_times) for an open file.
    pub fn set_file_times(
        &self,
        id: u64,
        accessed: Option<SystemTime>,
        modified: Option<SystemTime>,
        created: Option<SystemTime>,
    ) -> io::Result<()> {
        let (blob, _) = self.opened(id)?;
        set_disk_times(&blob, accessed, modified, created)
    }


    /// List a directory without reading anything else from the disk.
    pub fn list_entries(&self, path: &str) -> io::Result<Vec<DirEntry>> {
        let disk = self.resolve_dir(&components(path))?;
        let manifest = self.dir(&disk)?;
        Ok(manifest
            .children()
            .iter()
            .map(|c| DirEntry {
                name: c.real.clone(),
                is_dir: c.is_dir(),
                size_hint: c.size,
                disk: disk.join(&c.boring),
            })
            .collect())
    }

    /// List a directory with each child's metadata.
    ///
    /// The boring entries' sizes and dates come from one scan of the backing
    /// folder (on Windows the scan returns them, with no call per file), so a
    /// big folder lists about as fast as the disk lists it. A file this store
    /// is writing is read from its open handle instead, since NTFS only
    /// updates a folder's copy of an open file's size and dates lazily.
    ///
    /// The same scan is checked against the folder's list for strays (see
    /// [`check_folder`](Self::check_folder)), at no extra cost to the disk.
    pub fn list_dir_meta(&self, path: &str) -> io::Result<Vec<(String, Metadata)>> {
        let folder = self.resolve_dir(&components(path))?;
        let found = scan(&folder);
        if let Some(found) = &found {
            // Only when the folder changed since it was last checked.
            let modified = std::fs::metadata(&folder).and_then(|m| m.modified()).ok();
            if modified.is_none() || lock(&self.checked).get(&folder) != modified.as_ref() {
                self.reconcile(&folder, found)?;
                if let Some(t) = modified {
                    lock(&self.checked).insert(folder.clone(), t);
                }
            }
        }
        let found = found.unwrap_or_default();
        let entries = self.list_entries(path)?;
        Ok(entries
            .into_iter()
            .map(|e| {
                let open = self.handles.get(&e.disk).and_then(|f| f.metadata().ok());
                let disk = open.as_ref().or_else(|| e.disk.file_name().and_then(|n| found.get(n)));
                let m = Metadata::from_disk(e.is_dir, e.size_hint, disk);
                (e.name, m)
            })
            .collect())
    }

    // ---- strays ---------------------------------------------------------
    //
    // Files and folders on disk that a folder's list doesn't name: moved
    // there by hand, or left by a list that was lost. See `docs/FORMAT.md`.

    /// A folder's list. One that's there but won't open with the drive's key
    /// (damaged, or copied over from another drive's folder) is set aside,
    /// not deleted, as `unreadable-list-….bak`, and the list is rebuilt from
    /// what's on disk: this drive's files and folders by their envelopes and
    /// own names, the folder's own name from its parent's list.
    fn dir(&self, folder: &Path) -> io::Result<Arc<Dir>> {
        match self.dirs.load(folder, &self.keys) {
            Err(e) if e.kind() == io::ErrorKind::InvalidData && manifest::Manifest::path_in(folder, &self.keys).exists() => {
                self.set_aside_list(folder)?;
                if let Some(found) = scan(folder) {
                    self.reconcile(folder, &found)?;
                }
                if folder != self.backing_dir {
                    let name = self.real_path_of(folder).and_then(|p| p.rsplit('/').next().map(str::to_string));
                    if let Some(name) = name.filter(|n| !n.is_empty()) {
                        self.dirs.edit(folder, &self.keys, |d| d.set_name(Some(name)))?;
                    }
                }
                self.dirs.load(folder, &self.keys)
            }
            r => r,
        }
    }

    /// Does the disk folder `dir` hold anything this drive's key opens (a
    /// file's envelope, or a subfolder's list)?
    fn holds_ours(&self, dir: &Path) -> bool {
        let Ok(rd) = std::fs::read_dir(dir) else { return false };
        rd.flatten().any(|e| match e.file_type() {
            Ok(t) if t.is_file() => Envelope::read(&e.path(), &self.key).is_ok(),
            Ok(t) if t.is_dir() => {
                manifest::Manifest::path_in(&e.path(), &self.keys).exists() && read_listing(&e.path(), &self.keys).is_ok()
            }
            _ => false,
        })
    }

    /// Move a folder's unreadable list files out of the way, keeping them.
    fn set_aside_list(&self, folder: &Path) -> io::Result<()> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        for e in std::fs::read_dir(folder)?.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
            if manifest::is_list_file(&self.key, &name) {
                std::fs::rename(e.path(), folder.join(format!("unreadable-list-{stamp}-{name}.bak")))?;
            }
        }
        durable::sync_dir(folder)?;
        self.dirs.forget(folder);
        lock(&self.checked).remove(folder);
        lock(&self.repaired).push(folder.to_path_buf());
        Ok(())
    }

    /// Folders whose list couldn't be opened and was rebuilt (see `dir`).
    pub fn repaired_count(&self) -> usize {
        lock(&self.repaired).len()
    }

    /// Check the folder at `path` for strays, if it has changed since it was
    /// last checked: one scan of its disk folder, compared with its list in
    /// memory. A stray from this drive (its envelope, or a folder's list,
    /// opens) is added to the list under its real name; one from another
    /// drive is left alone and counted ([`foreign_count`](Self::foreign_count)).
    /// Entries whose file or folder has gone are dropped. Changes to the
    /// list are saved with the others.
    pub fn check_folder(&self, path: &str) -> io::Result<()> {
        self.check_disk_folder(&self.resolve_dir(&components(path))?)
    }

    fn check_disk_folder(&self, folder: &Path) -> io::Result<()> {
        let modified = std::fs::metadata(folder)?.modified()?;
        if lock(&self.checked).get(folder) == Some(&modified) {
            return Ok(());
        }
        let found = scan(folder).ok_or_else(|| io::Error::other("couldn't read the folder"))?;
        self.reconcile(folder, &found)?;
        lock(&self.checked).insert(folder.to_path_buf(), modified);
        Ok(())
    }

    /// Check the whole drive for strays (as unlocking does, in the
    /// background). Returns how many from other drives are waiting.
    pub fn sweep(&self) -> io::Result<usize> {
        let mut folders = vec![self.backing_dir.clone()];
        while let Some(folder) = folders.pop() {
            let checked = self.check_disk_folder(&folder);
            if folder == self.backing_dir {
                checked?;
            } else if checked.is_err() {
                continue;
            }
            let Ok(dir) = self.dir(&folder) else {
                continue; // a damaged list: reported when the folder is opened
            };
            folders.extend(dir.children().iter().filter(|c| c.is_dir()).map(|c| folder.join(&c.boring)));
        }
        // Every folder has been checked: anything taken in whose old entry
        // didn't turn up had no other entry (a lost list's files, say).
        lock(&self.arrived).clear();
        Ok(self.foreign_count())
    }

    /// How many files and folders from other drives were found (by
    /// [`check_folder`](Self::check_folder) or [`sweep`](Self::sweep)).
    pub fn foreign_count(&self) -> usize {
        lock(&self.foreign).values().map(BTreeSet::len).sum()
    }

    /// Compare a folder's scan with its list (see `check_folder`).
    fn reconcile(&self, folder: &Path, found: &HashMap<OsString, std::fs::Metadata>) -> io::Result<()> {
        let at_root = folder == self.backing_dir;
        // Through `dir`, so an unreadable list is set aside and rebuilt (by
        // this same comparison, then against an empty list).
        let dir = self.dir(folder)?;
        let mut adopt = Vec::new();
        let mut foreign = BTreeSet::new();
        for (name, m) in found {
            let Some(name) = name.to_str() else { continue };
            if dir.has_boring(name)
                || crate::convert::is_reserved(Some(&self.keys), name, at_root)
                || self.doomed.iter().any(|(d, b)| d == folder && b == name)
            {
                continue;
            }
            let path = folder.join(name);
            if m.is_dir() {
                if !manifest::Manifest::path_in(&path, &self.keys).exists() {
                    // Without this drive's list: this drive's folder whose
                    // list was lost (rebuilt when it's opened), another
                    // drive's folder (its files carry a lock), or neither.
                    if self.holds_ours(&path) {
                        adopt.push(Child::dir(RECOVERED.into(), name.into()));
                    } else if carries_a_lock(&path) {
                        foreign.insert(name.to_string());
                    }
                    continue;
                }
                match read_listing(&path, &self.keys) {
                    Ok(l) => adopt.push(Child::dir(l.name.unwrap_or_else(|| RECOVERED.into()), name.into())),
                    // Its list won't open, but what's in it does: this drive's
                    // folder with a damaged list. Repair it and take it in.
                    Err(_) if self.holds_ours(&path) => {
                        let l = self.dir(&path)?;
                        adopt.push(Child::dir(l.name().unwrap_or(RECOVERED).to_string(), name.into()));
                    }
                    Err(_) => {
                        foreign.insert(name.to_string());
                    }
                }
            } else if m.is_file() && m.len() >= ENVELOPE {
                match Envelope::read(&path, &self.key) {
                    Ok(e) => adopt.push(Child::from_envelope(e, name.into(), m.len() - ENVELOPE)),
                    Err(_) if lock::lock_of_file(&path).is_some_and(|l| plausible(&l)) => {
                        foreign.insert(name.to_string());
                    }
                    Err(_) => {} // not a drive's file at all
                }
            }
        }
        let gone: Vec<Child> = dir
            .children()
            .iter()
            .filter(|c| !found.contains_key(std::ffi::OsStr::new(&c.boring)))
            .cloned()
            .collect();
        drop(dir);
        self.note_missing(folder, &gone, &adopt)?;
        if !adopt.is_empty() || !gone.is_empty() {
            self.dirs.edit(folder, &self.keys, |d| {
                for c in &gone {
                    if let Some(p) = d.position_of_boring(&c.boring) {
                        d.remove(p);
                    }
                }
                for c in adopt {
                    if !d.has_boring(&c.boring) {
                        d.push(c); // a clashing name gets " (conflict N)"
                    }
                }
            })?;
        }
        let mut all = lock(&self.foreign);
        if foreign.is_empty() {
            all.remove(folder);
        } else {
            all.insert(folder.to_path_buf(), foreign);
        }
        Ok(())
    }

    /// Record `gone` (dropped from `folder`'s list: found gone from the disk)
    /// as missing, and clear the records of anything in `back` (taken back
    /// in) that had gone missing.
    fn note_missing(&self, folder: &Path, gone: &[Child], back: &[Child]) -> io::Result<()> {
        if gone.is_empty() && back.is_empty() {
            return Ok(());
        }
        let same = |c: &Child, id: &crate::envelope::FileId, boring: &str| {
            if c.is_dir() {
                c.boring == boring
            } else {
                c.id == *id && *id != [0; 16]
            }
        };
        let mut missing = lock(&self.missing);
        let mut arrived = lock(&self.arrived);
        let before = missing.len();
        for c in back {
            // Back after going missing, or moved here from elsewhere in the drive.
            if missing.iter().any(|m| same(c, &m.id, &m.boring)) {
                missing.retain(|m| !same(c, &m.id, &m.boring));
            } else {
                arrived.push((c.id, c.boring.clone()));
            }
        }
        let mut changed = missing.len() != before;
        let gone: Vec<&Child> = gone
            .iter()
            .filter(|c| match arrived.iter().position(|(id, b)| same(c, id, b)) {
                Some(i) => {
                    arrived.swap_remove(i); // moved within the drive
                    false
                }
                None => true,
            })
            .collect();
        drop(arrived);
        if !gone.is_empty() {
            let at = self.real_path_of(folder).unwrap_or_default();
            let since = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            for c in gone {
                let path = if at.is_empty() { c.real.clone() } else { format!("{at}/{}", c.real) };
                if !missing.iter().any(|m| m.path == path && m.boring == c.boring) {
                    missing.push(Missing { path, is_dir: c.is_dir(), since, id: c.id, boring: c.boring.clone() });
                    changed = true;
                }
            }
        }
        if changed {
            self.save_missing(&missing)?;
        }
        Ok(())
    }

    /// Items found gone from the disk (moved out of the drive's folder, or
    /// deleted, outside cloak), oldest first. They're kept until they come
    /// back (then taken in again as strays) or are dismissed with
    /// [`clear_missing`](Self::clear_missing).
    pub fn missing(&self) -> Vec<Missing> {
        lock(&self.missing).clone()
    }

    pub fn missing_count(&self) -> usize {
        lock(&self.missing).len()
    }

    /// Forget the record of missing items.
    pub fn clear_missing(&self) -> io::Result<()> {
        let mut missing = lock(&self.missing);
        missing.clear();
        self.save_missing(&missing)
    }

    /// The record of missing items, at the top (a name worked out from the
    /// drive's key).
    fn missing_path(&self) -> PathBuf {
        self.backing_dir.join(lock::names(&self.key).missing)
    }

    fn load_missing(&self) -> Vec<Missing> {
        #[derive(Deserialize)]
        struct Saved {
            #[serde(flatten)]
            m: Missing,
            id: crate::envelope::FileId,
        }
        let Ok(bytes) = std::fs::read(self.missing_path()) else {
            return Vec::new();
        };
        let Ok(plain) = crypto::open(&self.key, MISSING_LABEL, &bytes) else {
            return Vec::new(); // damaged: only a record, start a new one
        };
        let saved: Vec<Saved> = serde_json::from_slice(&plain).unwrap_or_default();
        saved.into_iter().map(|s| Missing { id: s.id, ..s.m }).collect()
    }

    fn save_missing(&self, missing: &[Missing]) -> io::Result<()> {
        let path = self.missing_path();
        if missing.is_empty() {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        #[derive(Serialize)]
        struct Saved<'a> {
            #[serde(flatten)]
            m: &'a Missing,
            id: crate::envelope::FileId,
        }
        let saved: Vec<Saved> = missing.iter().map(|m| Saved { m, id: m.id }).collect();
        durable::write_atomic(&path, &crypto::seal(&self.key, MISSING_LABEL, &serde_json::to_vec(&saved)?))
    }

    /// The master keys of the other drives the strays here came from that
    /// `password` opens: each stray carries its drive's lock, so neither that
    /// drive nor its folder is needed. One slow password check per drive.
    pub fn keys_for_strays(&self, password: &str) -> io::Result<Vec<Key>> {
        self.sweep()?;
        let strays: Vec<PathBuf> = lock(&self.foreign)
            .iter()
            .flat_map(|(d, names)| names.iter().map(move |n| d.join(n)))
            .collect();
        let mut locks = Vec::new();
        for p in strays {
            let found = if p.is_dir() { first_lock_in(&p) } else { lock::lock_of_file(&p) };
            locks.extend(found.filter(plausible));
        }
        let mut keys: Vec<Key> = Vec::new();
        let mut tried: Vec<crate::key::Salt> = Vec::new();
        for l in &locks {
            let Some((salt, _)) = lock::peek(l) else { continue };
            if tried.contains(&salt) {
                continue;
            }
            tried.push(salt);
            let kek = lock::kek_for(password, &salt)?;
            for l2 in locks.iter().filter(|l2| lock::peek(l2.as_slice()).is_some_and(|(s, _)| s == salt)) {
                if let Ok((master, _, _)) = lock::open_with(&kek, l2) {
                    if !keys.contains(&master) {
                        keys.push(master);
                    }
                    break;
                }
            }
        }
        Ok(keys)
    }

    /// What [`adopt_from`](Self::adopt_from) would bring in with `other`,
    /// without changing anything: each item's path in this drive (the
    /// folder it sits in, then its real name), whether it's a folder and,
    /// for a folder, how many items it holds directly. Also how many items
    /// are from yet another drive.
    pub fn preview_from(&self, other: &Key) -> io::Result<(Vec<Found>, usize)> {
        self.sweep()?;
        let strays: Vec<(PathBuf, String)> = lock(&self.foreign)
            .iter()
            .flat_map(|(d, names)| names.iter().map(move |n| (d.clone(), n.clone())))
            .collect();
        let mut found = Vec::new();
        let mut left = 0;
        for (folder, name) in strays {
            let path = folder.join(&name);
            let theirs = Keys::bare(*other, 0);
            if !path.is_dir() && is_other_list(&theirs, &name) {
                continue; // that drive's own list, copied in: nothing to bring in
            }
            let item = if path.is_dir() {
                let listed = manifest::Manifest::path_in(&path, &theirs).exists();
                listed.then(|| read_listing(&path, &theirs).ok()).flatten().map(|l| Found {
                    path: String::new(),
                    name: l.name.unwrap_or_else(|| RECOVERED.into()),
                    is_dir: true,
                    items: l.children.len(),
                })
            } else {
                Envelope::read(&path, other).ok().map(|e| Found { path: String::new(), name: e.name, is_dir: false, items: 0 })
            };
            match item {
                Some(mut f) => {
                    let at = self.real_path_of(&folder).unwrap_or_default();
                    f.path = if at.is_empty() { f.name.clone() } else { format!("{at}/{}", f.name) };
                    found.push(f);
                }
                None => left += 1,
            }
        }
        found.sort_by_key(|f| names::fold(&f.path));
        Ok((found, left))
    }

    /// The drive path (real names, `/`-separated; `""` for the top) of the
    /// disk folder `disk`, found by looking each boring name up in its
    /// parent's list.
    fn real_path_of(&self, disk: &Path) -> Option<String> {
        let rel = disk.strip_prefix(&self.backing_dir).ok()?;
        let mut cur = self.backing_dir.clone();
        let mut out = Vec::new();
        for c in rel.components() {
            let boring = c.as_os_str().to_str()?;
            let dir = self.dir(&cur).ok()?;
            let child = dir.children().iter().find(|ch| ch.boring == boring)?;
            out.push(child.real.clone());
            cur = cur.join(boring);
        }
        Some(out.join("/"))
    }

    /// Bring in the strays from the drive whose master key is `other`:
    /// each file's envelope (and each folder's lists and the envelopes inside
    /// it) is opened with `other` and sealed again with this drive's key, and
    /// the item joins its folder's list. A file's data and its own key don't
    /// change, so this costs about 512 bytes per file. Returns how many were
    /// brought in and how many are left (from yet another drive).
    pub fn adopt_from(&mut self, other: &Key) -> io::Result<(usize, usize)> {
        self.sweep()?;
        let strays: Vec<(PathBuf, String)> = lock(&self.foreign)
            .iter()
            .flat_map(|(d, names)| names.iter().map(move |n| (d.clone(), n.clone())))
            .collect();
        let (mut adopted, mut left) = (0, 0);
        let theirs = Keys::bare(*other, 0);
        for (folder, name) in strays {
            let path = folder.join(&name);
            if !path.is_dir() && is_other_list(&theirs, &name) {
                // That drive's own list, copied in: of no use here once its
                // files are brought in (each by its own envelope).
                std::fs::remove_file(&path)?;
                if let Some(set) = lock(&self.foreign).get_mut(&folder) {
                    set.remove(&name);
                }
                continue;
            }
            let child = if path.is_dir() {
                if self.rekey_tree(&path, other)? {
                    let l = read_listing(&path, &self.keys)?;
                    Some(Child::dir(l.name.unwrap_or_else(|| RECOVERED.into()), name.clone()))
                } else {
                    None
                }
            } else {
                let size = std::fs::metadata(&path)?.len().saturating_sub(ENVELOPE);
                self.rekey_file(&path, other)?.map(|e| Child::from_envelope(e, name.clone(), size))
            };
            match child {
                Some(c) => {
                    self.dirs.edit(&folder, &self.keys, |d| {
                        if !d.has_boring(&c.boring) {
                            d.push(c);
                        }
                    })?;
                    if let Some(set) = lock(&self.foreign).get_mut(&folder) {
                        set.remove(&name);
                    }
                    adopted += 1;
                }
                None => left += 1,
            }
        }
        lock(&self.foreign).retain(|_, s| !s.is_empty());
        self.sync()?;
        Ok((adopted, left))
    }

    /// Seal the envelope of the file at `path` with this drive's key if it's
    /// sealed with `other`. Its old envelope is journaled first, so a crash
    /// part-way leaves one or the other, never neither. `None` if neither key
    /// opens it.
    fn rekey_file(&self, path: &Path, other: &Key) -> io::Result<Option<Envelope>> {
        if let Ok(e) = Envelope::read(path, &self.key) {
            return Ok(Some(e));
        }
        let Ok(e) = Envelope::read(path, other) else {
            return Ok(None);
        };
        let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        let len = f.metadata()?.len();
        let at = len - ENVELOPE;
        let mut old = [0u8; ENVELOPE as usize];
        read_exact_at(&f, &mut old, at)?;
        self.write_journal(&Journal::Undo { blob: self.rel(path), len, ranges: vec![(at, old.to_vec())] })?;
        write_all_at(&f, &e.seal(&self.key, &self.keys.lock()), at)?;
        f.sync_data()?;
        self.clear_journal()?;
        Ok(Some(e))
    }

    /// Re-seal a folder from the drive with key `other`, and everything in
    /// it, with this drive's key: files first, then each folder's own list,
    /// so an interrupted run is simply run again. False if the folder's
    /// list opens with neither key.
    fn rekey_tree(&self, dir: &Path, other: &Key) -> io::Result<bool> {
        let other = Keys::bare(*other, 0);
        let ours = manifest::Manifest::path_in(dir, &self.keys);
        let theirs = if ours.exists() && read_listing(dir, &self.keys).is_ok() {
            None // re-sealed already, by a run that stopped part-way
        } else if manifest::Manifest::path_in(dir, &other).exists() {
            match read_listing(dir, &other) {
                Ok(l) => Some(l),
                Err(_) => return Ok(false),
            }
        } else {
            return Ok(false);
        };
        for e in std::fs::read_dir(dir)?.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
            if crate::convert::is_reserved(Some(&self.keys), &name, false)
                || crate::convert::is_reserved(Some(&other), &name, false)
            {
                continue;
            }
            let ft = e.file_type()?;
            if ft.is_dir() {
                self.rekey_tree(&e.path(), &other.master)?;
            } else if ft.is_file() {
                self.rekey_file(&e.path(), &other.master)?;
            }
        }
        if let Some(l) = theirs {
            write_listing(dir, &self.keys, l.name.as_deref(), &l.children, 0, &mut Vec::new(), None)?;
            // Then the other drive's list files go: this one's replace them.
            let _ = std::fs::remove_file(manifest::Manifest::path_in(dir, &other));
            for i in 0..l.parts {
                let _ = std::fs::remove_file(dir.join(manifest::part_name(&other, i)));
            }
        }
        Ok(true)
    }

    /// The path with each component in its stored case (lookups are
    /// case-insensitive, so `photos/A.JPG` may name `Photos/a.jpg`). `None` if
    /// any component is missing. The root is `""`.
    pub fn canonical_path(&self, path: &str) -> io::Result<Option<String>> {
        let comps = components(path);
        let mut cur = self.backing_dir.clone();
        let mut out = Vec::with_capacity(comps.len());
        for (i, name) in comps.iter().enumerate() {
            let manifest = self.dir(&cur)?;
            let Some(child) = manifest.find(name) else {
                return Ok(None);
            };
            out.push(child.real.clone());
            if i + 1 < comps.len() {
                if !child.is_dir() {
                    return Ok(None);
                }
                cur = cur.join(&child.boring);
            }
        }
        Ok(Some(out.join("/")))
    }

    /// List a directory: (name, is_dir, size) for each immediate child.
    pub fn list_dir(&self, path: &str) -> io::Result<Vec<(String, bool, u64)>> {
        Ok(self
            .list_dir_meta(path)?
            .into_iter()
            .map(|(name, m)| (name, m.is_dir, m.size))
            .collect())
    }

    /// Root-level child names (flat-compatibility helper for the mount adapters).
    pub fn list(&self) -> Vec<String> {
        self.list_dir("")
            .map(|v| v.into_iter().map(|(n, _, _)| n).collect())
            .unwrap_or_default()
    }

    // ---- mutations -------------------------------------------------------

    /// Create a new directory at `path`. Its parent must already exist.
    pub fn mkdir(&mut self, path: &str) -> io::Result<()> {
        let (parent, name) = parent_and_name(path)?;
        names::validate(&name)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let boring = {
            let dir = self.dir(&parent_disk)?;
            if dir.find(&name).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "name already exists",
                ));
            }
            generate_unique(&mut rand::thread_rng(), &Taken { dir: &dir, at: &parent_disk })
        };
        let disk = parent_disk.join(&boring);
        std::fs::create_dir(&disk)?;
        // Its own list first, with its name, so the folder describes itself
        // from the start.
        write_listing(&disk, &self.keys, Some(&name), &[], 0, &mut Vec::new(), None)?;
        self.dirs.edit(&parent_disk, &self.keys, |d| d.push(Child::dir(name, boring)))?;
        self.tick()
    }

    /// Create an empty file at `path` (parent must exist). Returns its boring
    /// name; if the name already exists, returns the existing boring name.
    pub fn create(&mut self, path: &str) -> io::Result<String> {
        let (parent, name) = parent_and_name(path)?;
        names::validate(&name)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let boring = {
            let dir = self.dir(&parent_disk)?;
            if let Some(existing) = dir.find(&name) {
                if existing.is_dir() {
                    return Err(io::Error::new(io::ErrorKind::IsADirectory, "is a directory"));
                }
                return Ok(existing.boring.clone());
            }
            generate_unique(&mut rand::thread_rng(), &Taken { dir: &dir, at: &parent_disk })
        };
        let child = Child::new_file(name, boring.clone(), 0);
        // Created empty: its envelope goes in with its first data (or when
        // it's closed or saved still empty), so a new file is written once.
        // Its handle is kept for the writes that usually follow: on Windows,
        // reopening a file just written waits for the antivirus scan.
        let blob = parent_disk.join(&boring);
        let f = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&blob)?;
        let env = child.envelope().seal(&self.key, &self.keys.lock());
        self.unwritten.insert(blob.clone());
        if self.handles.len() >= MAX_HANDLES {
            self.handles.clear();
        }
        self.handles.insert(blob.clone(), f);
        self.envelopes.insert(blob, env);
        self.dirs.edit(&parent_disk, &self.keys, |d| d.push(child))?;
        self.tick()?;
        Ok(boring)
    }

    /// Ingest a real file into the root under its own filename.
    pub fn ingest(&mut self, source: impl AsRef<Path>) -> io::Result<String> {
        let source = source.as_ref();
        let name = source
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no file name"))?
            .to_owned();
        let data = std::fs::read(source)?;
        let boring = self.create(&name)?;
        self.write_at(&name, 0, &data)?;
        Ok(boring)
    }

    /// Write `data` at `offset`, growing the file if needed. Only the written
    /// bytes and the encrypted ends that move are touched (see `update_blob`),
    /// so appending to a large file costs about the same as appending to a
    /// small one. The manifest isn't rewritten: a file's size is its boring
    /// file's length.
    pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> io::Result<()> {
        let (blob, crypt) = self.file_blob(path)?;
        self.write_blob(blob, crypt, offset, data)
    }

    /// Set a file's length (shorter truncates, longer zero-extends).
    pub fn truncate(&mut self, path: &str, new_size: u64) -> io::Result<()> {
        let (blob, crypt) = self.file_blob(path)?;
        self.truncate_blob(blob, crypt, new_size)
    }

    /// Make everything written to `path` durable (an app's fsync /
    /// FlushFileBuffers).
    /// Its name is saved too, along with any other pending list changes.
    pub fn flush(&mut self, path: &str) -> io::Result<()> {
        self.sync()?;
        let (blob, _) = self.file_blob(path)?;
        self.flush_blob(&blob)
    }

    /// The last handle on `path` closed. Like a normal filesystem, closing
    /// doesn't force data to disk; it only ends the "written since flush"
    /// tracking (later writes then treat everything as durable, which only
    /// ever means more protection).
    pub fn close(&mut self, path: &str) {
        if let Ok((blob, _)) = self.file_blob(path) {
            self.close_blob(&blob);
        }
    }

    // ---- open files ------------------------------------------------------
    //
    // A mount adapter opens a file once and then reads and writes it by id,
    // as an OS file handle works: the path is resolved at open, not on every
    // 4 KiB a cache writes back. The id follows the file through renames and
    // moves.

    /// Open the file at `path`; returns an id for the `*_file` calls. Pair
    /// with [`release_file`](Self::release_file).
    pub fn open_file(&mut self, path: &str) -> io::Result<u64> {
        let (blob, crypt) = self.file_blob(path)?;
        let id = self.next_id;
        self.next_id += 1;
        self.open.insert(id, Opened { blob, crypt });
        Ok(id)
    }

    /// The app closed the file. The last close of a file ends its tracking,
    /// as [`close`](Self::close) does.
    pub fn release_file(&mut self, id: u64) {
        if let Some(o) = self.open.remove(&id) {
            if !self.open.values().any(|other| other.blob == o.blob) {
                self.close_blob(&o.blob);
            }
        }
    }

    fn opened(&self, id: u64) -> io::Result<(PathBuf, Crypt)> {
        self.open
            .get(&id)
            .map(|o| (o.blob.clone(), o.crypt))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file not open"))
    }

    pub fn read_file(&self, id: u64, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let o = self.open.get(&id).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file not open"))?;
        self.read_blob(&o.blob, &o.crypt, offset, len)
    }

    pub fn write_file(&mut self, id: u64, offset: u64, data: &[u8]) -> io::Result<()> {
        let (blob, crypt) = self.opened(id)?;
        self.write_blob(blob, crypt, offset, data)
    }

    pub fn truncate_file(&mut self, id: u64, new_size: u64) -> io::Result<()> {
        let (blob, crypt) = self.opened(id)?;
        self.truncate_blob(blob, crypt, new_size)
    }

    pub fn flush_file(&mut self, id: u64) -> io::Result<()> {
        self.sync()?;
        let (blob, _) = self.opened(id)?;
        self.flush_blob(&blob)
    }

    /// An open file's metadata, from its handle where there is one.
    pub fn file_metadata(&self, id: u64) -> io::Result<Metadata> {
        let o = self.open.get(&id).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file not open"))?;
        Ok(self.disk_metadata(false, 0, &o.blob))
    }

    /// Point open files at a boring entry's new place after a move (a moved
    /// folder takes the files inside it along).
    fn moved(&mut self, from: &Path, to: &Path) {
        for o in self.open.values_mut() {
            if let Ok(rest) = o.blob.strip_prefix(from) {
                o.blob = if rest.as_os_str().is_empty() { to.to_path_buf() } else { to.join(rest) };
            }
        }
    }

    // ---- boring files ----------------------------------------------------

    fn write_blob(&mut self, blob: PathBuf, crypt: Crypt, offset: u64, data: &[u8]) -> io::Result<()> {
        let f = self.take_handle(&blob)?;
        let result = (|| {
            let old = data_len(&f)?;
            let end = offset + data.len() as u64;
            let new = max(old, end);
            // Changing bytes in an encrypted end: a fresh nonce first.
            let crypt = if offset < old && overlaps(&protected_ranges(old, self.region), offset, min(end, old)) {
                self.renonce(&f, &blob, crypt, old)?
            } else {
                crypt
            };
            self.update_blob(&f, &blob, &crypt, old, new, offset, data)
        })();
        self.handles.insert(blob, f);
        result
    }

    fn truncate_blob(&mut self, blob: PathBuf, crypt: Crypt, new_size: u64) -> io::Result<()> {
        let f = self.take_handle(&blob)?;
        let result = (|| {
            let old = data_len(&f)?;
            if new_size == old {
                return Ok(());
            }
            if new_size < old && new_size > 0 {
                // Shortening brings bytes into the tail end: a fresh nonce first.
                let crypt = self.renonce(&f, &blob, crypt, old)?;
                return self.update_blob(&f, &blob, &crypt, old, new_size, new_size, &[]);
            }
            self.update_blob(&f, &blob, &crypt, old, new_size, new_size, &[])?;
            if new_size == 0 {
                // Nothing left under the old nonce: start the next contents
                // under a new one.
                self.renonce(&f, &blob, crypt, 0)?;
            }
            Ok(())
        })();
        self.handles.insert(blob, f);
        result
    }

    /// Give the file at `blob` (`len` bytes long, encrypted with `crypt`) a
    /// new content nonce for this editing session, re-encrypting its ends,
    /// unless it already has one. Returns the key and nonce to use from now on.
    ///
    /// Crash safety: the original ends and envelope are journaled first, the
    /// file is synced before its list is saved with the new nonce, and the
    /// journal goes last. After a crash the list says which nonce won: if
    /// it's still the old one, the original bytes go back.
    fn renonce(&mut self, f: &std::fs::File, blob: &Path, crypt: Crypt, len: u64) -> io::Result<Crypt> {
        if self.renonced.contains(blob) {
            return Ok(crypt);
        }
        let (dir, boring) = split_blob(blob)?;
        let entry = self.dir(&dir)?.children().iter().find(|c| c.boring == boring).cloned();
        let Some(mut entry) = entry else {
            return Ok(crypt); // not listed (being moved): leave it be
        };
        let (key, old_nonce) = crypt;
        let nonce = envelope::new_nonce();
        let mut ranges = Vec::new();
        for (s, e) in protected_ranges(len, self.region) {
            let mut buf = vec![0u8; (e - s) as usize];
            read_exact_at(f, &mut buf, s)?;
            ranges.push((s, buf));
        }
        let old_env = self.envelope_of(f, blob, len)?;
        ranges.push((len, old_env.to_vec()));
        let journaled = len > 0;
        if journaled {
            self.write_journal(&Journal::Renonce {
                dir: self.rel(&dir),
                boring: boring.clone(),
                nonce,
                len: len + ENVELOPE,
                ranges: ranges.clone(),
            })?;
        }
        for (s, mut buf) in ranges.into_iter().take_while(|(s, _)| *s < len) {
            transform_region(&key, &old_nonce, s, &mut buf);
            transform_region(&key, &nonce, s, &mut buf);
            write_all_at(f, &buf, s)?;
        }
        entry.nonce = nonce;
        let env = entry.envelope().seal(&self.key, &self.keys.lock());
        write_all_at(f, &env, len)?;
        self.envelopes.insert(blob.to_path_buf(), env);
        self.unwritten.remove(blob);
        f.sync_data()?;
        self.dirs.edit(&dir, &self.keys, |d| {
            if let Some(p) = d.position_of_boring(&boring) {
                d.child_mut(p).nonce = nonce;
            }
        })?;
        self.dirs.flush_dir(&dir, &self.keys)?;
        if journaled {
            self.clear_journal()?;
        }
        for o in self.open.values_mut().filter(|o| o.blob == blob) {
            o.crypt = (key, nonce);
        }
        self.renonced.insert(blob.to_path_buf());
        Ok((key, nonce))
    }

    /// Put the envelope of a new file that's still empty on the disk.
    fn write_unwritten_one(&mut self, blob: &Path) -> io::Result<()> {
        self.unwritten.remove(blob);
        let Some(env) = self.envelopes.get(blob).copied() else { return Ok(()) };
        let f = match self.handles.get(blob) {
            Some(f) => f.try_clone()?,
            None => match std::fs::OpenOptions::new().read(true).write(true).open(blob) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()), // deleted since
                Err(e) => return Err(e),
            },
        };
        if f.metadata()?.len() == 0 {
            write_all_at(&f, &env, 0)?;
        }
        Ok(())
    }

    /// Put every pending envelope on the disk (see `unwritten`).
    fn write_unwritten(&mut self) -> io::Result<()> {
        let blobs: Vec<PathBuf> = self.unwritten.iter().cloned().collect();
        for blob in blobs {
            self.write_unwritten_one(&blob)?;
        }
        Ok(())
    }

    /// The envelope of the file at `blob` whose data is `len` bytes, from the
    /// cache or the disk.
    fn envelope_of(&mut self, f: &std::fs::File, blob: &Path, len: u64) -> io::Result<[u8; ENVELOPE as usize]> {
        if let Some(e) = self.envelopes.get(blob) {
            return Ok(*e);
        }
        let mut e = [0u8; ENVELOPE as usize];
        read_exact_at(f, &mut e, len)?;
        self.envelopes.insert(blob.to_path_buf(), e);
        Ok(e)
    }

    fn flush_blob(&mut self, blob: &Path) -> io::Result<()> {
        if self.durable_len.remove(blob).is_some() {
            match self.handles.get(blob) {
                Some(f) => f.sync_data()?,
                None => std::fs::OpenOptions::new().write(true).open(blob)?.sync_data()?,
            }
        }
        Ok(())
    }

    fn close_blob(&mut self, blob: &Path) {
        if self.unwritten.contains(blob) {
            let _ = self.write_unwritten_one(blob);
        }
        self.durable_len.remove(blob);
        self.handles.remove(blob);
        self.sparse.remove(blob);
        self.envelopes.remove(blob);
        self.renonced.remove(blob);
        readers_mut(&mut self.readers).remove(blob);
    }

    /// A read-write handle on `blob`, from the cache or freshly opened. The
    /// caller puts it back.
    fn take_handle(&mut self, blob: &Path) -> io::Result<std::fs::File> {
        if let Some(f) = self.handles.remove(blob) {
            return Ok(f);
        }
        if self.handles.len() >= MAX_HANDLES {
            self.handles.clear();
        }
        std::fs::OpenOptions::new().read(true).write(true).open(blob)
    }

    /// The boring file, key and nonce behind a file path.
    fn file_blob(&self, path: &str) -> io::Result<(PathBuf, Crypt)> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let manifest = self.dir(&parent_disk)?;
        let child = manifest.find(&name).ok_or_else(not_found)?;
        if child.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "is a directory"));
        }
        Ok((parent_disk.join(&child.boring), child.crypt()))
    }

    /// Take blob `f` (at `blob`) from `old` to `new` bytes of data (its envelope
    /// follows them) and write `data` at `offset`
    /// (`offset + data.len() <= new`), leaving it exactly as if the whole
    /// plaintext had been re-encrypted at the new size.
    ///
    /// Encryption is a keystream XOR keyed by file offset, so a byte's disk
    /// form depends only on whether it lies in an encrypted end. A resize moves
    /// the tail end: bytes that enter or leave it are toggled in place, bytes
    /// added by growing are zeros (keystream inside an end), and the new data
    /// is encrypted where it falls in an end. Everything else is untouched, so
    /// the cost is the data plus at most two ends, whatever the file size.
    ///
    /// Toggling is the one step that rewrites bytes the app didn't write, so a
    /// crash part-way could garble data that was safely on disk. When a toggle
    /// reaches below the file's length at its last flush, the original bytes
    /// are journaled first and the file is synced before the journal goes; a
    /// crash then rolls the file back to before this write. A plain copy or
    /// append only ever toggles bytes it wrote itself since the last flush,
    /// so it never pays for this.
    #[allow(clippy::too_many_arguments)]
    fn update_blob(
        &mut self,
        f: &std::fs::File,
        blob: &Path,
        crypt: &Crypt,
        old: u64,
        new: u64,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let end = offset + data.len() as u64;
        let n = self.region;
        let (key, nonce) = (&crypt.0, &crypt.1);
        let env = if new != old { Some(self.envelope_of(f, blob, old)?) } else { None };

        let kept = min(old, new);
        let toggles = subtract(&toggled(old, new, n, kept), offset, end);
        let durable = *self.durable_len.entry(blob.to_path_buf()).or_insert(old);
        let journaled = toggles.iter().any(|&(s, _)| s < durable);
        if journaled {
            let mut ranges = Vec::with_capacity(toggles.len());
            for &(s, e) in &toggles {
                let mut buf = vec![0u8; (e - s) as usize];
                read_exact_at(f, &mut buf, s)?;
                ranges.push((s, buf));
            }
            if let Some(env) = env {
                ranges.push((old, env.to_vec()));
            }
            self.write_journal(&Journal::Undo { blob: self.rel(blob), len: old + ENVELOPE, ranges })?;
        }
        if new < durable {
            self.durable_len.insert(blob.to_path_buf(), new);
        }

        // 1. Kept bytes whose encrypted/plain state flips (skipping what `data`
        //    is about to overwrite).
        for &(s, e) in &toggles {
            let mut buf = vec![0u8; (e - s) as usize];
            read_exact_at(f, &mut buf, s)?;
            transform_region(key, nonce, s, &mut buf);
            write_all_at(f, &buf, s)?;
        }

        // 2. Resize. Added bytes read as zeros, which is right outside the ends;
        //    inside one they must hold the keystream. Where the envelope was
        //    is cleared first.
        // Growing by a write that reaches the new end needs no resize: that
        // write (data then envelope) extends the file itself, and any gap
        // before it reads as zeros.
        let extends = new > old && !data.is_empty() && end == new;
        // A jump in size puts the tail end and envelope far past the old end.
        // Windows would first fill the gap with zeros on the disk, and then
        // the app writes its data over them (a copy sets the file's full size
        // before writing it): every byte twice. A sparse file leaves the gap
        // as a hole instead, which reads as the same zeros. It stays sparse:
        // making it normal again on close would write zeros wherever the
        // app's data hasn't reached the disk yet, the same double write.
        let gap_to = if extends { offset } else { new };
        if gap_to >= old + SPARSE_MIN && !self.sparse.contains(blob) && set_sparse(f, true).is_ok() {
            self.sparse.insert(blob.to_path_buf());
        }
        if new != old && !extends {
            f.set_len(new + ENVELOPE)?;
        }
        if new > old {
            for (s, e) in subtract(&[(old, min(old + ENVELOPE, new))], offset, end) {
                write_all_at(f, &vec![0u8; (e - s) as usize], s)?;
            }
            let added = clip(&protected_ranges(new, n), old, new);
            for (s, e) in subtract(&added, offset, end) {
                let mut buf = vec![0u8; (e - s) as usize];
                transform_region(key, nonce, s, &mut buf);
                write_all_at(f, &buf, s)?;
            }
        }

        // 3. The data itself, and the envelope at the new end (in the same
        //    write when the data reaches it, as when appending).
        let mut env = env;
        let encrypted = clip(&protected_ranges(new, n), offset, end);
        if !data.is_empty() && encrypted.is_empty() && (env.is_none() || end != new || data.len() > 64 * 1024) {
            // All in the plain middle: straight from the app's buffer, not a
            // copy of it (the envelope, if it moves, follows in its own write).
            write_all_at(f, data, offset)?;
        } else if !data.is_empty() {
            let mut buf = data.to_vec();
            for (s, e) in encrypted {
                let (ls, le) = ((s - offset) as usize, (e - offset) as usize);
                transform_region(key, nonce, s, &mut buf[ls..le]);
            }
            if end == new {
                if let Some(e) = env.take() {
                    buf.extend_from_slice(&e);
                }
            }
            write_all_at(f, &buf, offset)?;
        }
        if let Some(e) = env {
            write_all_at(f, &e, new)?;
        }
        if new != old {
            self.unwritten.remove(blob); // written at the new end, just now
        }
        if journaled {
            f.sync_data()?;
            self.clear_journal()?;
        }
        Ok(())
    }

    /// Delete a file, or a directory and its whole subtree. It leaves the
    /// list at once and the disk when the list is saved.
    pub fn remove(&mut self, path: &str) -> io::Result<()> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        if self.dir(&parent_disk)?.find(&name).is_none() {
            return Ok(());
        }
        let child = self
            .dirs
            .edit(&parent_disk, &self.keys, |d| d.position(&name).map(|p| d.remove(p)))?
            .ok_or_else(not_found)?;
        self.durable_len.remove(&parent_disk.join(&child.boring));
        self.doomed.push((parent_disk, child.boring));
        self.tick()
    }

    /// Rename or move a path. Same parent => rename in place (no disk move, the
    /// boring name is untouched). Different parent => a single cheap on-disk
    /// `rename` of the boring entry (moving a whole subtree in one metadata op).
    /// Errors with `AlreadyExists` if `new` names a different existing entry; a
    /// rename to the same entry in another case or Unicode form (`a.txt` ->
    /// `A.txt`) just updates the stored name.
    pub fn rename_path(&mut self, old: &str, new: &str) -> io::Result<()> {
        self.rename_inner(old, new, false)
    }

    /// Like [`rename_path`](Self::rename_path), but an existing file or empty
    /// directory at `new` is replaced (POSIX `rename`, Windows
    /// `MoveFileEx(REPLACE_EXISTING)`). This is how most editors save: write a
    /// temp file, then rename it over the original. A non-empty directory at
    /// `new` is never replaced (`DirectoryNotEmpty`), and a file never replaces
    /// a directory or vice versa.
    pub fn rename_replace(&mut self, old: &str, new: &str) -> io::Result<()> {
        self.rename_inner(old, new, true)
    }

    fn rename_inner(&mut self, old: &str, new: &str, replace: bool) -> io::Result<()> {
        let (old_parent, old_name) = parent_and_name(old)?;
        let (new_parent, new_name) = parent_and_name(new)?;
        names::validate(&new_name)?;

        let old_parent_disk = self.resolve_dir(&old_parent)?;
        let old_manifest = self.dir(&old_parent_disk)?;
        let pos = old_manifest.position(&old_name).ok_or_else(not_found)?;
        let moving_dir = old_manifest.children()[pos].is_dir();
        let new_parent_disk = self.resolve_dir(&new_parent)?;
        let same_parent = old_parent_disk == new_parent_disk;

        // An existing *different* entry at the destination: replace or refuse.
        let target = if same_parent {
            old_manifest.position(&new_name).filter(|&p| p != pos)
        } else {
            self.dir(&new_parent_disk)?.position(&new_name)
        };
        let mut replaced = None;
        if let Some(t) = target {
            if !replace {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "destination exists",
                ));
            }
            let dest = self
                .metadata(new)?
                .ok_or_else(not_found)?;
            if dest.is_dir != moving_dir {
                let kind = if dest.is_dir {
                    io::ErrorKind::IsADirectory
                } else {
                    io::ErrorKind::NotADirectory
                };
                return Err(io::Error::new(kind, "destination is a different kind"));
            }
            if dest.is_dir && !self.list_entries(new)?.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::DirectoryNotEmpty,
                    "destination directory not empty",
                ));
            }
            let manifest = if same_parent {
                old_manifest.clone()
            } else {
                self.dir(&new_parent_disk)?
            };
            let boring = manifest.children()[t].boring.clone();
            self.durable_len.remove(&new_parent_disk.join(&boring));
            replaced = Some(boring);
        }

        let mut child = old_manifest.children()[pos].clone();
        drop(old_manifest);
        let from_boring = child.boring.clone();

        // Within one folder only the list changes, so it's saved with the
        // others; a replaced entry is deleted from the disk after that.
        if same_parent {
            let gone = replaced.clone();
            self.dirs.edit(&old_parent_disk, &self.keys, |d| {
                if let Some(p) = gone.as_deref().and_then(|r| d.position_of_boring(r)) {
                    d.remove(p);
                }
                let p = d.position_of_boring(&from_boring).expect("found above");
                d.rename(p, new_name.clone());
            })?;
            if moving_dir {
                self.name_folder(&old_parent_disk.join(&from_boring), &new_name)?;
            }
            if let Some(r) = replaced {
                self.doomed.push((old_parent_disk, r));
            }
            return self.tick();
        }

        // Across folders the boring entry moves on disk and two lists change:
        // journaled, and saved before returning.
        let new_manifest = self.dir(&new_parent_disk)?;
        child.boring = generate_unique(&mut rand::thread_rng(), &Taken { dir: &new_manifest, at: &new_parent_disk });
        drop(new_manifest);
        child.real = new_name.clone();
        if let Ok(blob) = self.disk_path(old) {
            self.durable_len.remove(&blob);
        }
        let moved_to = new_parent_disk.join(&child.boring);
        self.run(Journal::Move {
            from_dir: self.rel(&old_parent_disk),
            from_boring,
            to_dir: self.rel(&new_parent_disk),
            child,
            replaced,
        })?;
        if moving_dir {
            self.name_folder(&moved_to, &new_name)?;
        }
        Ok(())
    }

    /// Record a folder's real name in its own list (saved with the others).
    fn name_folder(&mut self, disk: &Path, name: &str) -> io::Result<()> {
        self.dirs.edit(disk, &self.keys, |d| d.set_name(Some(name.to_string())))?;
        self.tick()
    }

    // ---- reads -----------------------------------------------------------

    /// Read `len` plaintext bytes at `offset` of the file at `path`.
    pub fn read_at(&self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let manifest = self.dir(&parent_disk)?;
        let child = manifest.find(&name).ok_or_else(not_found)?;
        if child.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "is a directory"));
        }
        self.read_blob(&parent_disk.join(&child.boring), &child.crypt(), offset, len)
    }

    fn read_blob(&self, blob: &Path, crypt: &Crypt, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        // The handle the file is being written through if there is one:
        // opening a just-written file again waits for the antivirus scan, and
        // with Windows caching, every new file's first page is read back.
        let reader;
        let file: &std::fs::File = match self.handles.get(blob) {
            Some(f) => f,
            None => {
                let mut readers = self.readers.lock().unwrap_or_else(PoisonError::into_inner);
                reader = match readers.get(blob) {
                    Some(f) => f.clone(),
                    None => {
                        if readers.len() >= MAX_HANDLES {
                            readers.clear();
                        }
                        let f = Arc::new(std::fs::File::open(blob)?);
                        readers.insert(blob.to_path_buf(), f.clone());
                        f
                    }
                };
                &reader
            }
        };
        let size = data_len(file)?;
        if offset >= size {
            return Ok(Vec::new());
        }
        let end = min(offset + len as u64, size);
        let mut buf = vec![0u8; (end - offset) as usize];
        read_exact_at(file, &mut buf, offset)?;

        for (rs, re) in protected_ranges(size, self.region) {
            let o_start = max(offset, rs);
            let o_end = min(end, re);
            if o_start < o_end {
                let ls = (o_start - offset) as usize;
                let le = (o_end - offset) as usize;
                transform_region(&crypt.0, &crypt.1, o_start, &mut buf[ls..le]);
            }
        }
        Ok(buf)
    }

    /// Read a whole file back as plaintext.
    pub fn read_all(&self, path: &str) -> io::Result<Vec<u8>> {
        let size = self
            .metadata(path)?
            .filter(|m| !m.is_dir)
            .ok_or_else(not_found)?
            .size;
        self.read_at(path, 0, size as usize)
    }


    // ---- journal ---------------------------------------------------------

    /// `disk` relative to the backing root, `/`-separated.
    fn rel(&self, disk: &Path) -> String {
        disk.strip_prefix(&self.backing_dir)
            .unwrap_or(disk)
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    }

    fn abs(&self, rel: &str) -> PathBuf {
        rel.split('/').filter(|c| !c.is_empty()).fold(self.backing_dir.clone(), |p, c| p.join(c))
    }

    fn write_journal(&self, j: &Journal) -> io::Result<()> {
        let sealed = crypto::seal(&self.key, JOURNAL_LABEL, &serde_json::to_vec(j)?);
        durable::write_synced(&self.backing_dir.join(JOURNAL), &sealed)?;
        durable::sync_dir(&self.backing_dir)
    }

    fn clear_journal(&self) -> io::Result<()> {
        std::fs::remove_file(self.backing_dir.join(JOURNAL))?;
        durable::sync_dir(&self.backing_dir)
    }

    /// Journal a change, carry it out, and clear the journal. Cached handles
    /// are closed first: Windows won't delete a folder while a file in it is
    /// open, and a moved file's handle would be keyed by its old path.
    fn run(&mut self, j: Journal) -> io::Result<()> {
        self.sync()?;
        self.handles.clear();
        self.envelopes.clear();
        readers_mut(&mut self.readers).clear();
        self.write_journal(&j)?;
        self.apply(&j)?;
        if let Journal::Move { from_dir, from_boring, to_dir, child, .. } = &j {
            let from = self.abs(from_dir).join(from_boring);
            let to = self.abs(to_dir).join(&child.boring);
            self.moved(&from, &to);
        }
        self.clear_journal()
    }

    /// Save pending list changes if the oldest has waited [`SAVE_DELAY`].
    /// Mount adapters call this a few times a second; each change calls it
    /// too.
    pub fn tick(&mut self) -> io::Result<()> {
        match self.dirs.oldest_unsaved() {
            Some(t) if t.elapsed() >= SAVE_DELAY => self.sync(),
            _ => Ok(()),
        }
    }

    /// Save every pending directory-list change now, then delete from the
    /// disk what those changes removed.
    ///
    /// Crash safety: each list is written atomically, so after a crash every
    /// directory shows either its saved or its newer list. Deletions wait
    /// until the list no longer names the entry, so a crash can't leave a name
    /// pointing at nothing; they are journaled, so a crash part-way still
    /// finishes them. A file created just before a crash whose list wasn't
    /// saved yet stays on disk unnamed, as unflushed data does on any disk.
    pub fn sync(&mut self) -> io::Result<()> {
        self.write_unwritten()?;
        let doomed = std::mem::take(&mut self.doomed);
        let purge = Journal::Purge {
            items: doomed.iter().map(|(d, b)| (self.rel(d), b.clone())).collect(),
        };
        let mut result = Ok(());
        if !doomed.is_empty() {
            result = self.write_journal(&purge);
        }
        if result.is_ok() {
            result = self.dirs.flush(&self.keys);
        }
        if let Err(e) = result {
            self.doomed.splice(0..0, doomed);
            return Err(e);
        }
        if doomed.is_empty() {
            return Ok(());
        }
        // Windows won't delete a file or folder with a file open in it.
        for (d, b) in &doomed {
            let gone = d.join(b);
            self.handles.retain(|p, _| !p.starts_with(&gone));
            self.envelopes.retain(|p, _| !p.starts_with(&gone));
            readers_mut(&mut self.readers).retain(|p, _| !p.starts_with(&gone));
            self.durable_len.retain(|p, _| !p.starts_with(&gone));
        }
        self.apply(&purge)?;
        self.clear_journal()
    }

    /// Finish (or, for `Undo`, roll back) a journaled change left by a crash.
    /// A journal that doesn't decrypt or parse was torn while being written,
    /// before anything it describes had started, so it's just dropped.
    fn recover(&self) -> io::Result<()> {
        let path = self.backing_dir.join(JOURNAL);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(());
        };
        let opened = crypto::open(&self.key, JOURNAL_LABEL, &bytes);
        if let Some(j) = opened.ok().and_then(|b| serde_json::from_slice::<Journal>(&b).ok()) {
            self.apply(&j)?;
        }
        self.clear_journal()
    }

    /// Carry out a journaled change. Every step checks before acting, so
    /// running it again after a crash part-way through is harmless.
    fn apply(&self, j: &Journal) -> io::Result<()> {
        match j {
            Journal::Purge { items } => {
                for (dir, boring) in items {
                    let dir = self.abs(dir);
                    // Still listed means the save that dropped it never happened.
                    if dir.is_dir() && !self.dir(&dir)?.has_boring(boring) {
                        delete_entry(&dir.join(boring))?;
                        durable::sync_dir(&dir)?;
                    }
                }
                Ok(())
            }
            Journal::Move { from_dir, from_boring, to_dir, child, replaced } => {
                let (from_dir, to_dir) = (self.abs(from_dir), self.abs(to_dir));
                if let Some(r) = replaced {
                    delete_entry(&to_dir.join(r))?;
                }
                let (from, to) = (from_dir.join(from_boring), to_dir.join(&child.boring));
                if from != to && from.exists() && !to.exists() {
                    std::fs::rename(&from, &to)?;
                }
                // Destination first: until the source entry goes, a crash
                // leaves the item listed twice at worst, never not at all.
                let same = from_dir == to_dir;
                self.dirs.edit(&to_dir, &self.keys, |d| {
                    let gone = [Some(&child.boring), replaced.as_ref(), same.then_some(from_boring)];
                    for b in gone.into_iter().flatten() {
                        if let Some(p) = d.position_of_boring(b) {
                            d.remove(p);
                        }
                    }
                    d.push(child.clone());
                })?;
                self.dirs.flush_dir(&to_dir, &self.keys)?;
                if !same {
                    self.dirs.edit(&from_dir, &self.keys, |d| {
                        if let Some(p) = d.position_of_boring(from_boring) {
                            d.remove(p);
                        }
                    })?;
                    self.dirs.flush_dir(&from_dir, &self.keys)?;
                }
                durable::sync_dir(&to_dir)?;
                durable::sync_dir(&from_dir)
            }
            Journal::Undo { blob, len, ranges } => restore(&self.abs(blob), *len, ranges),
            Journal::Renonce { dir, boring, nonce, len, ranges } => {
                let dir = self.abs(dir);
                let done = dir.is_dir()
                    && self.dir(&dir)?.children().iter().any(|c| c.boring == *boring && c.nonce == *nonce);
                if done {
                    Ok(())
                } else {
                    restore(&dir.join(boring), *len, ranges)
                }
            }
        }
    }

    /// Merge sync-conflict copies of every manifest in the store.
    fn merge_all_conflicts(&self) -> io::Result<()> {
        let mut dirs = vec![self.backing_dir.clone()];
        while let Some(dir) = dirs.pop() {
            manifest::merge_conflicts(&dir, &self.keys)?;
            for e in std::fs::read_dir(&dir)?.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    dirs.push(e.path());
                }
            }
        }
        Ok(())
    }
}

impl Drop for Store {
    /// Save what's pending (unmounting, or a CLI command finishing). Errors
    /// can't be reported here; callers that care call [`Store::sync`] first.
    fn drop(&mut self) {
        let _ = self.sync();
    }
}

/// The reader map, given exclusive access (no locking needed).
fn readers_mut(
    r: &mut Mutex<HashMap<PathBuf, Arc<std::fs::File>>>,
) -> &mut HashMap<PathBuf, Arc<std::fs::File>> {
    r.get_mut().unwrap_or_else(PoisonError::into_inner)
}

/// Read exactly `buf.len()` bytes at `offset` without moving a shared file
/// position, so reads on several threads can share one handle.
fn read_exact_at(f: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match f.seek_read(&mut buf[done..], offset + done as u64)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => done += n,
            }
        }
        Ok(())
    }
}

/// Write all of `buf` at `offset` in as few calls as the OS allows.
fn write_all_at(f: &std::fs::File, buf: &[u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match f.seek_write(&buf[done..], offset + done as u64)? {
                0 => return Err(io::ErrorKind::WriteZero.into()),
                n => done += n,
            }
        }
        Ok(())
    }
}

fn plausible(l: &[u8; lock::LEN]) -> bool {
    lock::plausible(l)
}

/// Is `name` one of the list files of the drive with `keys`?
fn is_other_list(keys: &Keys, name: &str) -> bool {
    manifest::is_list_file(&keys.master, name) || manifest::is_conflict_copy(&keys.master, name)
}

/// Does anything in the disk folder `dir` carry a drive's lock?
fn carries_a_lock(dir: &Path) -> bool {
    first_lock_in(dir).is_some()
}

/// The first lock found in the disk folder `dir` or below.
fn first_lock_in(dir: &Path) -> Option<[u8; lock::LEN]> {
    let mut folders = vec![dir.to_path_buf()];
    while let Some(f) = folders.pop() {
        for e in std::fs::read_dir(&f).ok()?.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => folders.push(e.path()),
                Ok(t) if t.is_file() => {
                    if let Some(l) = lock::lock_of_file(&e.path()).filter(plausible) {
                        return Some(l);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// The name given to a folder found without one.
const RECOVERED: &str = "Recovered folder";

/// A mutex's contents, even if a thread panicked while holding it.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Every entry of a disk folder with its metadata, from one scan (on
/// Windows the scan returns the metadata, with no call per entry). `None` if
/// the folder can't be read.
fn scan(folder: &Path) -> Option<HashMap<OsString, std::fs::Metadata>> {
    let rd = std::fs::read_dir(folder).ok()?;
    let mut found = HashMap::new();
    for e in rd.flatten() {
        if let Ok(m) = e.metadata() {
            found.insert(e.file_name(), m);
        }
    }
    Some(found)
}

/// Put `ranges` back into the file at `path` and make it `len` bytes long
/// (undoing a change that was journaled with them).
fn restore(path: &Path, len: u64, ranges: &[(u64, Vec<u8>)]) -> io::Result<()> {
    let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) else {
        return Ok(()); // deleted since; nothing to restore
    };
    f.set_len(max(len, ranges.iter().map(|(s, b)| s + b.len() as u64).max().unwrap_or(0)))?;
    for (s, bytes) in ranges {
        f.seek(SeekFrom::Start(*s))?;
        f.write_all(bytes)?;
    }
    f.set_len(len)?;
    f.sync_data()
}

/// A jump in a file's size at least this big is left as a hole.
const SPARSE_MIN: u64 = 1 << 20;

/// Mark a file sparse (or not). Only Windows needs it: elsewhere a file grows
/// with a hole anyway.
#[cfg(windows)]
fn set_sparse(f: &std::fs::File, sparse: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;
    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            device: *mut std::ffi::c_void,
            code: u32,
            input: *const std::ffi::c_void,
            input_len: u32,
            output: *mut std::ffi::c_void,
            output_len: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }
    let flag: u8 = sparse.into(); // FILE_SET_SPARSE_BUFFER
    let mut returned = 0u32;
    // SAFETY: a valid open handle, a 1-byte input buffer that outlives the
    // call, no output, and a synchronous handle (no OVERLAPPED).
    let ok = unsafe {
        DeviceIoControl(
            f.as_raw_handle(),
            FSCTL_SET_SPARSE,
            (&flag as *const u8).cast(),
            1,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_sparse(_: &std::fs::File, _: bool) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// A file's data length: its length on disk less its envelope.
fn data_len(f: &std::fs::File) -> io::Result<u64> {
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(0); // a new file, empty, its envelope not written yet
    }
    len.checked_sub(ENVELOPE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a file in the drive is damaged (too short)"))
}

/// A boring file's folder and name.
fn split_blob(blob: &Path) -> io::Result<(PathBuf, String)> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "not a file in the drive");
    let dir = blob.parent().ok_or_else(bad)?.to_path_buf();
    let name = blob.file_name().and_then(|n| n.to_str()).ok_or_else(bad)?.to_string();
    Ok((dir, name))
}

/// Does `[lo, hi)` meet any of `ranges`?
fn overlaps(ranges: &[(u64, u64)], lo: u64, hi: u64) -> bool {
    ranges.iter().any(|&(s, e)| s < hi && lo < e)
}

/// Delete a boring file or directory if it's there.
fn delete_entry(path: &Path) -> io::Result<()> {
    let result = match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(_) => return Ok(()),
    };
    match result {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The parts of `ranges` inside `[lo, hi)`.
fn clip(ranges: &[(u64, u64)], lo: u64, hi: u64) -> Vec<(u64, u64)> {
    ranges
        .iter()
        .map(|&(s, e)| (max(s, lo), min(e, hi)))
        .filter(|(s, e)| s < e)
        .collect()
}

/// The parts of `ranges` outside `[lo, hi)`.
fn subtract(ranges: &[(u64, u64)], lo: u64, hi: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(s, e) in ranges {
        if hi <= s || e <= lo || lo >= hi {
            out.push((s, e));
            continue;
        }
        if s < lo {
            out.push((s, lo));
        }
        if hi < e {
            out.push((hi, e));
        }
    }
    out
}

/// Ranges below `limit` that are encrypted at one size and plain at the other.
fn toggled(old: u64, new: u64, n: u64, limit: u64) -> Vec<(u64, u64)> {
    let (a, b) = (protected_ranges(old, n), protected_ranges(new, n));
    let inside = |r: &[(u64, u64)], x: u64| r.iter().any(|&(s, e)| s <= x && x < e);
    let mut cuts: Vec<u64> = a.iter().chain(&b).flat_map(|&(s, e)| [s, e]).collect();
    cuts.extend([0, limit]);
    cuts.retain(|&c| c <= limit);
    cuts.sort_unstable();
    cuts.dedup();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for w in cuts.windows(2) {
        let (s, e) = (w[0], w[1]);
        if inside(&a, s) != inside(&b, s) {
            match out.last_mut() {
                Some(last) if last.1 == s => last.1 = e,
                _ => out.push((s, e)),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dircache::read_listing;
    use tempfile::tempdir;

    fn store(dir: &Path) -> Store {
        Store::open(dir, [9u8; 32], 128).unwrap()
    }

    #[test]
    fn nested_create_read_roundtrip() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("Documents").unwrap();
        s.mkdir("Documents/Taxes").unwrap();
        s.create("Documents/Taxes/Return.pdf").unwrap();
        let payload: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        s.write_at("Documents/Taxes/Return.pdf", 0, &payload).unwrap();

        assert_eq!(s.read_all("Documents/Taxes/Return.pdf").unwrap(), payload);
        // Listing shows real names at each level.
        assert_eq!(s.list(), vec!["Documents".to_string()]);
        let taxes = s.list_dir("Documents/Taxes").unwrap();
        assert_eq!(taxes.len(), 1);
        assert_eq!(taxes[0].0, "Return.pdf");
        assert!(!taxes[0].1);
    }

    #[test]
    fn on_disk_leaks_no_real_names() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("SecretFolder").unwrap();
        s.create("SecretFolder/Passwords.txt").unwrap();
        s.write_at("SecretFolder/Passwords.txt", 0, b"hunter2").unwrap();

        // Walk every path under the backing dir; no real name may appear as a
        // file/dir name (manifests are encrypted, blobs/dirs are boring).
        for entry in walkdir(d.path()) {
            let name = entry.file_name().unwrap().to_string_lossy().to_string();
            assert!(name != "SecretFolder" && name != "Passwords.txt");
        }
    }

    fn walkdir(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(p) = stack.pop() {
            if p.is_dir() {
                for e in std::fs::read_dir(&p).unwrap() {
                    let e = e.unwrap().path();
                    out.push(e.clone());
                    stack.push(e);
                }
            }
        }
        out
    }

    #[test]
    fn rename_in_place_file_and_folder() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("A").unwrap();
        s.create("A/old.txt").unwrap();
        s.write_at("A/old.txt", 0, b"data").unwrap();

        s.rename_path("A/old.txt", "A/new.txt").unwrap();
        assert!(s.read_all("A/old.txt").is_err());
        assert_eq!(s.read_all("A/new.txt").unwrap(), b"data");

        s.rename_path("A", "B").unwrap();
        assert_eq!(s.read_all("B/new.txt").unwrap(), b"data");
    }

    #[test]
    fn case_insensitive_lookup_and_rename() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("Hello").unwrap();
        s.create("Hello/Note.txt").unwrap();
        // Lookups fold case (like a Windows/macOS drive).
        assert!(s.metadata("hello").unwrap().unwrap().is_dir);
        assert!(s.metadata("HELLO/note.TXT").unwrap().is_some());
        // Rename with an uppercased source — what Windows sends on rename.
        s.rename_path("HELLO", "World").unwrap();
        // Case is preserved in storage, so it lists as "World".
        assert_eq!(s.list(), vec!["World".to_string()]);
        assert!(s.metadata("world/note.txt").unwrap().is_some());
    }

    #[test]
    fn move_folder_across_parents_keeps_subtree() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("src").unwrap();
        s.mkdir("src/inner").unwrap();
        s.create("src/inner/file.bin").unwrap();
        let payload: Vec<u8> = (0..500u32).map(|i| (i * 3) as u8).collect();
        s.write_at("src/inner/file.bin", 0, &payload).unwrap();
        s.mkdir("dst").unwrap();

        // Move the whole `inner` subtree under `dst`.
        s.rename_path("src/inner", "dst/inner").unwrap();
        assert!(s.read_all("src/inner/file.bin").is_err());
        assert_eq!(s.read_all("dst/inner/file.bin").unwrap(), payload);
    }

    #[test]
    fn remove_file_and_folder() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("dir").unwrap();
        s.create("dir/a.bin").unwrap();
        s.remove("dir/a.bin").unwrap();
        assert!(s.list_dir("dir").unwrap().is_empty());
        s.remove("dir").unwrap();
        assert!(s.list().is_empty());
    }

    #[test]
    fn fast_path_middle_write_survives_reopen() {
        let d = tempdir().unwrap();
        {
            let mut s = store(d.path());
            s.create("big.bin").unwrap();
            let orig: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
            s.write_at("big.bin", 0, &orig).unwrap();
            s.write_at("big.bin", 1000, &[0xAB; 10]).unwrap(); // middle, fast path
        }
        let s = store(d.path());
        let out = s.read_all("big.bin").unwrap();
        assert_eq!(&out[1000..1010], &[0xAB; 10]);
        assert_eq!(out.len(), 3000);
    }

    #[test]
    fn create_open_wrong_password_and_missing() {
        let d = tempdir().unwrap();
        {
            let mut s = Store::create_with_passphrase(d.path(), "right", 64).unwrap();
            s.mkdir("vault").unwrap();
            s.create("vault/note.txt").unwrap();
            s.write_at("vault/note.txt", 0, b"top secret contents").unwrap();
        }
        // Creating again where a drive already exists must fail (never clobber).
        assert!(Store::create_with_passphrase(d.path(), "right", 64).is_err());

        // Right password opens and reads.
        let good = Store::open_with_passphrase(d.path(), "right").unwrap();
        assert_eq!(good.read_all("vault/note.txt").unwrap(), b"top secret contents");

        // Wrong password is rejected up front by the verifier.
        let bad = Store::open_with_passphrase(d.path(), "wrong");
        assert_eq!(bad.err().map(|e| e.kind()), Some(io::ErrorKind::PermissionDenied));

        // Opening where no drive exists errors.
        let empty = tempdir().unwrap();
        assert_eq!(
            Store::open_with_passphrase(empty.path(), "x").err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn a_drive_folder_has_no_plain_text_and_old_formats_are_named() {
        let d = tempdir().unwrap();
        {
            let mut s = Store::create_with_passphrase(d.path(), "right", 64).unwrap();
            s.mkdir("Docs").unwrap();
            s.create("Docs/note.txt").unwrap();
            s.write_at("Docs/note.txt", 0, b"kept").unwrap();
        }
        // No meta.json, no manifest.idx, nothing readable: dull names only.
        let mut all = Vec::new();
        let mut folders = vec![d.path().to_path_buf()];
        while let Some(f) = folders.pop() {
            for e in std::fs::read_dir(&f).unwrap().flatten() {
                if e.file_type().unwrap().is_dir() {
                    folders.push(e.path());
                } else {
                    let bytes = std::fs::read(e.path()).unwrap();
                    assert!(!bytes.starts_with(b"{"), "{:?} looks like plain JSON", e.file_name());
                }
                all.push(e.file_name().to_string_lossy().into_owned());
            }
        }
        assert!(all.iter().all(|n| n.contains('_') && n != "manifest.idx" && n != "meta.json"), "{all:?}");
        let s = Store::open_with_passphrase(d.path(), "right").unwrap();
        assert_eq!(s.read_all("Docs/note.txt").unwrap(), b"kept");
        assert_eq!(Store::open_with_passphrase(d.path(), "wrong").err().map(|e| e.kind()), Some(io::ErrorKind::PermissionDenied));
        drop(s);

        // A folder with no drive, and one from an earlier format.
        let empty = tempdir().unwrap();
        assert_eq!(Store::open_with_passphrase(empty.path(), "x").err().map(|e| e.kind()), Some(io::ErrorKind::NotFound));
        std::fs::write(empty.path().join("meta.json"), br#"{"version":2}"#).unwrap();
        let err = Store::open_with_passphrase(empty.path(), "x").err().unwrap();
        assert!(err.to_string().contains("earlier test version"), "{err}");
    }

    // ---- cross-platform names ---------------------------------------------

    #[test]
    fn macos_nfd_and_windows_nfc_are_one_file() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        // Created from macOS (decomposed é)...
        s.mkdir("Caf\u{65}\u{301}").unwrap();
        s.create("Caf\u{65}\u{301}/r\u{e9}sum\u{65}\u{301}.txt").unwrap();
        s.write_at("Cafe\u{301}/re\u{301}sume\u{301}.txt", 0, b"x").unwrap();
        // ...is stored composed, and found by the composed (Windows) spelling.
        assert_eq!(s.list(), vec!["Caf\u{e9}".to_string()]);
        assert_eq!(s.read_all("Caf\u{e9}/r\u{e9}sum\u{e9}.txt").unwrap(), b"x");
        // And it can't be created a second time in the other form.
        assert!(s.mkdir("Caf\u{e9}").is_err());
        assert_eq!(s.list_dir("Café").unwrap().len(), 1);
    }

    #[test]
    fn unicode_case_insensitive_lookup() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("Ärger.txt").unwrap();
        assert!(s.metadata("ärger.TXT").unwrap().is_some());
        assert_eq!(s.canonical_path("ÄRGER.txt").unwrap().unwrap(), "Ärger.txt");
    }

    #[test]
    fn backslash_is_part_of_a_name() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create(r"a\b.txt").unwrap();
        assert_eq!(s.list(), vec![r"a\b.txt".to_string()]);
        assert!(s.metadata("a").unwrap().is_none());
    }

    #[test]
    fn non_portable_names_are_refused() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        assert!(s.create(&"x".repeat(256)).is_err());
        assert!(s.mkdir(&"漢".repeat(100)).is_err()); // 300 bytes: too long for macOS
        assert!(s.create("ok.txt").is_ok());
        assert!(s.rename_path("ok.txt", &"y".repeat(300)).is_err());
        assert!(s.create("..").is_err());
    }

    #[test]
    fn case_only_rename() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("dir").unwrap();
        s.create("dir/report.txt").unwrap();
        s.rename_path("dir/report.txt", "dir/Report.TXT").unwrap();
        s.rename_path("dir", "DIR").unwrap();
        assert_eq!(s.list(), vec!["DIR".to_string()]);
        assert_eq!(s.list_dir("dir").unwrap()[0].0, "Report.TXT");
    }

    #[test]
    fn save_by_rename_over_existing_file() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("doc.txt").unwrap();
        s.write_at("doc.txt", 0, b"old").unwrap();
        s.create("doc.txt.tmp").unwrap();
        s.write_at("doc.txt.tmp", 0, b"new contents").unwrap();

        assert_eq!(
            s.rename_path("doc.txt.tmp", "doc.txt").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        s.rename_replace("doc.txt.tmp", "doc.txt").unwrap();
        assert_eq!(s.list(), vec!["doc.txt".to_string()]);
        assert_eq!(s.read_all("doc.txt").unwrap(), b"new contents");

        // Across directories too.
        s.mkdir("sub").unwrap();
        s.create("sub/doc.txt").unwrap();
        s.rename_replace("doc.txt", "sub/doc.txt").unwrap();
        assert!(s.list().iter().all(|n| n != "doc.txt"));
        assert_eq!(s.read_all("sub/doc.txt").unwrap(), b"new contents");
    }

    #[test]
    fn rename_replace_guards_directories() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("full").unwrap();
        s.create("full/keep.txt").unwrap();
        s.mkdir("empty").unwrap();
        s.mkdir("src").unwrap();
        s.create("file.txt").unwrap();

        let kind = |r: io::Result<()>| r.unwrap_err().kind();
        assert_eq!(kind(s.rename_replace("src", "full")), io::ErrorKind::DirectoryNotEmpty);
        assert_eq!(kind(s.rename_replace("file.txt", "empty")), io::ErrorKind::IsADirectory);
        assert_eq!(kind(s.rename_replace("src", "file.txt")), io::ErrorKind::NotADirectory);
        assert!(s.metadata("full/keep.txt").unwrap().is_some());

        s.rename_replace("src", "empty").unwrap();
        let mut names: Vec<String> = s.list();
        names.sort();
        assert_eq!(names, vec!["empty", "file.txt", "full"]);
    }

    #[test]
    fn times_come_from_disk_and_can_be_set() {
        use std::time::Duration;
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("dir").unwrap();
        s.create("dir/a.txt").unwrap();
        s.write_at("dir/a.txt", 0, b"hello").unwrap();

        // A fresh file carries a real, recent time rather than the epoch.
        let m = s.metadata("dir/a.txt").unwrap().unwrap();
        let age = SystemTime::now().duration_since(m.modified).unwrap_or_default();
        assert!(age < Duration::from_secs(60), "modified time should be now");
        assert!(s.metadata("").unwrap().unwrap().modified > UNIX_EPOCH);

        // Dates set through the store stick, on files and on directories, and
        // show in listings too.
        let then = UNIX_EPOCH + Duration::from_secs(1_500_000_000);
        let earlier = UNIX_EPOCH + Duration::from_secs(1_400_000_000);
        s.set_times("DIR/A.TXT", Some(then), Some(then), Some(earlier)).unwrap();
        s.set_times("dir", None, Some(earlier), None).unwrap();
        let m = s.metadata("dir/a.txt").unwrap().unwrap();
        assert_eq!(m.modified, then);
        assert_eq!(m.accessed, then);
        #[cfg(any(windows, target_os = "macos"))]
        assert_eq!(m.created, earlier);
        assert_eq!(s.metadata("dir").unwrap().unwrap().modified, earlier);
        assert_eq!(s.list_dir_meta("dir").unwrap()[0].1, m);

        // A missing path is an error, not a silent no-op.
        assert!(s.set_times("dir/nope", None, Some(then), None).is_err());
    }

    /// The blob on disk must be byte-for-byte what encrypting the ends of the
    /// whole plaintext with the file's key would give, followed by an
    /// envelope that describes it, after any mix of writes and resizes.
    fn assert_disk_matches(s: &Store, name: &str, plain: &[u8]) {
        assert_eq!(s.read_all(name).unwrap(), plain, "read back differs");
        let manifest = s.dirs.load(&s.backing_dir, &s.keys).unwrap();
        let child = manifest.find(name).unwrap();
        let mut want = plain.to_vec();
        crate::crypto::transform_ends(&child.key, &child.nonce, &mut want, s.region);
        let disk = std::fs::read(s.backing_dir.join(&child.boring)).unwrap();
        assert_eq!(disk.len(), want.len() + ENVELOPE as usize, "length at size {}", plain.len());
        assert!(disk[..want.len()] == want, "disk form differs at size {}", plain.len());
        let env = Envelope::open(&s.key, &disk[want.len()..]).expect("an envelope this drive opens");
        assert_eq!((env.id, env.key, env.nonce), (child.id, child.key, child.nonce));
    }

    #[test]
    fn incremental_writes_match_full_reencryption() {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        let d = tempdir().unwrap();
        let mut s = store(d.path()); // 128-byte ends
        s.create("f").unwrap();
        let mut plain: Vec<u8> = Vec::new();
        let mut rng = StdRng::seed_from_u64(7);
        for step in 0..3000 {
            let len = plain.len();
            match rng.gen_range(0..10) {
                // Writes anywhere, including past the end (a gap of zeros).
                0..=5 => {
                    let off = rng.gen_range(0..=len + 300);
                    let n = rng.gen_range(0..400);
                    let data: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
                    s.write_at("f", off as u64, &data).unwrap();
                    if plain.len() < off + n {
                        plain.resize(off + n, 0);
                    }
                    plain[off..off + n].copy_from_slice(&data);
                }
                // Appends, the common case for a copy.
                6..=7 => {
                    let data: Vec<u8> = (0..rng.gen_range(1..300)).map(|_| rng.gen()).collect();
                    s.write_at("f", len as u64, &data).unwrap();
                    plain.extend_from_slice(&data);
                }
                // Shrink or grow.
                _ => {
                    let new = rng.gen_range(0..=len + 400);
                    s.truncate("f", new as u64).unwrap();
                    plain.resize(new, 0);
                }
            }
            if step % 7 == 0 || plain.len() < 600 {
                assert_disk_matches(&s, "f", &plain);
            }
        }
        assert_disk_matches(&s, "f", &plain);
    }

    #[test]
    fn appending_leaves_the_middle_alone() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("big").unwrap();
        let chunk = vec![0xABu8; 1000];
        for i in 0..20 {
            s.write_at("big", i * 1000, &chunk).unwrap();
        }
        let plain = vec![0xABu8; 20_000];
        assert_disk_matches(&s, "big", &plain);
        let child = s.dirs.load(&s.backing_dir, &s.keys).unwrap().find("big").unwrap().clone();
        let disk = std::fs::read(s.backing_dir.join(&child.boring)).unwrap();
        assert!(disk[128..20_000 - 128].iter().all(|&b| b == 0xAB), "middle is plaintext");
        assert_ne!(&disk[..128], &plain[..128]);
        assert_ne!(&disk[20_000 - 128..], &plain[20_000 - 128..]);
    }

    #[test]
    fn range_helpers() {
        assert_eq!(clip(&[(0, 10), (20, 30)], 5, 25), vec![(5, 10), (20, 25)]);
        assert_eq!(subtract(&[(0, 10), (20, 30)], 5, 25), vec![(0, 5), (25, 30)]);
        assert_eq!(subtract(&[(0, 10)], 3, 3), vec![(0, 10)]);
        // 200 bytes is all one end (<= 2*128); at 1000 only [0,128) and [872,1000).
        assert_eq!(toggled(200, 1000, 128, 200), vec![(128, 200)]);
        assert_eq!(toggled(1000, 200, 128, 200), vec![(128, 200)]);
        assert_eq!(toggled(1000, 1100, 128, 1000), vec![(872, 972)]);
        assert_eq!(toggled(100, 300, 128, 100), vec![]);
    }

    /// Reopen a store as after a crash: unsaved list changes are lost, and
    /// opening finishes whatever the journal says.
    fn reopen(mut s: Store) -> Store {
        let (dir, key, region) = (s.backing_dir.clone(), s.key, s.region);
        s.dirs = DirCache::default();
        s.doomed.clear();
        drop(s);
        Store::open(dir, key, region).unwrap()
    }

    #[test]
    fn crash_mid_move_is_finished_on_open() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("a").unwrap();
        s.mkdir("b").unwrap();
        s.create("a/f.txt").unwrap();
        s.write_at("a/f.txt", 0, b"payload").unwrap();
        s.create("b/g.txt").unwrap();

        // Journal a move of a/f.txt over b/g.txt, then "crash" after only the
        // disk rename happened.
        s.sync().unwrap();
        let a_disk = s.resolve_dir(&["a".into()]).unwrap();
        let b_disk = s.resolve_dir(&["b".into()]).unwrap();
        let mut child = s.dirs.load(&a_disk, &s.keys).unwrap().find("f.txt").unwrap().clone();
        let from_boring = child.boring.clone();
        let replaced = s.dirs.load(&b_disk, &s.keys).unwrap().find("g.txt").unwrap().boring.clone();
        child.boring = "cache_0042.dat".into();
        child.real = "g.txt".into();
        s.write_journal(&Journal::Move {
            from_dir: s.rel(&a_disk),
            from_boring: from_boring.clone(),
            to_dir: s.rel(&b_disk),
            child,
            replaced: Some(replaced),
        })
        .unwrap();
        std::fs::rename(a_disk.join(&from_boring), b_disk.join("cache_0042.dat")).unwrap();

        let s = reopen(s);
        assert!(s.list_dir("a").unwrap().is_empty());
        assert_eq!(s.list_dir("b").unwrap().len(), 1);
        assert_eq!(s.read_all("b/g.txt").unwrap(), b"payload");
        assert!(!d.path().join(JOURNAL).exists());
        // Only the moved file is left in b's folder on disk (plus its manifest).
        assert_eq!(std::fs::read_dir(&b_disk).unwrap().count(), 2);
    }

    #[test]
    fn crash_mid_purge_is_finished_on_open() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("dir").unwrap();
        s.create("dir/inner.txt").unwrap();
        s.sync().unwrap();
        let boring = s.dirs.load(&s.backing_dir, &s.keys).unwrap().find("dir").unwrap().boring.clone();
        s.remove("dir").unwrap();

        // "Crash" after the list was saved but before the folder was deleted.
        let items = vec![(String::new(), boring.clone())];
        s.write_journal(&Journal::Purge { items }).unwrap();
        s.dirs.flush(&s.keys).unwrap();
        let s = reopen(s);
        assert!(s.metadata("dir").unwrap().is_none());
        assert!(!d.path().join(&boring).exists(), "no orphaned data left on disk");
    }

    #[test]
    fn crash_before_saving_loses_only_the_last_moment() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("old.txt").unwrap();
        s.write_at("old.txt", 0, b"kept").unwrap();
        s.create("doomed.txt").unwrap();
        s.sync().unwrap();
        let boring = s.dirs.load(&s.backing_dir, &s.keys).unwrap().find("doomed.txt").unwrap().boring.clone();

        // Unsaved when the crash comes: a delete, a rename and a create.
        s.remove("doomed.txt").unwrap();
        s.rename_path("old.txt", "new.txt").unwrap();
        s.create("fresh.txt").unwrap();
        assert!(s.metadata("doomed.txt").unwrap().is_none());

        let s = reopen(s);
        let mut names: Vec<String> = s.list_dir("").unwrap().into_iter().map(|e| e.0).collect();
        names.sort();
        // Back to the last save, consistently, except that the file created
        // just before the crash is still on disk with its envelope, so it's
        // found and taken back in.
        assert_eq!(names, ["doomed.txt", "fresh.txt", "old.txt"]);
        assert!(d.path().join(&boring).exists(), "an unsaved delete deletes nothing");
        assert_eq!(s.read_all("old.txt").unwrap(), b"kept");
    }

    #[test]
    fn changes_are_saved_after_the_delay() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("a.txt").unwrap();
        assert!(read_listing(d.path(), &s.keys).unwrap().children.is_empty());
        std::thread::sleep(SAVE_DELAY);
        s.tick().unwrap();
        assert_eq!(read_listing(d.path(), &s.keys).unwrap().children.len(), 1);
    }

    #[test]
    fn deletes_reach_the_disk_only_after_the_save() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("a.txt").unwrap();
        s.write_at("a.txt", 0, b"x").unwrap();
        s.sync().unwrap();
        let boring = s.dirs.load(&s.backing_dir, &s.keys).unwrap().find("a.txt").unwrap().boring.clone();
        s.remove("a.txt").unwrap();
        assert!(d.path().join(&boring).exists());
        // A new file may not take the name of one waiting to be deleted.
        for i in 0..200 {
            assert_ne!(s.create(&format!("n{i}")).unwrap(), boring);
        }
        s.sync().unwrap();
        assert!(!d.path().join(&boring).exists());
        assert!(!d.path().join(JOURNAL).exists());
    }

    #[test]
    fn big_folder_round_trip() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("big").unwrap();
        let n = crate::dircache::SPLIT_AT + 500;
        for i in 0..n {
            s.create(&format!("big/f{i}.txt")).unwrap();
        }
        s.rename_path("big/f3.txt", "big/three.txt").unwrap();
        s.remove("big/f4.txt").unwrap();
        s.rename_path("big/f5.txt", "f5-moved.txt").unwrap();
        drop(s);
        let s = store(d.path());
        assert_eq!(s.list_dir("big").unwrap().len(), n - 2);
        assert!(s.metadata("big/three.txt").unwrap().is_some());
        assert!(s.metadata("big/f4.txt").unwrap().is_none());
        assert!(s.metadata("f5-moved.txt").unwrap().is_some());
    }

    #[test]
    fn crash_mid_resize_rolls_back() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("db").unwrap();
        let original: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        s.write_at("db", 0, &original).unwrap();
        s.flush("db").unwrap();
        let (blob, _) = s.file_blob("db").unwrap();
        let before = std::fs::read(&blob).unwrap();

        // The append toggles the old tail; pretend the crash came right after,
        // with the journal still holding the original bytes.
        s.write_at("db", 1000, &[7u8; 500]).unwrap();
        s.write_journal(&Journal::Undo {
            blob: s.rel(&blob),
            len: 1000 + ENVELOPE,
            ranges: vec![(0, before.clone())],
        })
        .unwrap();
        let s = reopen(s);
        assert_eq!(s.read_all("db").unwrap(), original);
        assert_eq!(std::fs::read(&blob).unwrap(), before);
    }

    #[test]
    fn torn_journal_is_ignored() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("keep.txt").unwrap();
        s.sync().unwrap();
        std::fs::write(d.path().join(JOURNAL), b" not a journal").unwrap();
        let s = reopen(s);
        assert!(s.metadata("keep.txt").unwrap().is_some());
        assert!(!d.path().join(JOURNAL).exists());
    }

    #[test]
    fn appending_to_a_new_file_never_journals() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("copy.bin").unwrap();
        for i in 0..50u64 {
            s.write_at("copy.bin", i * 300, &[1u8; 300]).unwrap();
        }
        // The only journal ever written would have been cleared, so check the
        // tracking instead: everything written is above the durable length 0.
        let (blob, _) = s.file_blob("copy.bin").unwrap();
        assert_eq!(s.durable_len.get(&blob), Some(&0));
        s.flush("copy.bin").unwrap();
        assert!(s.durable_len.get(&blob).is_none());
        assert_disk_matches(&s, "copy.bin", &[1u8; 15_000]);
    }

    #[test]
    fn changes_from_another_writer_show_up() {
        // A sync tool bringing in another machine's edits looks, to this
        // store, like a second store writing the same folder.
        let d = tempdir().unwrap();
        let mut a = store(d.path());
        a.mkdir("docs").unwrap();
        a.create("docs/one.txt").unwrap();
        assert_eq!(a.list_dir("docs").unwrap().len(), 1);
        a.sync().unwrap();

        a.dirs = DirCache::with_recheck(Duration::ZERO); // see changes at once

        let mut b = store(d.path());
        b.create("docs/two.txt").unwrap();
        b.rename_path("docs/one.txt", "docs/uno.txt").unwrap();
        b.write_at("docs/two.txt", 0, b"hello").unwrap();
        b.sync().unwrap(); // saved, and synced across

        let mut names: Vec<String> = a.list_dir("docs").unwrap().into_iter().map(|e| e.0).collect();
        names.sort();
        assert_eq!(names, ["two.txt", "uno.txt"]);
        assert!(a.metadata("docs/one.txt").unwrap().is_none());
        assert_eq!(a.read_all("docs/two.txt").unwrap(), b"hello");
    }

    #[test]
    fn listing_metadata_matches_per_file_metadata() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("dir").unwrap();
        s.mkdir("dir/sub").unwrap();
        for i in 0..20 {
            s.create(&format!("dir/f{i}")).unwrap();
            s.write_at(&format!("dir/f{i}"), 0, &vec![7u8; i * 100]).unwrap();
            s.close(&format!("dir/f{i}"));
        }
        // One still open for writing, and growing.
        s.write_at("dir/f3", 300, &[1u8; 5000]).unwrap();
        let listed = s.list_dir_meta("dir").unwrap();
        assert_eq!(listed.len(), 21);
        for (name, m) in listed {
            let one = s.metadata(&format!("dir/{name}")).unwrap().unwrap();
            assert_eq!(m, one, "{name}");
        }
        assert!(s.list_dir_meta("dir/sub").unwrap().is_empty());
    }

    #[test]
    fn store_can_be_shared_across_threads() {
        fn shareable<T: Send + Sync>() {}
        shareable::<Store>();
    }

    #[test]
    fn open_files_follow_renames_and_moves() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("a").unwrap();
        s.mkdir("b").unwrap();
        s.create("a/f.txt").unwrap();
        let id = s.open_file("a/f.txt").unwrap();
        s.write_file(id, 0, b"hello").unwrap();
        s.rename_path("a/f.txt", "a/g.txt").unwrap();
        s.write_file(id, 5, b" world").unwrap();
        s.rename_path("a", "b/a2").unwrap(); // the folder moves, file and all
        s.write_file(id, 11, b"!").unwrap();
        assert_eq!(s.read_file(id, 0, 100).unwrap(), b"hello world!");
        assert_eq!(s.file_metadata(id).unwrap().size, 12);
        s.truncate_file(id, 5).unwrap();
        s.flush_file(id).unwrap();
        s.release_file(id);
        assert_eq!(s.read_all("b/a2/g.txt").unwrap(), b"hello");
        assert!(s.read_file(id, 0, 1).is_err(), "a released id is refused");
    }

    #[test]
    fn parallel_reads_see_the_right_bytes() {
        use std::sync::RwLock;
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        let mut ids = Vec::new();
        for i in 0..8u8 {
            let name = format!("f{i}");
            s.create(&name).unwrap();
            s.write_at(&name, 0, &vec![i; 50_000]).unwrap();
            ids.push(s.open_file(&name).unwrap());
        }
        let s = RwLock::new(s);
        std::thread::scope(|t| {
            for (i, &id) in ids.iter().enumerate() {
                let s = &s;
                t.spawn(move || {
                    for k in 0..200u64 {
                        let off = (k * 997) % 49_000;
                        let got = s.read().unwrap().read_file(id, off, 1000).unwrap();
                        assert!(got.iter().all(|&b| b == i as u8));
                    }
                });
            }
        });
    }

    // ---- format 2: keys, nonces, envelopes, strays -----------------------

    fn entry(s: &Store, folder: &Path, name: &str) -> Child {
        s.dirs.load(folder, &s.keys).unwrap().find(name).unwrap().clone()
    }

    #[test]
    fn each_file_has_its_own_key_and_an_envelope() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        for name in ["a.txt", "b.txt"] {
            s.create(name).unwrap();
            s.write_at(name, 0, b"same contents").unwrap();
        }
        let (a, b) = (entry(&s, d.path(), "a.txt"), entry(&s, d.path(), "b.txt"));
        assert_ne!(a.key, b.key);
        assert_ne!(a.key, s.key, "file keys aren't the master key");
        let (ra, rb) = (std::fs::read(d.path().join(&a.boring)).unwrap(), std::fs::read(d.path().join(&b.boring)).unwrap());
        assert_ne!(ra[..13], rb[..13], "same contents, different ciphertext");
        let env = Envelope::read(&d.path().join(&a.boring), &s.key).unwrap();
        assert_eq!(env.name, "a.txt");
        assert_eq!(s.metadata("a.txt").unwrap().unwrap().size, 13, "the envelope isn't counted");
    }

    #[test]
    fn a_new_files_envelope_is_written_with_its_data_or_on_close() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("empty.txt").unwrap();
        s.create("full.txt").unwrap();
        let (e, f) = (entry(&s, d.path(), "empty.txt"), entry(&s, d.path(), "full.txt"));
        assert_eq!(std::fs::metadata(d.path().join(&e.boring)).unwrap().len(), 0, "not written at create");
        assert_eq!(s.metadata("empty.txt").unwrap().unwrap().size, 0);
        assert!(s.read_all("empty.txt").unwrap().is_empty());

        s.write_at("full.txt", 0, b"data").unwrap();
        assert_disk_matches(&s, "full.txt", b"data");
        s.close("empty.txt");
        let env = Envelope::read(&d.path().join(&e.boring), &s.key).unwrap();
        assert_eq!(env.name, "empty.txt");
        assert_disk_matches(&s, "empty.txt", b"");

        // One never closed gets its envelope when the drive saves.
        s.create("later.txt").unwrap();
        let l = entry(&s, d.path(), "later.txt");
        s.sync().unwrap();
        assert!(Envelope::read(&d.path().join(&l.boring), &s.key).is_ok());
        let _ = f;
    }

    #[test]
    fn a_file_from_a_drive_that_is_gone_comes_in_with_just_its_password() {
        let (d1, d2) = (tempdir().unwrap(), tempdir().unwrap());
        let mut a = Store::create_with_passphrase(d1.path(), "pass-a", 128).unwrap();
        a.create("letter.txt").unwrap();
        a.write_at("letter.txt", 0, b"dear diary").unwrap();
        a.sync().unwrap();
        let boring = entry(&a, d1.path(), "letter.txt").boring;
        drop(a);
        let mut b = Store::create_with_passphrase(d2.path(), "pass-b", 128).unwrap();
        b.sync().unwrap();
        drop(b);
        // The hidden file into B, and A's folder gone for good.
        std::fs::copy(d1.path().join(&boring), d2.path().join(&boring)).unwrap();
        drop(d1);

        let mut b = Store::open_with_passphrase(d2.path(), "pass-b").unwrap();
        assert!(b.list_dir("").unwrap().is_empty());
        assert_eq!(b.foreign_count(), 1);
        assert!(b.keys_for_strays("wrong").unwrap().is_empty());
        let keys = b.keys_for_strays("pass-a").unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(b.adopt_from(&keys[0]).unwrap(), (1, 0));
        assert_eq!(b.read_all("letter.txt").unwrap(), b"dear diary");
    }

    #[test]
    fn a_copy_that_sets_the_size_first_reads_back_and_leaves_a_hole() {
        // How Windows copies a file: its full size first, then the data in order.
        let d = tempdir().unwrap();
        let mut s = Store::create_with_passphrase(d.path(), "pw", 128).unwrap();
        let len = 5 * 1024 * 1024 + 777;
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + i / 4096) as u8).collect();
        s.create("big.bin").unwrap();
        let id = s.open_file("big.bin").unwrap();
        s.truncate_file(id, len as u64).unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let (blob, _) = s.opened(id).unwrap();
            assert_ne!(std::fs::metadata(&blob).unwrap().file_attributes() & 0x200, 0, "sparse");
        }
        assert_eq!(s.read_file(id, len as u64 - 10, 10).unwrap(), vec![0; 10], "unwritten reads as zeros");
        for (i, chunk) in data.chunks(1 << 20).enumerate() {
            s.write_file(id, (i << 20) as u64, chunk).unwrap();
        }
        s.release_file(id);
        assert_eq!(s.read_all("big.bin").unwrap(), data);
        drop(s);
        let s = Store::open_with_passphrase(d.path(), "pw").unwrap();
        assert_eq!(s.read_all("big.bin").unwrap(), data, "after reopening");
    }

    #[test]
    fn another_drives_files_copied_in_dont_take_over_the_drive() {
        let (d1, d2) = (tempdir().unwrap(), tempdir().unwrap());
        {
            let mut v1 = Store::create_with_passphrase(d1.path(), "test1", 128).unwrap();
            for i in 0..12 {
                let p = format!("f{i}.txt");
                v1.create(&p).unwrap();
                v1.write_at(&p, 0, p.as_bytes()).unwrap();
            }
        }
        drop(Store::create_with_passphrase(d2.path(), "test2", 128).unwrap());
        // v2 is empty; v1's hidden files (not its list) copied into it, so
        // v1's lock outnumbers v2's twelve to one.
        let v1_list = unlock(d1.path(), "test1").unwrap().list_name().to_string();
        for e in std::fs::read_dir(d1.path()).unwrap().flatten() {
            if e.file_name().to_string_lossy() != v1_list {
                std::fs::copy(e.path(), d2.path().join(e.file_name())).unwrap();
            }
        }

        let mut v2 = Store::open_with_passphrase(d2.path(), "test2").expect("v2's own password opens v2");
        assert!(v2.list_dir("").unwrap().is_empty());
        assert_eq!(v2.foreign_count(), 12, "v1's files wait");
        let err = Store::open_with_passphrase(d2.path(), "test1").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "v1's password isn't v2's: {err}");

        let keys = v2.keys_for_strays("test1").unwrap();
        assert_eq!(v2.adopt_from(&keys[0]).unwrap(), (12, 0));
        assert_eq!(v2.read_all("f3.txt").unwrap(), b"f3.txt");
        drop(v2);
        // Now they're v2's: v2's password still opens it, v1's still doesn't.
        assert!(Store::open_with_passphrase(d2.path(), "test2").is_ok());
        assert!(Store::open_with_passphrase(d2.path(), "test1").is_err());
    }

    #[test]
    fn a_password_change_relocks_everything() {
        let d = tempdir().unwrap();
        {
            let mut s = Store::create_with_passphrase(d.path(), "old", 128).unwrap();
            s.mkdir("Docs").unwrap();
            for p in ["a.txt", "Docs/b.txt"] {
                s.create(p).unwrap();
                s.write_at(p, 0, p.as_bytes()).unwrap();
            }
        }
        let mut seen = (0, 0);
        change_password(d.path(), "old", "new", &mut |n, t| seen = (n, t)).unwrap();
        assert_eq!(seen, (4, 4), "2 lists and 2 files");
        // Every lock in the drive is the new one.
        let mut folders = vec![d.path().to_path_buf()];
        while let Some(f) = folders.pop() {
            for e in std::fs::read_dir(&f).unwrap().flatten() {
                if e.file_type().unwrap().is_dir() {
                    folders.push(e.path());
                } else if let Some(l) = lock::lock_of_file(&e.path()) {
                    assert!(lock::unlock_one(&l, "new").is_ok(), "{:?}", e.file_name());
                    assert!(lock::unlock_one(&l, "old").is_err());
                }
            }
        }
        assert_eq!(Store::open_with_passphrase(d.path(), "old").err().map(|e| e.kind()), Some(io::ErrorKind::PermissionDenied));
        let s = Store::open_with_passphrase(d.path(), "new").unwrap();
        assert_eq!(s.read_all("Docs/b.txt").unwrap(), b"Docs/b.txt");
    }

    #[test]
    fn an_interrupted_password_change_is_finished_by_the_new_password() {
        let d = tempdir().unwrap();
        let file;
        {
            let mut s = Store::create_with_passphrase(d.path(), "old", 128).unwrap();
            s.create("a.txt").unwrap();
            s.write_at("a.txt", 0, b"A").unwrap();
            s.sync().unwrap();
            file = d.path().join(entry(&s, d.path(), "a.txt").boring);
        }
        // Stopped after the top list: its lock is new, the file's is old.
        let keys = unlock(d.path(), "old").unwrap().relocked("new").unwrap();
        let s = Store::open_with_keys(d.path(), keys.clone()).unwrap();
        durable::write_synced(&s.relock_marker(), b"").unwrap();
        let l = read_listing(d.path(), &keys).unwrap();
        write_listing(d.path(), &keys, l.name.as_deref(), &l.children, 0, &mut Vec::new(), None).unwrap();
        drop(s);
        assert!(lock::unlock_one(&lock::lock_of_file(&file).unwrap(), "old").is_ok());

        let err = Store::open_with_passphrase(d.path(), "old").err().unwrap();
        assert!(err.to_string().contains("password was changed"), "{err}");
        let s = Store::open_with_passphrase(d.path(), "new").unwrap();
        assert!(!s.relock_marker().exists(), "finished");
        assert!(lock::unlock_one(&lock::lock_of_file(&file).unwrap(), "new").is_ok());
        assert_eq!(s.read_all("a.txt").unwrap(), b"A");
    }

    #[test]
    fn a_drive_unlocks_without_its_top_list() {
        let d = tempdir().unwrap();
        {
            let mut s = Store::create_with_passphrase(d.path(), "pw", 128).unwrap();
            s.create("a.txt").unwrap();
            s.write_at("a.txt", 0, b"A").unwrap();
        }
        let keys = unlock(d.path(), "pw").unwrap();
        std::fs::remove_file(manifest::Manifest::path_in(d.path(), &keys)).unwrap();
        let s = Store::open_with_passphrase(d.path(), "pw").unwrap();
        assert_eq!(s.list_dir("").unwrap().into_iter().map(|e| e.0).collect::<Vec<_>>(), ["a.txt"]);
        assert_eq!(s.read_all("a.txt").unwrap(), b"A");
    }

    #[test]
    fn wrong_password_and_changing_it() {
        let d = tempdir().unwrap();
        {
            let mut s = Store::create_with_passphrase(d.path(), "first", 128).unwrap();
            s.create("note.txt").unwrap();
            s.write_at("note.txt", 0, b"kept").unwrap();
        }
        let wrong = Store::open_with_passphrase(d.path(), "nope").err().unwrap();
        assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);

        change_password(d.path(), "first", "second", &mut |_, _| {}).unwrap();
        assert!(Store::open_with_passphrase(d.path(), "first").is_err());
        let s = Store::open_with_passphrase(d.path(), "second").unwrap();
        assert_eq!(s.read_all("note.txt").unwrap(), b"kept", "files untouched");
        assert!(change_password(d.path(), "first", "x", &mut |_, _| {}).is_err());
    }

    #[test]
    fn an_edit_gets_a_fresh_nonce_and_appending_does_not() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("f").unwrap();
        let mut plain: Vec<u8> = (0..1000u32).map(|i| (i * 3) as u8).collect();
        s.write_at("f", 0, &plain).unwrap();
        s.close("f");
        let n0 = entry(&s, d.path(), "f").nonce;

        // Appending, in a new session: same nonce.
        s.write_at("f", 1000, b"more").unwrap();
        plain.extend_from_slice(b"more");
        assert_eq!(entry(&s, d.path(), "f").nonce, n0);
        assert_disk_matches(&s, "f", &plain);
        // Writing only the middle: same nonce.
        s.write_at("f", 500, b"mid").unwrap();
        plain[500..503].copy_from_slice(b"mid");
        assert_eq!(entry(&s, d.path(), "f").nonce, n0);
        s.close("f");

        // Changing a byte in an encrypted end: a new nonce, once per session.
        s.write_at("f", 3, b"X").unwrap();
        plain[3] = b'X';
        let n1 = entry(&s, d.path(), "f").nonce;
        assert_ne!(n1, n0);
        s.write_at("f", 4, b"Y").unwrap();
        plain[4] = b'Y';
        assert_eq!(entry(&s, d.path(), "f").nonce, n1, "one per session");
        assert_disk_matches(&s, "f", &plain);
        s.close("f");

        // Shortening: a new nonce. Emptying: a new one for what comes next.
        s.truncate("f", 900).unwrap();
        plain.truncate(900);
        let n2 = entry(&s, d.path(), "f").nonce;
        assert_ne!(n2, n1);
        assert_disk_matches(&s, "f", &plain);
        s.close("f");
        s.truncate("f", 0).unwrap();
        assert_ne!(entry(&s, d.path(), "f").nonce, n2);
        s.write_at("f", 0, b"new contents").unwrap();
        assert_disk_matches(&s, "f", b"new contents");

        let s = reopen(s);
        assert_eq!(s.read_all("f").unwrap(), b"new contents");
    }

    #[test]
    fn a_crash_mid_renonce_puts_the_file_back() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("f").unwrap();
        let plain: Vec<u8> = (0..700u32).map(|i| i as u8).collect();
        s.write_at("f", 0, &plain).unwrap();
        s.sync().unwrap();
        s.close("f");
        let c = entry(&s, d.path(), "f");
        let blob = d.path().join(&c.boring);
        let before = std::fs::read(&blob).unwrap();

        // The ends half re-encrypted, the list not yet saved: as a crash
        // would leave it, with the journal holding the original bytes.
        let mut torn = before.clone();
        for b in &mut torn[..64] {
            *b ^= 0x5a;
        }
        std::fs::write(&blob, &torn).unwrap();
        s.write_journal(&Journal::Renonce {
            dir: String::new(),
            boring: c.boring.clone(),
            nonce: envelope::new_nonce(),
            len: before.len() as u64,
            ranges: vec![(0, before.clone())],
        })
        .unwrap();
        let s = reopen(s);
        assert_eq!(std::fs::read(&blob).unwrap(), before);
        assert_eq!(s.read_all("f").unwrap(), plain);
    }

    #[test]
    fn a_file_moved_by_hand_within_the_drive_is_found() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("A").unwrap();
        s.mkdir("B").unwrap();
        s.create("A/report.pdf").unwrap();
        s.write_at("A/report.pdf", 0, b"quarterly numbers").unwrap();
        s.sync().unwrap();
        let (a, b) = (entry(&s, d.path(), "A"), entry(&s, d.path(), "B"));
        let file = entry(&s, &d.path().join(&a.boring), "report.pdf");

        std::fs::rename(d.path().join(&a.boring).join(&file.boring), d.path().join(&b.boring).join(&file.boring))
            .unwrap();
        let in_b: Vec<String> = s.list_dir("B").unwrap().into_iter().map(|e| e.0).collect();
        assert_eq!(in_b, ["report.pdf"]);
        assert!(s.list_dir("A").unwrap().is_empty(), "gone from where it was");
        assert_eq!(s.read_all("B/report.pdf").unwrap(), b"quarterly numbers");
        assert_eq!(s.foreign_count(), 0);

        // The lists' changes are saved like any other.
        s.sync().unwrap();
        let s = reopen(s);
        assert_eq!(s.read_all("B/report.pdf").unwrap(), b"quarterly numbers");
    }

    #[test]
    fn items_moved_out_are_remembered_until_they_return_or_are_dismissed() {
        let d = tempdir().unwrap();
        let away = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("Docs").unwrap();
        s.create("Docs/plan.txt").unwrap();
        s.write_at("Docs/plan.txt", 0, b"the plan").unwrap();
        s.mkdir("Docs/Old").unwrap();
        s.sync().unwrap();
        let docs = d.path().join(entry(&s, d.path(), "Docs").boring);
        let plan = entry(&s, &docs, "plan.txt").boring;
        let old = entry(&s, &docs, "Old").boring;

        // Moved out of the drive by hand: dropped, and remembered.
        std::fs::rename(docs.join(&plan), away.path().join(&plan)).unwrap();
        std::fs::rename(docs.join(&old), away.path().join(&old)).unwrap();
        assert!(s.list_dir("Docs").unwrap().is_empty());
        let mut gone: Vec<(String, bool)> = s.missing().into_iter().map(|m| (m.path, m.is_dir)).collect();
        gone.sort();
        assert_eq!(gone, [("Docs/Old".to_string(), true), ("Docs/plan.txt".to_string(), false)]);

        // Remembered across a lock and unlock.
        s.sync().unwrap();
        let s = reopen(s);
        assert_eq!(s.missing_count(), 2);

        // One comes back: it reappears and its record clears.
        std::fs::rename(away.path().join(&plan), docs.join(&plan)).unwrap();
        let names: Vec<String> = s.list_dir("Docs").unwrap().into_iter().map(|e| e.0).collect();
        assert_eq!(names, ["plan.txt"]);
        assert_eq!(s.missing().into_iter().map(|m| m.path).collect::<Vec<_>>(), ["Docs/Old"]);

        s.clear_missing().unwrap();
        assert_eq!(s.missing_count(), 0);
        assert!(!d.path().join(lock::names(&s.key).missing).exists());
    }

    #[test]
    fn moving_within_the_drive_is_not_missing_whichever_folder_is_seen_first() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("A").unwrap();
        s.mkdir("B").unwrap();
        s.create("A/f.txt").unwrap();
        s.sync().unwrap();
        let (a, b) = (d.path().join(entry(&s, d.path(), "A").boring), d.path().join(entry(&s, d.path(), "B").boring));
        let f = entry(&s, &a, "f.txt").boring;
        std::fs::rename(a.join(&f), b.join(&f)).unwrap();
        // The new folder first, then the old one.
        assert_eq!(s.list_dir("B").unwrap().len(), 1);
        assert!(s.list_dir("A").unwrap().is_empty());
        assert_eq!(s.missing_count(), 0);
    }

    #[test]
    fn a_lost_list_is_rebuilt_from_what_is_on_disk() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("Photos").unwrap();
        s.create("Photos/beach.jpg").unwrap();
        s.write_at("Photos/beach.jpg", 0, b"sand").unwrap();
        s.create("notes.txt").unwrap();
        s.write_at("notes.txt", 0, b"hello").unwrap();
        s.rename_path("Photos", "Holiday").unwrap();
        s.sync().unwrap();
        drop(s);
        std::fs::remove_file(manifest::Manifest::path_in(d.path(), &Keys::bare([9u8; 32], 128))).unwrap();

        let s = Store::open(d.path(), [9u8; 32], 128).unwrap();
        let mut top: Vec<String> = s.list_dir("").unwrap().into_iter().map(|e| e.0).collect();
        top.sort();
        assert_eq!(top, ["Holiday", "notes.txt"], "the folder kept its own name");
        assert_eq!(s.read_all("Holiday/beach.jpg").unwrap(), b"sand");
        assert_eq!(s.read_all("notes.txt").unwrap(), b"hello");
    }

    #[test]
    fn names_in_envelopes_catch_up_lazily() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("draft.txt").unwrap();
        s.write_at("draft.txt", 0, b"words").unwrap();
        s.close("draft.txt");
        s.rename_path("draft.txt", "final.txt").unwrap();
        let blob = d.path().join(entry(&s, d.path(), "final.txt").boring);
        assert_eq!(Envelope::read(&blob, &s.key).unwrap().name, "draft.txt", "a rename touches only the list");
        s.write_at("final.txt", 0, b"W").unwrap(); // an edit rewrites the envelope
        assert_eq!(Envelope::read(&blob, &s.key).unwrap().name, "final.txt");
    }

    /// A second drive in `dir`, with its own key.
    fn other_store(dir: &Path) -> Store {
        Store::open(dir, [8u8; 32], 128).unwrap()
    }

    #[test]
    fn files_from_another_drive_wait_until_brought_in() {
        let (d1, d2) = (tempdir().unwrap(), tempdir().unwrap());
        let mut one = other_store(d1.path());
        one.mkdir("Album").unwrap();
        one.create("Album/song.mp3").unwrap();
        one.write_at("Album/song.mp3", 0, &[3u8; 3000]).unwrap();
        one.create("a.doc").unwrap();
        one.write_at("a.doc", 0, b"letter").unwrap();
        one.sync().unwrap();
        let (album, doc) = (entry(&one, d1.path(), "Album"), entry(&one, d1.path(), "a.doc"));
        drop(one);

        // Both drives locked; the hidden file and folder moved by hand.
        let mut two = store(d2.path());
        two.create("mine.txt").unwrap();
        two.sync().unwrap();
        std::fs::rename(d1.path().join(&doc.boring), d2.path().join(&doc.boring)).unwrap();
        std::fs::rename(d1.path().join(&album.boring), d2.path().join(&album.boring)).unwrap();

        let names = |s: &Store| -> Vec<String> {
            let mut v: Vec<String> = s.list_dir("").unwrap().into_iter().map(|e| e.0).collect();
            v.sort();
            v
        };
        assert_eq!(names(&two), ["mine.txt"], "not shown, not deleted");
        assert_eq!(two.foreign_count(), 2);
        assert!(d2.path().join(&doc.boring).exists());

        // A look first: what would come in, and where, changing nothing.
        let (found, left) = two.preview_from(&[8u8; 32]).unwrap();
        let shown: Vec<(&str, bool, usize)> = found.iter().map(|f| (f.path.as_str(), f.is_dir, f.items)).collect();
        assert_eq!(shown, [("a.doc", false, 0), ("Album", true, 1)]);
        assert_eq!(left, 0);
        assert_eq!(two.preview_from(&[1u8; 32]).unwrap().1, 2, "the wrong key recognizes nothing");
        assert_eq!(names(&two), ["mine.txt"]);

        // The wrong drive's key brings nothing in.
        assert_eq!(two.adopt_from(&[1u8; 32]).unwrap(), (0, 2));
        assert_eq!(two.adopt_from(&[8u8; 32]).unwrap(), (2, 0));
        assert_eq!(names(&two), ["Album", "a.doc", "mine.txt"]);
        assert_eq!(two.read_all("a.doc").unwrap(), b"letter");
        assert_eq!(two.read_all("Album/song.mp3").unwrap(), vec![3u8; 3000]);
        assert_eq!(two.foreign_count(), 0);

        // They're this drive's now, through and through.
        let two = reopen(two);
        assert_eq!(two.read_all("Album/song.mp3").unwrap(), vec![3u8; 3000]);
        assert!(Envelope::read(&d2.path().join(&doc.boring), &[9u8; 32]).is_ok());
        let one = other_store(d1.path());
        assert!(one.list_dir("").unwrap().is_empty(), "and gone from the first drive's list");
    }

    #[test]
    fn an_unreadable_list_is_set_aside_and_rebuilt() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("Sub").unwrap();
        s.create("Sub/inner.txt").unwrap();
        s.write_at("Sub/inner.txt", 0, b"in").unwrap();
        s.create("x.txt").unwrap();
        s.write_at("x.txt", 0, b"ex").unwrap();
        s.sync().unwrap();
        let sub = d.path().join(entry(&s, d.path(), "Sub").boring);
        drop(s);
        // A changed byte in the top list, and the subfolder's list garbled.
        let path = manifest::Manifest::path_in(d.path(), &Keys::bare([9u8; 32], 128));
        let mut raw = std::fs::read(&path).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 1;
        std::fs::write(&path, raw).unwrap();
        std::fs::write(manifest::Manifest::path_in(&sub, &Keys::bare([9u8; 32], 128)), b"not a list").unwrap();

        let s = Store::open(d.path(), [9u8; 32], 128).unwrap();
        let mut top: Vec<String> = s.list_dir("").unwrap().into_iter().map(|e| e.0).collect();
        top.sort();
        // Both lists that knew the folder's name were unreadable.
        assert_eq!(top, [RECOVERED, "x.txt"]);
        assert_eq!(s.read_all(&format!("{RECOVERED}/inner.txt")).unwrap(), b"in");
        assert_eq!(s.repaired_count(), 2);
        let kept = |dir: &Path| {
            std::fs::read_dir(dir).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("unreadable-list-"))
        };
        assert!(kept(d.path()) && kept(&sub), "the unreadable lists are kept");
        assert_eq!(s.foreign_count(), 0, "set-aside lists aren't strays");
    }

    #[test]
    fn a_folder_whose_own_list_is_unreadable_keeps_its_name() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.mkdir("Sub").unwrap();
        s.create("Sub/inner.txt").unwrap();
        s.write_at("Sub/inner.txt", 0, b"in").unwrap();
        s.sync().unwrap();
        let sub = d.path().join(entry(&s, d.path(), "Sub").boring);
        drop(s);
        std::fs::write(manifest::Manifest::path_in(&sub, &Keys::bare([9u8; 32], 128)), b"not a list").unwrap();

        let mut s = Store::open(d.path(), [9u8; 32], 128).unwrap();
        assert_eq!(s.list_dir("Sub").unwrap().into_iter().map(|e| e.0).collect::<Vec<_>>(), ["inner.txt"]);
        assert_eq!(s.read_all("Sub/inner.txt").unwrap(), b"in");
        s.sync().unwrap();
        drop(s);
        assert_eq!(read_listing(&sub, &Keys::bare([9u8; 32], 128)).unwrap().name.as_deref(), Some("Sub"), "named from its parent");
    }

    #[test]
    fn another_drives_files_and_list_copied_in() {
        let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
        let mut a = other_store(da.path());
        a.create("from-a.txt").unwrap();
        a.write_at("from-a.txt", 0, b"A").unwrap();
        a.sync().unwrap();
        drop(a);
        let mut b = store(db.path());
        b.create("mine.txt").unwrap();
        b.write_at("mine.txt", 0, b"B").unwrap();
        b.sync().unwrap();
        drop(b);
        // Everything in A's folder copied into B's, its list replacing B's.
        for e in std::fs::read_dir(da.path()).unwrap().flatten() {
            if e.file_name() != "meta.json" {
                std::fs::copy(e.path(), db.path().join(e.file_name())).unwrap();
            }
        }

        // Lists have names worked out from each drive's key, so A's list
        // arrives beside B's rather than over it.
        let mut b = store(db.path());
        let names: Vec<String> = b.list_dir("").unwrap().into_iter().map(|e| e.0).collect();
        assert_eq!(names, ["mine.txt"]);
        assert_eq!(b.read_all("mine.txt").unwrap(), b"B");
        let (found, left) = b.preview_from(&[8u8; 32]).unwrap();
        assert_eq!((found.len(), left), (1, 0), "A's file, not A's list");
        assert_eq!(b.adopt_from(&[8u8; 32]).unwrap(), (1, 0));
        assert_eq!(b.read_all("from-a.txt").unwrap(), b"A");
        assert_eq!(b.foreign_count(), 0, "A's list is gone too");
    }
}
