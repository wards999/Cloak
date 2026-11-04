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
use crate::key::{self, SALT_LEN};
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
pub const FORMAT: u32 = 2;

const META_LABEL: &[u8] = b"cloak-meta-v2";
const JOURNAL_LABEL: &[u8] = b"cloak-journal-v2";

/// Store-wide metadata persisted at the backing root (reserved name, distinct
/// from a directory manifest).
#[derive(Serialize, Deserialize)]
struct StoreMeta {
    version: u32,
    salt: [u8; SALT_LEN],
    region: u64,
    /// The Argon2id settings the password's key is derived with.
    kdf: key::KdfParams,
    /// The master key, sealed with the password's key: a wrong password
    /// fails its check.
    wrapped: Vec<u8>,
}

fn parse_meta(meta: &[u8]) -> io::Result<StoreMeta> {
    let damaged = |e: String| io::Error::new(io::ErrorKind::InvalidData, format!("damaged drive header: {e}"));
    let value: serde_json::Value = serde_json::from_slice(meta).map_err(|e| damaged(e.to_string()))?;
    if value.get("version").and_then(|v| v.as_u64()) != Some(FORMAT as u64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "this drive was made by an earlier test version of cloak, which this version can't open",
        ));
    }
    serde_json::from_value(value).map_err(|e| damaged(e.to_string()))
}

/// The master key and region for `passphrase`, from the bytes of a store's
/// `meta.json`. `InvalidData` if they aren't a store header this version
/// reads, `PermissionDenied` if the passphrase is wrong.
pub fn key_from_meta(meta: &[u8], passphrase: &str) -> io::Result<(Key, u64)> {
    let meta = parse_meta(meta)?;
    let kek = key::derive_key(passphrase, &meta.salt, &meta.kdf)?;
    let master = crypto::open(&kek, META_LABEL, &meta.wrapped)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "wrong password"))?;
    let master: Key = master
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "damaged drive header: key"))?;
    Ok((master, meta.region))
}

/// `meta.json` for a drive with `master` key, protected by `passphrase`.
fn meta_for(master: &Key, passphrase: &str, region: u64) -> io::Result<Vec<u8>> {
    let salt = key::random_salt();
    let kdf = key::KdfParams::CURRENT;
    let kek = key::derive_key(passphrase, &salt, &kdf)?;
    let meta = StoreMeta { version: FORMAT, salt, region, kdf, wrapped: crypto::seal(&kek, META_LABEL, master) };
    Ok(serde_json::to_vec_pretty(&meta)?)
}

/// Write a new drive's `meta.json` into `backing_dir`: a new random master
/// key, wrapped for `passphrase`. Returns the master key.
pub(crate) fn write_new_meta(backing_dir: &Path, passphrase: &str, region: u64) -> io::Result<Key> {
    let master = envelope::new_key();
    durable::write_atomic(&backing_dir.join("meta.json"), &meta_for(&master, passphrase, region)?)?;
    Ok(master)
}

/// Change a drive's password: only `meta.json` changes (the master key is
/// wrapped again), so it takes a moment whatever the drive holds.
pub fn change_password(backing_dir: &Path, old: &str, new: &str) -> io::Result<()> {
    let path = backing_dir.join("meta.json");
    let (master, region) = key_from_meta(&std::fs::read(&path)?, old)?;
    durable::write_atomic(&path, &meta_for(&master, new, region)?)
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
    key: Key,
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
    /// Files and folders found in each folder that belong to another drive
    /// (see [`Store::check_folder`]).
    foreign: Mutex<HashMap<PathBuf, BTreeSet<String>>>,
    /// Each folder's modified time when last checked for strays.
    checked: Mutex<HashMap<PathBuf, SystemTime>>,
}

/// A file's key and its current content nonce.
type Crypt = (Key, Nonce);

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
    /// Open (or create) a store with a raw master key.
    pub fn open(backing_dir: impl AsRef<Path>, key: Key, region: u64) -> io::Result<Self> {
        let backing_dir = backing_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&backing_dir)?;
        let store = Self {
            backing_dir,
            key,
            region,
            durable_len: HashMap::new(),
            handles: HashMap::new(),
            readers: Default::default(),
            open: HashMap::new(),
            next_id: 1,
            dirs: DirCache::default(),
            doomed: Vec::new(),
            envelopes: HashMap::new(),
            renonced: HashSet::new(),
            foreign: Mutex::default(),
            checked: Mutex::default(),
        };
        store.recover()?;
        store.merge_all_conflicts()?;
        Ok(store)
    }

    /// Create a brand-new drive protected by `passphrase`. Errors if a drive
    /// already exists at `backing_dir` (so Create never clobbers an existing
    /// one). Writes the salt, region, and an encrypted verifier token.
    pub fn create_with_passphrase(
        backing_dir: impl AsRef<Path>,
        passphrase: &str,
        region: u64,
    ) -> io::Result<Self> {
        let backing_dir = backing_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&backing_dir)?;
        let meta_path = backing_dir.join("meta.json");
        if meta_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a drive already exists here",
            ));
        }
        let derived = write_new_meta(&backing_dir, passphrase, region)?;
        Self::open(backing_dir, derived, region)
    }

    /// Open an existing drive. Errors if there is no drive at `backing_dir`
    /// ("no drive here"), or if the passphrase is wrong ("wrong password"),
    /// checked against the verifier token before any data is touched.
    pub fn open_with_passphrase(
        backing_dir: impl AsRef<Path>,
        passphrase: &str,
    ) -> io::Result<Self> {
        let backing_dir = backing_dir.as_ref().to_path_buf();
        let meta_path = backing_dir.join("meta.json");
        if !meta_path.exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no drive here"));
        }
        if crate::convert::in_progress(&backing_dir) {
            return Err(io::Error::other(
                "this folder is part-way through being converted; finish converting it first",
            ));
        }
        let (derived, region) = key_from_meta(&std::fs::read(&meta_path)?, passphrase)?;
        Self::open(backing_dir, derived, region)
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
            let manifest = self.dirs.load(&cur, &self.key)?;
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
        let manifest = self.dirs.load(&parent_disk, &self.key)?;
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
        let manifest = self.dirs.load(&parent_disk, &self.key)?;
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
        let manifest = self.dirs.load(&disk, &self.key)?;
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
            let Ok(dir) = self.dirs.load(&folder, &self.key) else {
                continue; // a damaged list: reported when the folder is opened
            };
            folders.extend(dir.children().iter().filter(|c| c.is_dir()).map(|c| folder.join(&c.boring)));
        }
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
        let dir = self.dirs.load(folder, &self.key)?;
        let mut adopt = Vec::new();
        let mut foreign = BTreeSet::new();
        for (name, m) in found {
            let Some(name) = name.to_str() else { continue };
            if dir.has_boring(name)
                || crate::convert::is_reserved(name, at_root)
                || self.doomed.iter().any(|(d, b)| d == folder && b == name)
            {
                continue;
            }
            let path = folder.join(name);
            if m.is_dir() {
                if !manifest::Manifest::path_in(&path).exists() {
                    continue; // not a drive's folder
                }
                match read_listing(&path, &self.key) {
                    Ok(l) => adopt.push(Child::dir(l.name.unwrap_or_else(|| RECOVERED.into()), name.into())),
                    Err(_) => {
                        foreign.insert(name.to_string());
                    }
                }
            } else if m.is_file() && m.len() >= ENVELOPE {
                match Envelope::read(&path, &self.key) {
                    Ok(e) => adopt.push(Child::from_envelope(e, name.into(), m.len() - ENVELOPE)),
                    Err(_) => {
                        foreign.insert(name.to_string());
                    }
                }
            }
        }
        let gone: Vec<String> = dir
            .children()
            .iter()
            .filter(|c| !found.contains_key(std::ffi::OsStr::new(&c.boring)))
            .map(|c| c.boring.clone())
            .collect();
        drop(dir);
        if !adopt.is_empty() || !gone.is_empty() {
            self.dirs.edit(folder, &self.key, |d| {
                for b in &gone {
                    if let Some(p) = d.position_of_boring(b) {
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
        for (folder, name) in strays {
            let path = folder.join(&name);
            let child = if path.is_dir() {
                if self.rekey_tree(&path, other)? {
                    let l = read_listing(&path, &self.key)?;
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
                    self.dirs.edit(&folder, &self.key, |d| {
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
        write_all_at(&f, &e.seal(&self.key), at)?;
        f.sync_data()?;
        self.clear_journal()?;
        Ok(Some(e))
    }

    /// Re-seal a folder from the drive with key `other`, and everything in
    /// it, with this drive's key: files first, then each folder's own list,
    /// so an interrupted run is simply run again. False if the folder's
    /// list opens with neither key.
    fn rekey_tree(&self, dir: &Path, other: &Key) -> io::Result<bool> {
        if !manifest::Manifest::path_in(dir).exists() {
            return Ok(false);
        }
        let theirs = match read_listing(dir, &self.key) {
            Ok(_) => None, // re-sealed already, by a run that stopped part-way
            Err(_) => match read_listing(dir, other) {
                Ok(l) => Some(l),
                Err(_) => return Ok(false),
            },
        };
        for e in std::fs::read_dir(dir)?.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
            if crate::convert::is_reserved(&name, false) {
                continue;
            }
            let ft = e.file_type()?;
            if ft.is_dir() {
                self.rekey_tree(&e.path(), other)?;
            } else if ft.is_file() {
                self.rekey_file(&e.path(), other)?;
            }
        }
        if let Some(l) = theirs {
            write_listing(dir, &self.key, l.name.as_deref(), &l.children, 0, &mut Vec::new(), None)?;
            for i in 0..l.parts {
                let _ = std::fs::remove_file(dir.join(manifest::part_name(i)));
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
            let manifest = self.dirs.load(&cur, &self.key)?;
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
            let dir = self.dirs.load(&parent_disk, &self.key)?;
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
        write_listing(&disk, &self.key, Some(&name), &[], 0, &mut Vec::new(), None)?;
        self.dirs.edit(&parent_disk, &self.key, |d| d.push(Child::dir(name, boring)))?;
        self.tick()
    }

    /// Create an empty file at `path` (parent must exist). Returns its boring
    /// name; if the name already exists, returns the existing boring name.
    pub fn create(&mut self, path: &str) -> io::Result<String> {
        let (parent, name) = parent_and_name(path)?;
        names::validate(&name)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let boring = {
            let dir = self.dirs.load(&parent_disk, &self.key)?;
            if let Some(existing) = dir.find(&name) {
                if existing.is_dir() {
                    return Err(io::Error::new(io::ErrorKind::IsADirectory, "is a directory"));
                }
                return Ok(existing.boring.clone());
            }
            generate_unique(&mut rand::thread_rng(), &Taken { dir: &dir, at: &parent_disk })
        };
        let child = Child::new_file(name, boring.clone(), 0);
        // An empty file is just its envelope. Its handle is kept for the
        // writes that usually follow: on Windows, reopening a file just
        // written waits for the antivirus scan.
        let blob = parent_disk.join(&boring);
        let f = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&blob)?;
        let env = child.envelope().seal(&self.key);
        write_all_at(&f, &env, 0)?;
        if self.handles.len() >= MAX_HANDLES {
            self.handles.clear();
        }
        self.handles.insert(blob.clone(), f);
        self.envelopes.insert(blob, env);
        self.dirs.edit(&parent_disk, &self.key, |d| d.push(child))?;
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
        let entry = self.dirs.load(&dir, &self.key)?.children().iter().find(|c| c.boring == boring).cloned();
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
        let env = entry.envelope().seal(&self.key);
        write_all_at(f, &env, len)?;
        self.envelopes.insert(blob.to_path_buf(), env);
        f.sync_data()?;
        self.dirs.edit(&dir, &self.key, |d| {
            if let Some(p) = d.position_of_boring(&boring) {
                d.child_mut(p).nonce = nonce;
            }
        })?;
        self.dirs.flush_dir(&dir, &self.key)?;
        if journaled {
            self.clear_journal()?;
        }
        for o in self.open.values_mut().filter(|o| o.blob == blob) {
            o.crypt = (key, nonce);
        }
        self.renonced.insert(blob.to_path_buf());
        Ok((key, nonce))
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
        self.durable_len.remove(blob);
        self.handles.remove(blob);
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
        let manifest = self.dirs.load(&parent_disk, &self.key)?;
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
        if new != old {
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
        if !data.is_empty() {
            let mut buf = data.to_vec();
            for (s, e) in clip(&protected_ranges(new, n), offset, end) {
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
        if self.dirs.load(&parent_disk, &self.key)?.find(&name).is_none() {
            return Ok(());
        }
        let child = self
            .dirs
            .edit(&parent_disk, &self.key, |d| d.position(&name).map(|p| d.remove(p)))?
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
        let old_manifest = self.dirs.load(&old_parent_disk, &self.key)?;
        let pos = old_manifest.position(&old_name).ok_or_else(not_found)?;
        let moving_dir = old_manifest.children()[pos].is_dir();
        let new_parent_disk = self.resolve_dir(&new_parent)?;
        let same_parent = old_parent_disk == new_parent_disk;

        // An existing *different* entry at the destination: replace or refuse.
        let target = if same_parent {
            old_manifest.position(&new_name).filter(|&p| p != pos)
        } else {
            self.dirs.load(&new_parent_disk, &self.key)?.position(&new_name)
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
                self.dirs.load(&new_parent_disk, &self.key)?
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
            self.dirs.edit(&old_parent_disk, &self.key, |d| {
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
        let new_manifest = self.dirs.load(&new_parent_disk, &self.key)?;
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
        self.dirs.edit(disk, &self.key, |d| d.set_name(Some(name.to_string())))?;
        self.tick()
    }

    // ---- reads -----------------------------------------------------------

    /// Read `len` plaintext bytes at `offset` of the file at `path`.
    pub fn read_at(&self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let manifest = self.dirs.load(&parent_disk, &self.key)?;
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
        let doomed = std::mem::take(&mut self.doomed);
        let purge = Journal::Purge {
            items: doomed.iter().map(|(d, b)| (self.rel(d), b.clone())).collect(),
        };
        let mut result = Ok(());
        if !doomed.is_empty() {
            result = self.write_journal(&purge);
        }
        if result.is_ok() {
            result = self.dirs.flush(&self.key);
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
                    if dir.is_dir() && !self.dirs.load(&dir, &self.key)?.has_boring(boring) {
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
                self.dirs.edit(&to_dir, &self.key, |d| {
                    let gone = [Some(&child.boring), replaced.as_ref(), same.then_some(from_boring)];
                    for b in gone.into_iter().flatten() {
                        if let Some(p) = d.position_of_boring(b) {
                            d.remove(p);
                        }
                    }
                    d.push(child.clone());
                })?;
                self.dirs.flush_dir(&to_dir, &self.key)?;
                if !same {
                    self.dirs.edit(&from_dir, &self.key, |d| {
                        if let Some(p) = d.position_of_boring(from_boring) {
                            d.remove(p);
                        }
                    })?;
                    self.dirs.flush_dir(&from_dir, &self.key)?;
                }
                durable::sync_dir(&to_dir)?;
                durable::sync_dir(&from_dir)
            }
            Journal::Undo { blob, len, ranges } => restore(&self.abs(blob), *len, ranges),
            Journal::Renonce { dir, boring, nonce, len, ranges } => {
                let dir = self.abs(dir);
                let done = dir.is_dir()
                    && self.dirs.load(&dir, &self.key)?.children().iter().any(|c| c.boring == *boring && c.nonce == *nonce);
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
            manifest::merge_conflicts(&dir, &self.key)?;
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

/// A file's data length: its length on disk less its envelope.
fn data_len(f: &std::fs::File) -> io::Result<u64> {
    let len = f.metadata()?.len();
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
    fn password_settings_are_recorded_and_old_formats_refused() {
        let d = tempdir().unwrap();
        {
            let mut s = Store::create_with_passphrase(d.path(), "right", 64).unwrap();
            s.create("note.txt").unwrap();
            s.write_at("note.txt", 0, b"kept").unwrap();
        }
        let meta_path = d.path().join("meta.json");
        let mut meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_value::<key::KdfParams>(meta["kdf"].clone()).unwrap(),
            key::KdfParams::CURRENT
        );

        let s = Store::open_with_passphrase(d.path(), "right").unwrap();
        assert_eq!(s.read_all("note.txt").unwrap(), b"kept");
        drop(s);

        // A drive from an earlier format is refused, saying why.
        let mut old = meta.clone();
        old["version"] = serde_json::json!(1);
        std::fs::write(&meta_path, serde_json::to_vec(&old).unwrap()).unwrap();
        let err = Store::open_with_passphrase(d.path(), "right").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("earlier test version"), "{err}");

        // Settings out of range are refused rather than tried.
        meta["kdf"] = serde_json::json!({ "m_cost": u32::MAX, "t_cost": 2, "p_cost": 1 });
        std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        assert_eq!(
            Store::open_with_passphrase(d.path(), "right").err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidData)
        );
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
        let manifest = s.dirs.load(&s.backing_dir, &s.key).unwrap();
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
        let child = s.dirs.load(&s.backing_dir, &s.key).unwrap().find("big").unwrap().clone();
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
        let mut child = s.dirs.load(&a_disk, &s.key).unwrap().find("f.txt").unwrap().clone();
        let from_boring = child.boring.clone();
        let replaced = s.dirs.load(&b_disk, &s.key).unwrap().find("g.txt").unwrap().boring.clone();
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
        let boring = s.dirs.load(&s.backing_dir, &s.key).unwrap().find("dir").unwrap().boring.clone();
        s.remove("dir").unwrap();

        // "Crash" after the list was saved but before the folder was deleted.
        let items = vec![(String::new(), boring.clone())];
        s.write_journal(&Journal::Purge { items }).unwrap();
        s.dirs.flush(&s.key).unwrap();
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
        let boring = s.dirs.load(&s.backing_dir, &s.key).unwrap().find("doomed.txt").unwrap().boring.clone();

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
        assert!(read_listing(d.path(), &s.key).unwrap().children.is_empty());
        std::thread::sleep(SAVE_DELAY);
        s.tick().unwrap();
        assert_eq!(read_listing(d.path(), &s.key).unwrap().children.len(), 1);
    }

    #[test]
    fn deletes_reach_the_disk_only_after_the_save() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("a.txt").unwrap();
        s.write_at("a.txt", 0, b"x").unwrap();
        s.sync().unwrap();
        let boring = s.dirs.load(&s.backing_dir, &s.key).unwrap().find("a.txt").unwrap().boring.clone();
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
        s.dirs.load(folder, &s.key).unwrap().find(name).unwrap().clone()
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
    fn wrong_password_and_changing_it() {
        let d = tempdir().unwrap();
        {
            let mut s = Store::create_with_passphrase(d.path(), "first", 128).unwrap();
            s.create("note.txt").unwrap();
            s.write_at("note.txt", 0, b"kept").unwrap();
        }
        let wrong = Store::open_with_passphrase(d.path(), "nope").err().unwrap();
        assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);

        change_password(d.path(), "first", "second").unwrap();
        assert!(Store::open_with_passphrase(d.path(), "first").is_err());
        let s = Store::open_with_passphrase(d.path(), "second").unwrap();
        assert_eq!(s.read_all("note.txt").unwrap(), b"kept", "files untouched");
        assert!(change_password(d.path(), "first", "x").is_err());
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
        std::fs::remove_file(d.path().join(manifest::MANIFEST_NAME)).unwrap();

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
    fn a_changed_list_is_refused() {
        let d = tempdir().unwrap();
        let mut s = store(d.path());
        s.create("x").unwrap();
        s.sync().unwrap();
        drop(s);
        let path = d.path().join(manifest::MANIFEST_NAME);
        let mut raw = std::fs::read(&path).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 1;
        std::fs::write(&path, raw).unwrap();
        let s = Store::open(d.path(), [9u8; 32], 128).unwrap();
        assert_eq!(s.list_dir("").err().map(|e| e.kind()), Some(io::ErrorKind::InvalidData));
    }
}
