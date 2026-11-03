//! The storage engine: a path-addressed tree store (Approach A).
//!
//! The backing store mirrors the logical directory tree using boring-named
//! directories, and each directory carries its own encrypted manifest (see
//! [`crate::manifest`]). A logical path like `Documents/Taxes/Return.pdf` is
//! resolved by walking manifests from the root, descending into each child's
//! boring on-disk directory, until the final component.
//!
//! File *contents* use the same header/footer ChaCha20 scheme as before; only
//! the directory layer is new. Directories themselves hold no blob and are never
//! encrypted — their real names live solely in the parent's manifest, so a
//! folder is "obfuscated" by having no real name on disk at all.
//!
//! All operations are plain file I/O, so the engine runs and is fully tested
//! without any FUSE/WinFsp driver.

use crate::boring::{generate_unique, Contains};
use crate::crypto::{protected_ranges, transform_region, Key, Nonce, NONCE_LEN};
use crate::key::{self, SALT_LEN};
use crate::dircache::{Dir, DirCache};
use crate::durable;
use crate::manifest::{self, Child, Kind};
use crate::names;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};
use std::collections::HashMap;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Known token encrypted under the derived key at create time; decrypting it on
/// open is how we tell a correct password from a wrong one. This is a
/// usability/security trade: it lets an attacker with the store test password
/// guesses offline, but Argon2id makes each guess expensive, and "wrong
/// password" feedback is table stakes for a drive app.
const VERIFY_TOKEN: &[u8] = b"cloak-verify-v1";

/// Store-wide metadata persisted at the backing root (reserved name, distinct
/// from a directory manifest).
#[derive(Serialize, Deserialize)]
struct StoreMeta {
    version: u32,
    salt: [u8; SALT_LEN],
    region: u64,
    /// Nonce + ciphertext of VERIFY_TOKEN under the derived key.
    verifier_nonce: [u8; NONCE_LEN],
    verifier: Vec<u8>,
    /// The Argon2id settings the key is derived with. Absent in drives made
    /// before they were recorded, which used the original ones.
    #[serde(default)]
    kdf: key::KdfParams,
}

/// The key and region for `passphrase`, from the bytes of a store's
/// `meta.json`. `InvalidData` if they aren't a store header,
/// `PermissionDenied` if the passphrase is wrong.
pub fn key_from_meta(meta: &[u8], passphrase: &str) -> io::Result<(Key, u64)> {
    let meta: StoreMeta = serde_json::from_slice(meta)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("damaged drive header: {e}")))?;
    let derived = key::derive_key(passphrase, &meta.salt, &meta.kdf)?;
    let mut check = meta.verifier.clone();
    transform_region(&derived, &meta.verifier_nonce, 0, &mut check);
    if check != VERIFY_TOKEN {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "wrong password"));
    }
    Ok((derived, meta.region))
}

/// Write a new drive's `meta.json` into `backing_dir`: a fresh salt, the
/// current password settings, `region`, and a verifier for `passphrase`.
/// Returns the drive's key.
pub(crate) fn write_new_meta(backing_dir: &Path, passphrase: &str, region: u64) -> io::Result<Key> {
    let salt = key::random_salt();
    let kdf = key::KdfParams::CURRENT;
    let derived = key::derive_key(passphrase, &salt, &kdf)?;

    let mut verifier_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut verifier_nonce);
    let mut verifier = VERIFY_TOKEN.to_vec();
    transform_region(&derived, &verifier_nonce, 0, &mut verifier);

    let meta = StoreMeta {
        version: 1,
        salt,
        region,
        verifier_nonce,
        verifier,
        kdf,
    };
    durable::write_atomic(&backing_dir.join("meta.json"), &serde_json::to_vec_pretty(&meta)?)?;
    Ok(derived)
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
                    if is_dir { 0 } else { d.len() },
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
}

/// A file opened with [`Store::open_file`].
struct Opened {
    blob: PathBuf,
    nonce: Nonce,
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
    pub fn list_dir_meta(&self, path: &str) -> io::Result<Vec<(String, Metadata)>> {
        let entries = self.list_entries(path)?;
        let Some(first) = entries.first() else {
            return Ok(Vec::new());
        };
        let folder = first.disk.parent().expect("a child of its folder").to_path_buf();
        let mut found: HashMap<std::ffi::OsString, std::fs::Metadata> = HashMap::new();
        if let Ok(rd) = std::fs::read_dir(&folder) {
            for e in rd.flatten() {
                if let Ok(m) = e.metadata() {
                    found.insert(e.file_name(), m);
                }
            }
        }
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
        std::fs::create_dir(parent_disk.join(&boring))?;
        let child = Child {
            real: name,
            boring,
            kind: Kind::Dir,
            nonce: [0u8; NONCE_LEN],
            size: 0,
        };
        self.dirs.edit(&parent_disk, &self.key, |d| d.push(child))?;
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
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        std::fs::write(parent_disk.join(&boring), [])?;
        let child = Child {
            real: name,
            boring: boring.clone(),
            kind: Kind::File,
            nonce,
            size: 0,
        };
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
        let (blob, nonce) = self.file_blob(path)?;
        self.write_blob(blob, &nonce, offset, data)
    }

    /// Set a file's length (shorter truncates, longer zero-extends).
    pub fn truncate(&mut self, path: &str, new_size: u64) -> io::Result<()> {
        let (blob, nonce) = self.file_blob(path)?;
        self.truncate_blob(blob, &nonce, new_size)
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
        let (blob, nonce) = self.file_blob(path)?;
        let id = self.next_id;
        self.next_id += 1;
        self.open.insert(id, Opened { blob, nonce });
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

    fn opened(&self, id: u64) -> io::Result<(PathBuf, Nonce)> {
        self.open
            .get(&id)
            .map(|o| (o.blob.clone(), o.nonce))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file not open"))
    }

    pub fn read_file(&self, id: u64, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let o = self.open.get(&id).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file not open"))?;
        self.read_blob(&o.blob, &o.nonce, offset, len)
    }

    pub fn write_file(&mut self, id: u64, offset: u64, data: &[u8]) -> io::Result<()> {
        let (blob, nonce) = self.opened(id)?;
        self.write_blob(blob, &nonce, offset, data)
    }

    pub fn truncate_file(&mut self, id: u64, new_size: u64) -> io::Result<()> {
        let (blob, nonce) = self.opened(id)?;
        self.truncate_blob(blob, &nonce, new_size)
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

    fn write_blob(&mut self, blob: PathBuf, nonce: &Nonce, offset: u64, data: &[u8]) -> io::Result<()> {
        let f = self.take_handle(&blob)?;
        let result = (|| {
            let old = f.metadata()?.len();
            let new = max(old, offset + data.len() as u64);
            self.update_blob(&f, &blob, nonce, old, new, offset, data)
        })();
        self.handles.insert(blob, f);
        result
    }

    fn truncate_blob(&mut self, blob: PathBuf, nonce: &Nonce, new_size: u64) -> io::Result<()> {
        let f = self.take_handle(&blob)?;
        let result = (|| {
            let old = f.metadata()?.len();
            if new_size == old {
                return Ok(());
            }
            self.update_blob(&f, &blob, nonce, old, new_size, new_size, &[])
        })();
        self.handles.insert(blob, f);
        result
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

    /// The boring file and nonce behind a file path.
    fn file_blob(&self, path: &str) -> io::Result<(PathBuf, Nonce)> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let manifest = self.dirs.load(&parent_disk, &self.key)?;
        let child = manifest.find(&name).ok_or_else(not_found)?;
        if child.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "is a directory"));
        }
        Ok((parent_disk.join(&child.boring), child.nonce))
    }

    /// Take blob `f` (at `blob`) from `old` to `new` bytes and write `data` at `offset`
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
        nonce: &Nonce,
        old: u64,
        new: u64,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let end = offset + data.len() as u64;
        let n = self.region;

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
            self.write_journal(&Journal::Undo { blob: self.rel(blob), len: old, ranges })?;
        }
        if new < durable {
            self.durable_len.insert(blob.to_path_buf(), new);
        }
        let key = &self.key;

        // 1. Kept bytes whose encrypted/plain state flips (skipping what `data`
        //    is about to overwrite).
        for &(s, e) in &toggles {
            let mut buf = vec![0u8; (e - s) as usize];
            read_exact_at(f, &mut buf, s)?;
            transform_region(key, nonce, s, &mut buf);
            write_all_at(f, &buf, s)?;
        }

        // 2. Resize. Added bytes read as zeros, which is right outside the ends;
        //    inside one they must hold the keystream.
        if new != old {
            f.set_len(new)?;
        }
        if new > old {
            let added = clip(&protected_ranges(new, n), old, new);
            for (s, e) in subtract(&added, offset, end) {
                let mut buf = vec![0u8; (e - s) as usize];
                transform_region(key, nonce, s, &mut buf);
                write_all_at(f, &buf, s)?;
            }
        }

        // 3. The data itself.
        if !data.is_empty() {
            let mut buf = data.to_vec();
            for (s, e) in clip(&protected_ranges(new, n), offset, end) {
                let (ls, le) = ((s - offset) as usize, (e - offset) as usize);
                transform_region(key, nonce, s, &mut buf[ls..le]);
            }
            write_all_at(f, &buf, offset)?;
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
                d.rename(p, new_name);
            })?;
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
        child.real = new_name;
        if let Ok(blob) = self.disk_path(old) {
            self.durable_len.remove(&blob);
        }
        self.run(Journal::Move {
            from_dir: self.rel(&old_parent_disk),
            from_boring,
            to_dir: self.rel(&new_parent_disk),
            child,
            replaced,
        })
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
        self.read_blob(&parent_disk.join(&child.boring), &child.nonce, offset, len)
    }

    fn read_blob(&self, blob: &Path, nonce: &Nonce, offset: u64, len: usize) -> io::Result<Vec<u8>> {
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
        let size = file.metadata()?.len();
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
                transform_region(&self.key, nonce, o_start, &mut buf[ls..le]);
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
        let sealed = manifest::seal(serde_json::to_vec(j)?, &self.key);
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
        if let Ok(j) = serde_json::from_slice::<Journal>(&manifest::unseal(bytes, &self.key)) {
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
            Journal::Undo { blob, len, ranges } => {
                let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(self.abs(blob)) else {
                    return Ok(()); // deleted since; nothing to restore
                };
                f.set_len(max(*len, ranges.iter().map(|(s, b)| s + b.len() as u64).max().unwrap_or(0)))?;
                for (s, bytes) in ranges {
                    f.seek(SeekFrom::Start(*s))?;
                    f.write_all(bytes)?;
                }
                f.set_len(*len)?;
                f.sync_data()
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
    fn password_settings_are_recorded_and_old_drives_still_open() {
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

        // A drive from before the settings were recorded has none: it opens
        // with the original ones.
        meta.as_object_mut().unwrap().remove("kdf");
        std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        let s = Store::open_with_passphrase(d.path(), "right").unwrap();
        assert_eq!(s.read_all("note.txt").unwrap(), b"kept");

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
    /// whole plaintext would give, after any mix of writes and resizes.
    fn assert_disk_matches(s: &Store, name: &str, plain: &[u8]) {
        assert_eq!(s.read_all(name).unwrap(), plain, "read back differs");
        let manifest = s.dirs.load(&s.backing_dir, &s.key).unwrap();
        let child = manifest.find(name).unwrap();
        let mut want = plain.to_vec();
        crate::crypto::transform_ends(&s.key, &child.nonce, &mut want, s.region);
        let disk = std::fs::read(s.backing_dir.join(&child.boring)).unwrap();
        assert!(disk == want, "disk form differs at size {}", plain.len());
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
        assert_eq!(names, ["doomed.txt", "old.txt"], "back to the last save, consistently");
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
        s.write_journal(&Journal::Undo { blob: s.rel(&blob), len: 1000, ranges: vec![(0, before.clone())] })
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
}
