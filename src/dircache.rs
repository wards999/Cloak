//! Directory lists: the in-memory cache, delayed saving, and the on-disk form.
//!
//! **Cache.** Every operation resolves its path from the root, and without a
//! cache each step reads, decrypts and parses a manifest — and on Windows the
//! first open of a freshly saved manifest also waits for the antivirus scan.
//! With the cache a step costs nothing. The cache doesn't trust itself for
//! long: at most every [`RECHECK`] (and always before saving) it compares the
//! manifest file's size, modified time and file ID with the copy it holds and
//! re-reads on any difference, so a list changed behind the mount's back — by
//! a sync tool bringing in another machine's edits — shows up within a second.
//!
//! **Delayed saving.** Edits change the cached list and mark it unsaved; the
//! store writes unsaved lists out in one batch shortly afterwards (see
//! `Store::sync`). If the disk copy changes while ours has unsaved edits, the
//! two are combined with a three-way merge ([`manifest::merge3`]).
//!
//! **On-disk form.** A list is one `manifest.idx`, or, past [`SPLIT_AT`]
//! entries, [`PARTS`] part files plus a `manifest.idx` holding each part's
//! tag. Each child lives in the part chosen by its boring name, so a save
//! rewrites only the parts that changed. Every file is written atomically;
//! the parts go first and `manifest.idx` last. A part whose tag doesn't match
//! `manifest.idx` is one a sync tool hasn't delivered yet, so until they agree
//! every part is checked on each use, not just `manifest.idx`.

use crate::crypto::Key;
use crate::durable;
use crate::manifest::{self, part_name, part_of, seal, Child, Manifest, PARTS};
use crate::names;
use rand::RngCore;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// Directories kept before the saved ones are dropped and the cache refills.
const MAX_DIRS: usize = 512;

/// How long a list is trusted before its files are checked again. A file
/// read in 4 KiB pieces resolves its path for every piece, and checking each
/// time cost more than the read itself.
pub const RECHECK: Duration = Duration::from_secs(1);

/// A list longer than this is split into [`PARTS`] parts when next saved.
pub const SPLIT_AT: usize = 2048;

/// What identifies one version of a file on disk: its size, modified time and
/// file ID. Every save (ours, or a sync tool's) writes a new file and renames
/// it into place, which gives it a new file ID — so a replacement is noticed
/// even when it has the same size and lands within the clock tick of the
/// last one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Stamp {
    len: u64,
    modified: SystemTime,
    id: (u64, u64),
}

impl Stamp {
    fn of(f: &File) -> io::Result<Stamp> {
        let m = f.metadata()?;
        Ok(Stamp { len: m.len(), modified: m.modified()?, id: file_id(f, &m)? })
    }

    /// `path`'s current stamp; `None` if there is no such file.
    fn current(path: &Path) -> io::Result<Option<Stamp>> {
        match open_for_stamp(path) {
            Ok(f) => Stamp::of(&f).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Open `path` just to read its attributes. On Windows that is an open
/// without read access, which the antivirus doesn't scan.
fn open_for_stamp(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().access_mode(0).open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

#[cfg(unix)]
fn file_id(_: &File, m: &Metadata) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Ok((m.dev(), m.ino()))
}

/// The volume serial number and file index (std's are unstable).
#[cfg(windows)]
fn file_id(f: &File, _: &Metadata) -> io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInformation {
        attributes: u32,
        times: [u32; 6],
        volume_serial: u32,
        size: [u32; 2],
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(file: *mut std::ffi::c_void, info: *mut ByHandleFileInformation) -> i32;
    }
    let mut info = ByHandleFileInformation::default();
    // SAFETY: a valid open handle and a correctly laid out out-struct
    // (BY_HANDLE_FILE_INFORMATION).
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info.volume_serial as u64, (info.index_high as u64) << 32 | info.index_low as u64))
}

#[cfg(not(any(unix, windows)))]
fn file_id(_: &File, _: &Metadata) -> io::Result<(u64, u64)> {
    Ok((0, 0))
}

/// Stamps of `manifest.idx`, then (for a split list whose parts don't all
/// match it yet) of each part.
type Stamps = Vec<Option<Stamp>>;

fn current_stamps(dir: &Path, parts: usize, settled: bool) -> io::Result<Stamps> {
    let mut out = vec![Stamp::current(&Manifest::path_in(dir))?];
    if !settled {
        for i in 0..parts {
            out.push(Stamp::current(&dir.join(part_name(i)))?);
        }
    }
    Ok(out)
}

/// A file's stamp and bytes from one open handle, so a file replaced in
/// between can't be paired with the other version's stamp.
fn read_stamped(path: &Path) -> io::Result<Option<(Stamp, Vec<u8>)>> {
    match File::open(path) {
        Ok(mut f) => {
            let stamp = Stamp::of(&f)?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;
            Ok(Some((stamp, bytes)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// A directory's list as read from disk.
pub struct Listing {
    pub children: Vec<Child>,
    /// The folder's own real name, if it records one.
    pub name: Option<String>,
    /// 0 for a list kept in one file.
    pub parts: usize,
    tags: Vec<u64>,
    stamps: Stamps,
    settled: bool,
}

/// Read `dir`'s list in either form. A directory with no `manifest.idx` is
/// empty.
pub fn read_listing(dir: &Path, key: &Key) -> io::Result<Listing> {
    let Some((stamp, bytes)) = read_stamped(&Manifest::path_in(dir))? else {
        return Ok(Listing {
            children: Vec::new(),
            name: None,
            parts: 0,
            tags: Vec::new(),
            stamps: vec![None],
            settled: true,
        });
    };
    let header = Manifest::from_sealed(bytes, key)?;
    let parts = header.parts.len();
    let name = header.name;
    let mut children = header.children;
    let mut stamps = vec![Some(stamp)];
    let mut settled = true;
    let mut seen: HashSet<String> = children.iter().map(|c| c.boring.clone()).collect();
    for (i, &tag) in header.parts.iter().enumerate() {
        match read_stamped(&dir.join(part_name(i)))? {
            Some((s, bytes)) => {
                let part = Manifest::from_sealed(bytes, key)?;
                settled &= part.tag == tag;
                stamps.push(Some(s));
                children.extend(part.children.into_iter().filter(|c| seen.insert(c.boring.clone())));
            }
            None => {
                settled &= tag == 0;
                stamps.push(None);
            }
        }
    }
    if settled {
        stamps.truncate(1);
    }
    Ok(Listing { children, name, parts, tags: header.parts, stamps, settled })
}

/// The serialized form of a list or part (the same JSON as [`Manifest`]).
#[derive(Serialize)]
struct Out<'a> {
    children: Vec<&'a Child>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parts: Vec<u64>,
    #[serde(skip_serializing_if = "is_zero")]
    tag: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

fn write_sealed(path: &Path, key: &Key, out: &Out) -> io::Result<()> {
    durable::write_atomic(path, &seal(serde_json::to_vec(out)?, key))
}

/// Write `dir`'s list. With `parts` > 0 it is split: the parts in `touched`
/// (all of them for `None`) are written with fresh tags, recorded in `tags`,
/// and then `manifest.idx`.
pub fn write_listing(
    dir: &Path,
    key: &Key,
    name: Option<&str>,
    children: &[Child],
    parts: usize,
    tags: &mut Vec<u64>,
    touched: Option<&HashSet<usize>>,
) -> io::Result<()> {
    if parts == 0 {
        let out = Out { children: children.iter().collect(), name, parts: Vec::new(), tag: 0 };
        return write_sealed(&Manifest::path_in(dir), key, &out);
    }
    let mut groups: Vec<Vec<&Child>> = vec![Vec::new(); parts];
    for c in children {
        groups[part_of(&c.boring, parts)].push(c);
    }
    tags.resize(parts, 0);
    for (i, group) in groups.into_iter().enumerate() {
        if touched.is_some_and(|t| !t.contains(&i)) {
            continue;
        }
        let tag = rand::thread_rng().next_u64() | 1;
        write_sealed(&dir.join(part_name(i)), key, &Out { children: group, name: None, parts: Vec::new(), tag })?;
        tags[i] = tag;
    }
    write_sealed(&Manifest::path_in(dir), key, &Out { children: Vec::new(), name, parts: tags.clone(), tag: 0 })
}

/// A directory's list in memory, indexed by real and by boring name.
#[derive(Clone, Default)]
pub struct Dir {
    children: Vec<Child>,
    /// The folder's own real name.
    name: Option<String>,
    /// [`names::fold`] of each real name -> position.
    by_name: HashMap<String, usize>,
    by_boring: HashMap<String, usize>,
    parts: usize,
    tags: Vec<u64>,
    /// The parts holding unsaved changes, as if split into [`PARTS`] (kept
    /// for a one-file list too, to choose how to save it).
    touched: HashSet<usize>,
}

impl Dir {
    fn new(children: Vec<Child>, name: Option<String>, parts: usize, tags: Vec<u64>) -> Dir {
        let mut d = Dir { name, parts, tags, ..Dir::default() };
        for c in children {
            d.index(c);
        }
        d
    }

    fn index(&mut self, mut c: Child) {
        if self.by_boring.contains_key(&c.boring) {
            return;
        }
        // Two names that clash (from a merge, or parts saved from different
        // moments): keep both, renaming the later one.
        let original = c.real.clone();
        let mut n = 1;
        while self.by_name.contains_key(&names::fold(&c.real)) {
            c.real = manifest::conflict_name(&original, n);
            n += 1;
        }
        let i = self.children.len();
        self.by_name.insert(names::fold(&c.real), i);
        self.by_boring.insert(c.boring.clone(), i);
        self.children.push(c);
    }

    pub fn children(&self) -> &[Child] {
        &self.children
    }

    /// The folder's own real name, if recorded.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Record the folder's own real name (it lives in the main list file).
    pub fn set_name(&mut self, name: Option<String>) {
        if self.name != name {
            self.name = name;
            self.touched.insert(0);
        }
    }

    /// The child at `pos`, to change in place (not its names).
    pub fn child_mut(&mut self, pos: usize) -> &mut Child {
        let boring = self.children[pos].boring.clone();
        self.touch(&boring);
        &mut self.children[pos]
    }

    /// Same answer as [`Manifest::position`], without scanning every name.
    pub fn position(&self, real: &str) -> Option<usize> {
        self.by_name.get(&names::fold(real)).copied()
    }

    pub fn find(&self, real: &str) -> Option<&Child> {
        self.position(real).map(|i| &self.children[i])
    }

    pub fn position_of_boring(&self, boring: &str) -> Option<usize> {
        self.by_boring.get(boring).copied()
    }

    pub fn has_boring(&self, boring: &str) -> bool {
        self.by_boring.contains_key(boring)
    }

    fn touch(&mut self, boring: &str) {
        let parts = if self.parts > 0 { self.parts } else { PARTS };
        self.touched.insert(part_of(boring, parts));
    }

    /// Add a child. The caller has checked that neither name is taken.
    pub fn push(&mut self, c: Child) {
        self.touch(&c.boring);
        self.index(c);
    }

    /// Remove and return the child at `pos` (the last child takes its place).
    pub fn remove(&mut self, pos: usize) -> Child {
        let c = self.children.swap_remove(pos);
        self.by_name.remove(&names::fold(&c.real));
        self.by_boring.remove(&c.boring);
        if let Some(moved) = self.children.get(pos) {
            self.by_name.insert(names::fold(&moved.real), pos);
            self.by_boring.insert(moved.boring.clone(), pos);
        }
        self.touch(&c.boring);
        c
    }

    /// Give the child at `pos` a new real name (not taken by another child).
    pub fn rename(&mut self, pos: usize, real: String) {
        let c = &mut self.children[pos];
        self.by_name.remove(&names::fold(&c.real));
        self.by_name.insert(names::fold(&real), pos);
        c.real = real;
        let boring = c.boring.clone();
        self.touch(&boring);
    }
}

struct Entry {
    stamps: Stamps,
    /// When `stamps` were last compared with the disk.
    checked: Instant,
    settled: bool,
    dir: Arc<Dir>,
    /// Unsaved edits: since when, and the list as it was on disk before them.
    dirty: Option<(Instant, Arc<Dir>)>,
}

impl Entry {
    fn clean(l: Listing) -> Entry {
        Entry {
            stamps: l.stamps,
            checked: Instant::now(),
            settled: l.settled,
            dir: Arc::new(Dir::new(l.children, l.name, l.parts, l.tags)),
            dirty: None,
        }
    }
}

pub struct DirCache {
    /// Shared by reads on several threads; held only briefly, never across
    /// another call into the cache.
    dirs: Mutex<HashMap<PathBuf, Entry>>,
    recheck: Duration,
}

impl Default for DirCache {
    fn default() -> Self {
        DirCache::with_recheck(RECHECK)
    }
}

impl DirCache {
    /// A cache that trusts a list for `recheck` between checks.
    pub fn with_recheck(recheck: Duration) -> Self {
        DirCache { dirs: Mutex::default(), recheck }
    }

    fn map(&self) -> MutexGuard<'_, HashMap<PathBuf, Entry>> {
        self.dirs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The list of on-disk directory `dir`, including unsaved edits.
    pub fn load(&self, dir: &Path, key: &Key) -> io::Result<Arc<Dir>> {
        let mut dirs = self.map();
        self.refresh(&mut dirs, dir, key, false)?;
        Ok(dirs[dir].dir.clone())
    }

    /// Change `dir`'s list in memory; it is written out by [`flush`](Self::flush).
    /// Holding another `Arc` of the list from [`load`](Self::load) meanwhile
    /// works but makes this copy the whole list.
    pub fn edit<R>(&self, dir: &Path, key: &Key, f: impl FnOnce(&mut Dir) -> R) -> io::Result<R> {
        let mut dirs = self.map();
        self.refresh(&mut dirs, dir, key, false)?;
        let e = dirs.get_mut(dir).expect("refreshed");
        if e.dirty.is_none() {
            e.dirty = Some((Instant::now(), e.dir.clone()));
        }
        Ok(f(Arc::make_mut(&mut e.dir)))
    }

    /// When the oldest unsaved edit was made.
    pub fn oldest_unsaved(&self) -> Option<Instant> {
        self.map().values().filter_map(|e| e.dirty.as_ref().map(|d| d.0)).min()
    }

    /// Write every list with unsaved edits.
    pub fn flush(&self, key: &Key) -> io::Result<()> {
        let dirty: Vec<PathBuf> =
            self.map().iter().filter(|(_, e)| e.dirty.is_some()).map(|(p, _)| p.clone()).collect();
        for dir in dirty {
            self.flush_dir(&dir, key)?;
        }
        Ok(())
    }

    /// Write `dir`'s list if it has unsaved edits.
    pub fn flush_dir(&self, dir: &Path, key: &Key) -> io::Result<()> {
        let mut dirs = self.map();
        if !dirs.get(dir).is_some_and(|e| e.dirty.is_some()) {
            return Ok(());
        }
        if !dir.is_dir() {
            // The folder itself is gone (deleted elsewhere): nothing to save.
            dirs.remove(dir);
            return Ok(());
        }
        self.refresh(&mut dirs, dir, key, true)?; // fold in anything changed on disk first
        let e = dirs.get_mut(dir).expect("refreshed");
        let d = Arc::make_mut(&mut e.dir);
        // How to save: a big list in parts when few changed, so a rename in a
        // 100,000-file folder rewrites one part. When changes are spread over
        // many parts (a bulk copy), one file is a single disk wait instead of
        // one per part; the next small change splits it again.
        let touched = std::mem::take(&mut d.touched);
        if d.children.len() <= SPLIT_AT || touched.len() > PARTS / 4 {
            d.parts = 0;
            d.tags.clear();
        } else if d.parts == 0 {
            d.parts = PARTS;
            d.tags = vec![0; PARTS];
        }
        let only = (!d.tags.iter().all(|&t| t == 0)).then_some(&touched);
        if let Err(err) = write_listing(dir, key, d.name.as_deref(), &d.children, d.parts, &mut d.tags, only) {
            d.touched = touched;
            return Err(err);
        }
        e.stamps = current_stamps(dir, d.parts, true)?;
        e.checked = Instant::now();
        e.settled = true;
        e.dirty = None;
        Ok(())
    }

    /// Bring `dir`'s entry up to date with the disk, if it hasn't been checked
    /// within `recheck` (or always, with `force`).
    fn refresh(&self, dirs: &mut HashMap<PathBuf, Entry>, dir: &Path, key: &Key, force: bool) -> io::Result<()> {
        let Some(e) = dirs.get_mut(dir) else {
            if dirs.len() >= MAX_DIRS {
                dirs.retain(|_, e| e.dirty.is_some());
            }
            dirs.insert(dir.to_path_buf(), Entry::clean(read_listing(dir, key)?));
            return Ok(());
        };
        if !force && e.checked.elapsed() < self.recheck {
            return Ok(());
        }
        let now = current_stamps(dir, e.dir.parts, e.settled)?;
        e.checked = Instant::now();
        if now == e.stamps {
            return Ok(());
        }
        let theirs = read_listing(dir, key)?;
        let Some((since, base)) = e.dirty.take() else {
            *e = Entry::clean(theirs);
            return Ok(());
        };
        // Changed on disk while we hold unsaved edits: merge, and save every
        // part of the result.
        let merged = manifest::merge3(&base.children, &e.dir.children, &theirs.children);
        let name = e.dir.name.clone().or(theirs.name.clone());
        let mut ours = Dir::new(merged, name, theirs.parts, theirs.tags.clone());
        ours.touched = (0..ours.parts).collect();
        e.stamps = theirs.stamps.clone();
        e.settled = theirs.settled;
        e.dir = Arc::new(ours);
        e.dirty = Some((since, Arc::new(Dir::new(theirs.children, theirs.name, theirs.parts, theirs.tags))));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NONCE_LEN;
    use tempfile::tempdir;

    fn child(real: &str, boring: &str) -> Child {
        let mut c = Child::new_file(real.into(), boring.into(), 0);
        (c.id, c.key, c.nonce) = ([0; 16], [0; 32], [0; NONCE_LEN]);
        c
    }

    fn names_in(d: &Dir) -> Vec<String> {
        let mut v: Vec<String> = d.children().iter().map(|c| c.real.clone()).collect();
        v.sort();
        v
    }

    #[test]
    fn sees_changes_made_behind_its_back() {
        let d = tempdir().unwrap();
        let key = [3u8; 32];
        let cache = DirCache::with_recheck(Duration::ZERO);
        assert!(cache.load(d.path(), &key).unwrap().children().is_empty());

        cache.edit(d.path(), &key, |m| m.push(child("a.txt", "cache_0001.dat"))).unwrap();
        cache.flush(&key).unwrap();
        assert_eq!(cache.load(d.path(), &key).unwrap().find("A.TXT").unwrap().boring, "cache_0001.dat");

        // Another writer (a sync tool) replaces the file, keeping its length.
        let mut m = Manifest::default();
        m.children.push(child("b.txt", "cache_0002.dat"));
        m.save(d.path(), &key).unwrap();
        let got = cache.load(d.path(), &key).unwrap();
        assert!(got.find("a.txt").is_none());
        assert_eq!(got.find("b.txt").unwrap().boring, "cache_0002.dat");

        std::fs::remove_file(Manifest::path_in(d.path())).unwrap();
        assert!(cache.load(d.path(), &key).unwrap().children().is_empty());
    }

    #[test]
    fn edits_wait_for_flush_and_merge_with_outside_changes() {
        let d = tempdir().unwrap();
        let key = [3u8; 32];
        let cache = DirCache::with_recheck(Duration::ZERO);
        cache.edit(d.path(), &key, |m| {
            m.push(child("keep.txt", "cache_0001.dat"));
            m.push(child("gone.txt", "cache_0002.dat"));
        }).unwrap();
        cache.flush(&key).unwrap();
        cache.edit(d.path(), &key, |m| m.push(child("ours.txt", "cache_0003.dat"))).unwrap();
        assert!(Manifest::load(d.path(), &key).unwrap().children.len() == 2, "not saved yet");

        // Meanwhile another machine removes gone.txt and adds theirs.txt.
        let mut m = Manifest::default();
        m.children.push(child("keep.txt", "cache_0001.dat"));
        m.children.push(child("theirs.txt", "cache_0004.dat"));
        m.save(d.path(), &key).unwrap();

        assert_eq!(names_in(&cache.load(d.path(), &key).unwrap()), ["keep.txt", "ours.txt", "theirs.txt"]);
        cache.flush(&key).unwrap();
        let saved = Manifest::load(d.path(), &key).unwrap();
        assert_eq!(saved.children.len(), 3);
    }

    #[test]
    fn big_lists_split_and_save_only_changed_parts() {
        let d = tempdir().unwrap();
        let key = [3u8; 32];
        let cache = DirCache::with_recheck(Duration::ZERO);
        cache.edit(d.path(), &key, |m| {
            for i in 0..SPLIT_AT + 10 {
                m.push(child(&format!("f{i}"), &format!("cache_{i:06}.dat")));
            }
        }).unwrap();
        cache.flush(&key).unwrap();
        // A bulk change is saved as one file...
        assert!(!d.path().join(part_name(0)).exists());
        assert_eq!(Manifest::load(d.path(), &key).unwrap().children.len(), SPLIT_AT + 10);
        // ...and the next small one splits it.
        cache.edit(d.path(), &key, |m| m.push(child("one more", "cache_999999.dat"))).unwrap();
        cache.flush(&key).unwrap();
        assert!(d.path().join(part_name(PARTS - 1)).exists());

        let before: Vec<_> = (0..PARTS).map(|i| std::fs::read(d.path().join(part_name(i))).unwrap()).collect();
        cache.edit(d.path(), &key, |m| {
            let p = m.position("f7").unwrap();
            m.rename(p, "seven".into());
        }).unwrap();
        cache.flush(&key).unwrap();
        let changed = (0..PARTS)
            .filter(|&i| std::fs::read(d.path().join(part_name(i))).unwrap() != before[i])
            .count();
        assert_eq!(changed, 1);

        // A fresh reader sees the same list.
        let l = read_listing(d.path(), &key).unwrap();
        assert_eq!(l.children.len(), SPLIT_AT + 11);
        assert!(l.children.iter().any(|c| c.real == "seven"));
        assert!(l.settled);
    }

    #[test]
    fn a_part_arriving_late_is_noticed() {
        let d = tempdir().unwrap();
        let key = [3u8; 32];
        let writer = DirCache::with_recheck(Duration::ZERO);
        writer.edit(d.path(), &key, |m| {
            for i in 0..SPLIT_AT + 10 {
                m.push(child(&format!("f{i}"), &format!("cache_{i:06}.dat")));
            }
        }).unwrap();
        writer.flush(&key).unwrap();
        writer.edit(d.path(), &key, |m| m.push(child("one more", "cache_999999.dat"))).unwrap();
        writer.flush(&key).unwrap(); // now split

        // The writer renames f7; a sync tool delivers manifest.idx first and
        // the changed part a moment later.
        let p = part_of("cache_000007.dat", PARTS);
        let old_part = std::fs::read(d.path().join(part_name(p))).unwrap();
        writer.edit(d.path(), &key, |m| {
            let i = m.position("f7").unwrap();
            m.rename(i, "seven".into());
        }).unwrap();
        writer.flush(&key).unwrap();
        let new_part = std::fs::read(d.path().join(part_name(p))).unwrap();
        std::fs::write(d.path().join(part_name(p)), &old_part).unwrap();

        let reader = DirCache::with_recheck(Duration::ZERO);
        assert!(reader.load(d.path(), &key).unwrap().find("f7").is_some());
        std::fs::write(d.path().join(part_name(p)), &new_part).unwrap();
        let now = reader.load(d.path(), &key).unwrap();
        assert!(now.find("f7").is_none());
        assert!(now.find("seven").is_some());
    }
}
