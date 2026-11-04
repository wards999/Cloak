//! Turning an existing folder into a drive in place, and back.
//!
//! A drive's folder is a mirror of its tree with boring names, whose files
//! hold their original bytes apart from the first and last `region` bytes
//! (see `docs/FORMAT.md`) and a 512-byte envelope at the end. So a plain
//! folder becomes a drive without copying: write `meta.json`, then in every
//! folder write its list (with the folder's own name) and, for each file,
//! encrypt its ends with a new key of its own where it lies, add its
//! envelope, and rename it to its boring name. Each file costs at most
//! `2 * region` bytes of reading and writing, whatever its size.
//! [`unconvert`] is the same walk backwards (the cipher is its own inverse).
//!
//! Crash safety, so an interrupted run can simply be run again:
//!
//! * A marker at the top ([`CONVERTING`] / [`UNCONVERTING`]) says a run is
//!   under way; the engine won't open the folder as a drive while it's there.
//! * Each folder's complete list is written before anything in it changes.
//!   An entry whose boring name exists on disk is done; one still under its
//!   real name is not.
//! * A file's original ends and length are journaled (sealed with the
//!   drive's key) before it's touched, and its rename is the commit. If a run
//!   stops in between, the next one finds the file under its old name, puts
//!   it back as it was and does it again.
//! * A folder is renamed only once everything inside it is done.
//!
//! [`scan`] is the dry run: everything that would stop a conversion, found
//! before anything is changed.

use crate::boring::{generate_unique, Contains};
use crate::crypto::{self, protected_ranges, transform_region, Key, Nonce};
use crate::dircache::read_listing;
use crate::durable;
use crate::engine::{key_from_meta, write_new_meta};
use crate::envelope::LEN as ENVELOPE;
use crate::manifest::{is_conflict_copy, is_list_file, Child, Kind, Manifest};
use crate::names;
use crate::Store;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, FileTimes, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Marker at the top of a folder being converted into a drive.
pub const CONVERTING: &str = "converting.idx";
/// Marker at the top of a drive being turned back into a plain folder.
pub const UNCONVERTING: &str = "unconverting.idx";
/// The one file in flight, while it is.
const JOURNAL: &str = "convert-journal.idx";
const JOURNAL_LABEL: &[u8] = b"cloak-convert-journal-v2";
const META: &str = "meta.json";

/// Names a drive keeps for itself at its top level (besides folder lists).
const ROOT_RESERVED: &[&str] = &[META, "journal.idx", CONVERTING, UNCONVERTING, JOURNAL];

/// Is a conversion either way under way in `dir`?
pub fn in_progress(dir: &Path) -> bool {
    dir.join(CONVERTING).exists() || dir.join(UNCONVERTING).exists()
}

/// Operating-system clutter that is deleted rather than converted.
fn is_litter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), ".ds_store" | "thumbs.db" | "ehthumbs.db" | "desktop.ini") || name.starts_with("._")
}

/// Does a drive use this name for its own files (a folder list, or at the
/// top `meta.json` and the journals), or a crash's side file of one?
pub(crate) fn is_reserved(name: &str, at_root: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(durable::SIDE_SUFFIX).unwrap_or(&lower);
    is_list_file(stem) || is_conflict_copy(stem) || (at_root && ROOT_RESERVED.contains(&stem))
}

/// The real name a name on disk stands for: on Windows, the characters it
/// can't store come through the same private-use look-alikes the Windows
/// adapter shows them as.
fn real_name(disk: &str) -> String {
    #[cfg(windows)]
    let disk = names::from_windows(disk);
    names::normalize(&disk)
}

/// The name on disk for a real name (the reverse of [`real_name`]).
fn disk_name(real: &str) -> String {
    #[cfg(windows)]
    return names::to_windows(real);
    #[cfg(not(windows))]
    real.to_string()
}

/// What a conversion of a folder would do, and what stops it.
#[derive(Serialize, Debug, Default)]
pub struct Report {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    /// How many of those bytes get encrypted (each file's ends).
    pub encrypt_bytes: u64,
    /// Clutter (`.DS_Store`, `Thumbs.db`, …) that will be deleted.
    pub litter: Vec<String>,
    /// Each must be fixed before the folder can be converted.
    pub problems: Vec<Problem>,
    /// Worth knowing, but not in the way.
    pub warnings: Vec<String>,
    /// A conversion was interrupted here and will pick up where it stopped.
    pub resume: bool,
}

#[derive(Serialize, Debug)]
pub struct Problem {
    /// Relative to the folder, `/`-separated.
    pub path: String,
    pub problem: String,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }

    fn problem(&mut self, path: &str, problem: impl Into<String>) {
        self.problems.push(Problem { path: path.to_string(), problem: problem.into() });
    }
}

/// Folders these services sync: converting rewrites every file in them, and
/// the service keeps the plain originals in its version history.
const SYNCED: &[&str] = &["onedrive", "dropbox", "google drive", "icloud drive", "mobile documents", "box sync", "pcloud"];

/// The dry run: what converting `dir` would do and anything that stops it.
/// Changes nothing.
pub fn scan(dir: &Path, region: u64) -> io::Result<Report> {
    if !dir.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no such folder"));
    }
    let mut report = Report::default();
    if dir.join(CONVERTING).exists() && dir.join(META).exists() {
        report.resume = true;
        return Ok(report);
    }
    if dir.join(META).exists() {
        report.problem("", "this folder is already a cloak drive");
        return Ok(report);
    }
    let shown = dir.to_string_lossy().to_lowercase();
    if let Some(service) = SYNCED.iter().find(|s| shown.contains(*s)) {
        report.warnings.push(format!(
            "this folder looks like it's synced ({service}): converting rewrites every file, \
             and the sync service may keep the unconverted originals in its version history"
        ));
    }
    scan_dir(dir, "", region, &mut report)?;
    Ok(report)
}

fn scan_dir(dir: &Path, rel: &str, region: u64, report: &mut Report) -> io::Result<()> {
    let at_root = rel.is_empty();
    let mut seen: HashMap<String, String> = HashMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            let path = crate::inodes::join(rel, &entry.file_name().to_string_lossy());
            report.problem(&path, "its name isn't valid text; rename it");
            continue;
        };
        let path = crate::inodes::join(rel, &name);
        if is_litter(&name) && ft.is_file() {
            report.litter.push(path);
            continue;
        }
        if is_reserved(&name, at_root) {
            report.problem(&path, "cloak uses this name for its own files; rename it");
            continue;
        }
        let real = real_name(&name);
        if let Err(e) = names::validate(&real) {
            report.problem(&path, format!("its name can't be used in a drive ({e})"));
            continue;
        }
        if let Some(first) = seen.insert(names::fold(&real), path.clone()) {
            report.problem(&path, format!("has the same name as {first} apart from case or accents"));
            continue;
        }
        if ft.is_symlink() {
            report.problem(&path, "is a link; a drive can't hold links");
        } else if ft.is_dir() {
            report.folders += 1;
            scan_dir(&entry.path(), &path, region, report)?;
        } else if ft.is_file() {
            let meta = entry.metadata()?;
            report.files += 1;
            report.bytes += meta.len();
            report.encrypt_bytes += protected_ranges(meta.len(), region).iter().map(|(s, e)| e - s).sum::<u64>();
            if meta.permissions().readonly() {
                report.problem(&path, "is read-only");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    report.problem(&path, "has other hard links, which would be changed too");
                }
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                // FILE_ATTRIBUTE_OFFLINE, _RECALL_ON_OPEN, _RECALL_ON_DATA_ACCESS
                if meta.file_attributes() & (0x1000 | 0x4_0000 | 0x40_0000) != 0 {
                    report.problem(&path, "is only in the cloud (not downloaded to this computer)");
                }
            }
        } else {
            report.problem(&path, "isn't an ordinary file or folder");
        }
    }
    Ok(())
}

/// Progress through a run: files done so far, out of all files.
pub type Progress<'a> = &'a mut dyn FnMut(u64, u64);

/// Convert `dir` into a drive protected by `passphrase`, in place. Runs the
/// [`scan`] first and changes nothing if it finds problems. If an earlier run
/// was interrupted, carries on from where it stopped (with the same password).
pub fn convert(dir: &Path, passphrase: &str, region: u64, progress: Progress) -> io::Result<()> {
    convert_until(dir, passphrase, region, progress, None)
}

/// Turn the drive in `dir` back into a plain folder in place, removing
/// everything cloak keeps there. The drive must not be unlocked. If an
/// earlier run was interrupted, carries on from where it stopped.
pub fn unconvert(dir: &Path, passphrase: &str, progress: Progress) -> io::Result<()> {
    unconvert_until(dir, passphrase, progress, None)
}

/// Where a test run stops, standing in for a crash.
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
enum Stop {
    /// After this many files are done.
    After(u64),
    /// Part-way through file number `n` (counting from 1): its ends changed,
    /// its rename not yet made.
    Within(u64),
}

fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "stopped (test)")
}

fn convert_until(dir: &Path, passphrase: &str, region: u64, progress: Progress, stop: Option<Stop>) -> io::Result<()> {
    let marker = dir.join(CONVERTING);
    let meta = dir.join(META);
    let (key, region) = if marker.exists() && meta.exists() {
        key_from_meta(&fs::read(&meta)?, passphrase)?
    } else {
        if marker.exists() {
            fs::remove_file(&marker)?; // stopped before anything was changed
        }
        let report = scan(dir, region)?;
        if let Some(p) = report.problems.first() {
            let more = report.problems.len() - 1;
            let what = if p.path.is_empty() { p.problem.clone() } else { format!("{} {}", p.path, p.problem) };
            let more = if more > 0 { format!(" (and {more} more)") } else { String::new() };
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{what}{more}")));
        }
        // The marker goes first: a folder with meta.json and no marker would
        // open as an empty drive.
        durable::write_synced(&marker, b"")?;
        durable::sync_dir(dir)?;
        (write_new_meta(dir, passphrase, region)?, region)
    };
    let mut run = Run::new(dir, key, region, progress, stop)?;
    run.recover()?;
    run.convert_dir(dir, true, None)?;
    fs::remove_file(&marker)?;
    durable::sync_dir(dir)
}

fn unconvert_until(dir: &Path, passphrase: &str, progress: Progress, stop: Option<Stop>) -> io::Result<()> {
    let marker = dir.join(UNCONVERTING);
    let meta = dir.join(META);
    if !meta.exists() {
        if marker.exists() {
            return fs::remove_file(&marker); // finished all but the marker
        }
        return Err(io::Error::new(io::ErrorKind::NotFound, "no drive here"));
    }
    if dir.join(CONVERTING).exists() {
        return Err(io::Error::other("this folder is part-way through being converted; finish converting it first"));
    }
    let (key, region) = key_from_meta(&fs::read(&meta)?, passphrase)?;
    if !marker.exists() {
        // Let the engine finish anything a crash left half done and fold in
        // sync tools' copies of lists, so the lists read here are whole.
        drop(Store::open(dir, key, region)?);
        check_names_out(dir, &key, true)?;
        durable::write_synced(&marker, b"")?;
        durable::sync_dir(dir)?;
    }
    let mut run = Run::new(dir, key, region, progress, stop)?;
    run.recover()?;
    run.unconvert_dir(dir, true)?;
    fs::remove_file(&meta)?;
    fs::remove_file(&marker)?;
    durable::sync_dir(dir)
}

/// Refuse to start turning a drive back if a real name would land on a name
/// cloak is still using in that folder while it works.
fn check_names_out(dir: &Path, key: &Key, at_root: bool) -> io::Result<()> {
    for c in read_listing(dir, key)?.children {
        let out = disk_name(&c.real);
        if is_reserved(&out, at_root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("“{}” has a name cloak uses for its own files; rename it in the drive first", c.real),
            ));
        }
        if c.is_dir() && dir.join(&c.boring).is_dir() {
            check_names_out(&dir.join(&c.boring), key, false)?;
        }
    }
    Ok(())
}

/// The file being changed, written before its ends are touched.
#[derive(Serialize, Deserialize)]
struct InFlight {
    /// Its folder, relative to the top, `/`-separated, as named on disk now.
    dir: String,
    /// Its name before the change, and after.
    from: String,
    to: String,
    /// Its ends (and envelope, if it had one) as they were, and its length.
    ranges: Vec<(u64, Vec<u8>)>,
    len: u64,
    accessed: Option<SystemTime>,
    modified: Option<SystemTime>,
}

/// Boring names already used in a folder, compared ignoring case (the disk
/// may not tell `a` from `A`).
struct Taken<'a>(&'a HashSet<String>);

impl Contains for Taken<'_> {
    fn contains(&self, name: &str) -> bool {
        name.starts_with("manifest") || self.0.contains(&name.to_ascii_lowercase())
    }
}

/// Which way a file is going.
#[allow(clippy::large_enum_variant)] // one at a time, briefly
enum Way {
    /// Into a drive: its ends encrypted, this envelope added.
    In([u8; ENVELOPE as usize]),
    /// Out of a drive: its ends decrypted, its envelope removed.
    Out,
}

struct Run<'a> {
    root: PathBuf,
    key: Key,
    region: u64,
    done: u64,
    total: u64,
    progress: Progress<'a>,
    stop: Option<Stop>,
}

impl<'a> Run<'a> {
    fn new(root: &Path, key: Key, region: u64, progress: Progress<'a>, stop: Option<Stop>) -> io::Result<Self> {
        let total = count_files(root, true)?;
        Ok(Run { root: root.to_path_buf(), key, region, done: 0, total, progress, stop })
    }

    fn tick(&mut self, files: u64) -> io::Result<()> {
        self.done += files;
        (self.progress)(self.done, self.total);
        match self.stop {
            Some(Stop::After(n)) if self.done >= n => Err(interrupted()),
            _ => Ok(()),
        }
    }

    fn rel(&self, dir: &Path) -> String {
        let rel = dir.strip_prefix(&self.root).unwrap_or(Path::new(""));
        rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/")
    }

    fn journal(&self) -> PathBuf {
        self.root.join(JOURNAL)
    }

    /// Finish what a stopped run left: a file whose rename wasn't made gets
    /// its original ends back, so this run does it again from the start.
    fn recover(&self) -> io::Result<()> {
        let Ok(bytes) = fs::read(self.journal()) else {
            return Ok(());
        };
        // Unreadable means it was torn while being written, before its file
        // was touched.
        let opened = crypto::open(&self.key, JOURNAL_LABEL, &bytes);
        if let Some(j) = opened.ok().and_then(|b| serde_json::from_slice::<InFlight>(&b).ok()) {
            let from = self.root.join(&j.dir).join(&j.from);
            if from.exists() {
                let mut f = OpenOptions::new().write(true).open(&from)?;
                let end = j.ranges.iter().map(|(s, b)| s + b.len() as u64).max().unwrap_or(0);
                f.set_len(j.len.max(end))?;
                for (s, buf) in &j.ranges {
                    f.seek(SeekFrom::Start(*s))?;
                    f.write_all(buf)?;
                }
                f.set_len(j.len)?;
                f.sync_data()?;
                set_times(&f, j.accessed, j.modified);
            }
        }
        fs::remove_file(self.journal())
    }

    /// Transform `from`'s ends in `dir` with the file's key and nonce
    /// (encrypting or decrypting: the same operation), add or remove its
    /// envelope, and rename it `to`, keeping its times.
    fn process_file(&mut self, dir: &Path, from: &str, to: &str, crypt: (Key, Nonce), way: Way) -> io::Result<()> {
        let path = dir.join(from);
        let mut f = OpenOptions::new().read(true).write(true).open(&path).map_err(|e| {
            io::Error::new(e.kind(), format!("couldn't change {} (is it open in another program?): {e}", path.display()))
        })?;
        let meta = f.metadata()?;
        let (accessed, modified) = (meta.accessed().ok(), meta.modified().ok());
        let len = meta.len();
        let data = match way {
            Way::In(_) => len,
            Way::Out => len.checked_sub(ENVELOPE).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{} is damaged (too short)", path.display()))
            })?,
        };
        let mut ranges = Vec::new();
        for (s, e) in protected_ranges(data, self.region) {
            let mut buf = vec![0u8; (e - s) as usize];
            f.seek(SeekFrom::Start(s))?;
            f.read_exact(&mut buf)?;
            ranges.push((s, buf));
        }
        if matches!(way, Way::Out) {
            let mut env = vec![0u8; ENVELOPE as usize];
            f.seek(SeekFrom::Start(data))?;
            f.read_exact(&mut env)?;
            ranges.push((data, env));
        }
        let j = InFlight { dir: self.rel(dir), from: from.into(), to: to.into(), ranges, len, accessed, modified };
        durable::write_synced(&self.journal(), &crypto::seal(&self.key, JOURNAL_LABEL, &serde_json::to_vec(&j)?))?;
        for (s, mut buf) in j.ranges.into_iter().filter(|(s, _)| *s < data) {
            transform_region(&crypt.0, &crypt.1, s, &mut buf);
            f.seek(SeekFrom::Start(s))?;
            f.write_all(&buf)?;
        }
        match way {
            Way::In(env) => {
                f.seek(SeekFrom::Start(data))?;
                f.write_all(&env)?;
            }
            Way::Out => f.set_len(data)?,
        }
        f.sync_data()?;
        set_times(&f, accessed, modified);
        drop(f);
        if matches!(self.stop, Some(Stop::Within(n)) if self.done + 1 == n) {
            return Err(interrupted());
        }
        fs::rename(&path, dir.join(to))?;
        durable::sync_dir(dir)?;
        fs::remove_file(self.journal())
    }

    /// Convert the folder `dir`, whose real name is `name` (none for the top).
    fn convert_dir(&mut self, dir: &Path, at_root: bool, name: Option<&str>) -> io::Result<()> {
        let listed = crate::manifest::Manifest::path_in(dir).exists();
        let mut plan: Vec<Child> = if listed { read_listing(dir, &self.key)?.children } else { Vec::new() };

        // What's on disk: boring names already done, real names to do.
        let mut on_disk: Vec<(String, fs::FileType)> = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_str().map(str::to_string).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("a name in {} isn't valid text", dir.display()))
            })?;
            if !is_reserved(&name, at_root) {
                on_disk.push((name, entry.file_type()?));
            }
        }
        let planned_boring: HashSet<String> = plan.iter().map(|c| c.boring.to_ascii_lowercase()).collect();
        let planned_real: HashSet<String> = plan.iter().map(|c| names::fold(&c.real)).collect();
        let mut taken: HashSet<String> = on_disk.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        taken.extend(planned_boring.iter().cloned());
        let mut real_on_disk: HashMap<String, String> = HashMap::new();
        let mut changed = !listed;

        for (disk, ft) in &on_disk {
            if planned_boring.contains(&disk.to_ascii_lowercase()) {
                continue;
            }
            if is_litter(disk) && ft.is_file() {
                fs::remove_file(dir.join(disk))?;
                continue;
            }
            let real = real_name(disk);
            let key = names::fold(&real);
            real_on_disk.insert(key.clone(), disk.clone());
            if planned_real.contains(&key) {
                continue;
            }
            // New since the plan (or no plan yet).
            names::validate(&real).map_err(|e| {
                io::Error::new(e.kind(), format!("{} can't be used in a drive: {e}", dir.join(disk).display()))
            })?;
            let kind = if ft.is_dir() {
                Kind::Dir
            } else if ft.is_file() {
                Kind::File
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} isn't an ordinary file or folder", dir.join(disk).display()),
                ));
            };
            let boring = generate_unique(&mut rand::thread_rng(), &Taken(&taken));
            taken.insert(boring.to_ascii_lowercase());
            plan.push(match kind {
                Kind::Dir => Child::dir(real, boring),
                Kind::File => Child::new_file(real, boring, fs::metadata(dir.join(disk))?.len()),
            });
            changed = true;
        }
        // Entries gone from disk since the plan was written.
        let before = plan.len();
        plan.retain(|c| dir.join(&c.boring).exists() || real_on_disk.contains_key(&names::fold(&c.real)));
        changed |= plan.len() != before;
        if changed {
            Manifest { children: plan.clone(), name: name.map(str::to_string), ..Default::default() }
                .save(dir, &self.key)?;
        }

        for c in plan.iter().filter(|c| !c.is_dir()) {
            if !dir.join(&c.boring).exists() {
                let from = &real_on_disk[&names::fold(&c.real)];
                let env = c.envelope().seal(&self.key);
                self.process_file(dir, from, &c.boring, c.crypt(), Way::In(env))?;
            }
            self.tick(1)?;
        }
        for c in plan.iter().filter(|c| c.is_dir()) {
            let done = dir.join(&c.boring);
            if done.exists() {
                self.tick(count_files(&done, false)?)?;
                continue;
            }
            let from = dir.join(&real_on_disk[&names::fold(&c.real)]);
            self.convert_dir(&from, false, Some(&c.real))?;
            fs::rename(&from, &done)?;
            durable::sync_dir(dir)?;
        }
        Ok(())
    }

    fn unconvert_dir(&mut self, dir: &Path, at_root: bool) -> io::Result<()> {
        let children = read_listing(dir, &self.key)?.children;
        for c in children.iter().filter(|c| !c.is_dir()) {
            if dir.join(&c.boring).exists() {
                self.process_file(dir, &c.boring, &disk_name(&c.real), c.crypt(), Way::Out)?;
            }
            self.tick(1)?;
        }
        for c in children.iter().filter(|c| c.is_dir()) {
            let from = dir.join(&c.boring);
            if from.exists() {
                self.unconvert_dir(&from, false)?;
                fs::rename(&from, dir.join(disk_name(&c.real)))?;
                durable::sync_dir(dir)?;
            } else {
                self.tick(count_files(&dir.join(disk_name(&c.real)), false)?)?;
            }
        }
        // The folder's list (and any sync tool's copies of it) last.
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_reserved(&name, false) && entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
            }
        }
        if at_root {
            for name in ["journal.idx", "journal.idx.new", "meta.json.new"] {
                let _ = fs::remove_file(dir.join(name));
            }
        }
        durable::sync_dir(dir)
    }
}

/// Files under `dir`, leaving out cloak's own and clutter.
fn count_files(dir: &Path, at_root: bool) -> io::Result<u64> {
    let mut n = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_reserved(&name, at_root) || is_litter(&name) {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            n += count_files(&entry.path(), false)?;
        } else if ft.is_file() {
            n += 1;
        }
    }
    Ok(n)
}

/// Put a file's times back after changing it (best effort: some disks keep
/// only some of them).
fn set_times(f: &fs::File, accessed: Option<SystemTime>, modified: Option<SystemTime>) {
    let mut times = FileTimes::new();
    if let Some(t) = accessed {
        times = times.set_accessed(t);
    }
    if let Some(t) = modified {
        times = times.set_modified(t);
    }
    let _ = f.set_times(times);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const REGION: u64 = 16;

    fn no_progress() -> impl FnMut(u64, u64) {
        |_, _| {}
    }

    /// A small tree: files below, at and above twice the region, an empty
    /// file, a nested folder, an accented name, and clutter.
    fn fill(dir: &Path) -> Vec<(&'static str, Vec<u8>)> {
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("small.txt", b"tiny".to_vec()),
            ("exact.bin", (0..32u8).collect()),
            ("large.bin", (0..1000u32).map(|i| (i * 7) as u8).collect()),
            ("empty.dat", Vec::new()),
            ("Photos/caf\u{e9}.jpg", (0..300u32).map(|i| i as u8).collect()),
            ("Photos/2024/deep.txt", b"deep inside".repeat(20)),
        ];
        for (path, bytes) in &files {
            let p = dir.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        }
        fs::create_dir_all(dir.join("Empty folder")).unwrap();
        fs::write(dir.join("Photos/.DS_Store"), b"junk").unwrap();
        files
    }

    fn assert_drive_holds(dir: &Path, files: &[(&str, Vec<u8>)]) {
        let store = Store::open_with_passphrase(dir, "pw").unwrap();
        for (path, bytes) in files {
            assert_eq!(&store.read_all(path).unwrap(), bytes, "{path}");
        }
        let top: Vec<String> = store.list_entries("").unwrap().into_iter().map(|e| e.name).collect();
        assert!(top.contains(&"Empty folder".to_string()), "{top:?}");
        let photos: Vec<String> = store.list_entries("Photos").unwrap().into_iter().map(|e| e.name).collect();
        assert!(!photos.iter().any(|n| n == ".DS_Store"), "{photos:?}");
    }

    fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let name = e.file_name().to_string_lossy().into_owned();
                let path = crate::inodes::join(rel, &name);
                if e.file_type().unwrap().is_dir() {
                    out.push((format!("{path}/"), Vec::new()));
                    walk(&e.path(), &path, out);
                } else {
                    out.push((path, fs::read(e.path()).unwrap()));
                }
            }
        }
        walk(dir, "", &mut out);
        out.sort();
        out
    }

    #[test]
    fn converts_in_place_and_the_drive_reads_back() {
        let d = tempdir().unwrap();
        let files = fill(d.path());
        let mtime = fs::metadata(d.path().join("large.bin")).unwrap().modified().unwrap();
        convert(d.path(), "pw", REGION, &mut no_progress()).unwrap();

        // Nothing under its real name is left, nor any clutter or marker.
        assert!(!d.path().join("large.bin").exists());
        assert!(!d.path().join("Photos").exists());
        assert!(!in_progress(d.path()));
        assert!(!d.path().join(JOURNAL).exists());
        assert_drive_holds(d.path(), &files);

        // The file kept its time, and only its ends changed on disk.
        let store = Store::open_with_passphrase(d.path(), "pw").unwrap();
        let m = store.metadata("large.bin").unwrap().unwrap();
        assert_eq!(m.modified, mtime);
        let listing = read_listing(d.path(), &key_from_meta(&fs::read(d.path().join(META)).unwrap(), "pw").unwrap().0)
            .unwrap();
        let large = listing.children.iter().find(|c| c.real == "large.bin").unwrap();
        let raw = fs::read(d.path().join(&large.boring)).unwrap();
        let original = &files.iter().find(|f| f.0 == "large.bin").unwrap().1;
        assert_eq!(raw[16..984], original[16..984]);
        assert_ne!(raw[..16], original[..16]);
        assert_ne!(raw[984..], original[984..]);
    }

    #[test]
    fn progress_counts_every_file() {
        let d = tempdir().unwrap();
        fill(d.path());
        let mut last = (0, 0);
        convert(d.path(), "pw", REGION, &mut |done, total| last = (done, total)).unwrap();
        assert_eq!(last, (6, 6));
    }

    #[test]
    fn scan_reports_what_would_stop_it_and_changes_nothing() {
        let d = tempdir().unwrap();
        fill(d.path());
        // Differs from café.jpg only in case: a second file only where the
        // disk is case-sensitive (Linux); elsewhere it's the same file.
        fs::write(d.path().join("Photos/CAF\u{c9}.JPG"), b"clash").unwrap();
        let clash = fs::read_dir(d.path().join("Photos")).unwrap().count() == 4;
        fs::write(d.path().join("meta.json"), b"{}").unwrap();
        fs::create_dir_all(d.path().join("sub")).unwrap();
        fs::write(d.path().join("sub/manifest.idx"), b"mine").unwrap();
        let before = snapshot(d.path());

        // A meta.json at the top reads as an existing drive.
        let report = scan(d.path(), REGION).unwrap();
        assert!(!report.ok());
        assert_eq!(report.problems[0].problem, "this folder is already a cloak drive");
        fs::remove_file(d.path().join("meta.json")).unwrap();

        let report = scan(d.path(), REGION).unwrap();
        let paths: Vec<&str> = report.problems.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(report.problems.len(), 1 + clash as usize, "{:?}", report.problems);
        assert!(paths.contains(&"sub/manifest.idx"));
        assert_eq!(paths.iter().any(|p| p.starts_with("Photos/")), clash);
        assert_eq!(report.litter, vec!["Photos/.DS_Store".to_string()]);
        assert_eq!(report.files, 6); // fill's 6: the clash and sub's file are problems instead
        assert!(report.encrypt_bytes < report.bytes);

        // Converting refuses, and leaves the folder as it was.
        let err = convert(d.path(), "pw", REGION, &mut no_progress()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let mut after = snapshot(d.path());
        after.retain(|(p, _)| p != "meta.json");
        let mut expected = before;
        expected.retain(|(p, _)| p != "meta.json");
        assert_eq!(after, expected);
        assert!(!in_progress(d.path()));
    }

    #[test]
    fn read_only_files_are_reported() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("locked.txt"), b"x").unwrap();
        let mut perms = fs::metadata(d.path().join("locked.txt")).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(d.path().join("locked.txt"), perms.clone()).unwrap();
        let report = scan(d.path(), REGION).unwrap();
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].problem, "is read-only");
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(d.path().join("locked.txt"), perms).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn links_are_reported() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("a.txt"), b"a").unwrap();
        std::os::unix::fs::symlink("a.txt", d.path().join("link")).unwrap();
        fs::hard_link(d.path().join("a.txt"), d.path().join("b.txt")).unwrap();
        let report = scan(d.path(), REGION).unwrap();
        assert_eq!(report.problems.len(), 3, "{:?}", report.problems);
    }

    #[test]
    fn the_engine_wont_open_a_folder_part_way_through() {
        let d = tempdir().unwrap();
        let files = fill(d.path());
        let err = convert_until(d.path(), "pw", REGION, &mut no_progress(), Some(Stop::After(3))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(in_progress(d.path()));
        assert!(Store::open_with_passphrase(d.path(), "pw").is_err());
        assert!(scan(d.path(), REGION).unwrap().resume);

        convert(d.path(), "pw", REGION, &mut no_progress()).unwrap();
        assert_drive_holds(d.path(), &files);
    }

    #[test]
    fn a_run_stopped_at_any_point_resumes_to_the_same_drive() {
        for n in 1..=6 {
            for within in [false, true] {
                let d = tempdir().unwrap();
                let files = fill(d.path());
                let stop = if within { Stop::Within(n) } else { Stop::After(n) };
                let result = convert_until(d.path(), "pw", REGION, &mut no_progress(), Some(stop));
                if n < 6 || within {
                    assert!(result.is_err(), "stop {n} within {within}");
                }
                // Stopping twice in a row is no different.
                let _ = convert_until(d.path(), "pw", REGION, &mut no_progress(), Some(Stop::Within(n.min(5) + 1)));
                if in_progress(d.path()) {
                    convert(d.path(), "pw", REGION, &mut no_progress()).unwrap();
                }
                assert_drive_holds(d.path(), &files);
            }
        }
    }

    #[test]
    fn resuming_needs_the_same_password() {
        let d = tempdir().unwrap();
        fill(d.path());
        let _ = convert_until(d.path(), "pw", REGION, &mut no_progress(), Some(Stop::After(2)));
        let err = convert(d.path(), "other", REGION, &mut no_progress()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn files_added_before_resuming_are_converted_too() {
        let d = tempdir().unwrap();
        let mut files = fill(d.path());
        let _ = convert_until(d.path(), "pw", REGION, &mut no_progress(), Some(Stop::After(2)));
        fs::write(d.path().join("late.txt"), b"added later").unwrap();
        files.push(("late.txt", b"added later".to_vec()));
        convert(d.path(), "pw", REGION, &mut no_progress()).unwrap();
        assert_drive_holds(d.path(), &files);
    }

    #[test]
    fn unconvert_gives_back_the_original_folder() {
        let d = tempdir().unwrap();
        fill(d.path());
        fs::remove_file(d.path().join("Photos/.DS_Store")).unwrap(); // clutter isn't kept
        let original = snapshot(d.path());
        convert(d.path(), "pw", REGION, &mut no_progress()).unwrap();
        // Use it as a drive in between, including a change.
        {
            let mut s = Store::open_with_passphrase(d.path(), "pw").unwrap();
            s.write_at("small.txt", 0, b"TINY").unwrap();
            s.sync().unwrap();
        }
        unconvert(d.path(), "pw", &mut no_progress()).unwrap();
        let mut expected = original;
        for (p, b) in expected.iter_mut() {
            if p == "small.txt" {
                *b = b"TINY".to_vec();
            }
        }
        assert_eq!(snapshot(d.path()), expected);
    }

    #[test]
    fn an_unconvert_stopped_at_any_point_resumes() {
        for n in 1..=6 {
            let d = tempdir().unwrap();
            fill(d.path());
            fs::remove_file(d.path().join("Photos/.DS_Store")).unwrap();
            let original = snapshot(d.path());
            convert(d.path(), "pw", REGION, &mut no_progress()).unwrap();
            let err = unconvert_until(d.path(), "pw", &mut no_progress(), Some(Stop::Within(n))).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Interrupted);
            assert!(Store::open_with_passphrase(d.path(), "pw").is_err());
            unconvert(d.path(), "pw", &mut no_progress()).unwrap();
            assert_eq!(snapshot(d.path()), original, "stopped within file {n}");
        }
    }

    #[test]
    fn unconvert_refuses_a_name_cloak_still_needs() {
        let d = tempdir().unwrap();
        let mut s = Store::create_with_passphrase(d.path(), "pw", REGION).unwrap();
        s.create("journal.idx").unwrap();
        s.sync().unwrap();
        drop(s);
        let err = unconvert(d.path(), "pw", &mut no_progress()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!in_progress(d.path()));
        assert!(Store::open_with_passphrase(d.path(), "pw").is_ok());
    }
}
