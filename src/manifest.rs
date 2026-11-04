//! Per-directory manifest (Approach A).
//!
//! Each logical directory is a real on-disk directory with a *boring* name, and
//! inside it sits one manifest file listing that directory's immediate children:
//! for each child, its real name, its boring on-disk name, whether it's a file
//! or subdirectory, and (for files) the per-file crypto params.
//!
//! The manifest holds real names and file keys, so it is sealed
//! (XChaCha20-Poly1305 under the master key, see [`crate::crypto::seal`]): a
//! damaged or tampered list fails to open rather than reading as garbage. It
//! also records the folder's own real name, so a folder moved elsewhere
//! still knows what it's called. Losing one manifest costs nothing for good:
//! every file carries an envelope (see [`crate::envelope`]) the list can be
//! rebuilt from. Saves go through [`crate::durable::write_atomic`], so a
//! crash never leaves one torn.
//!
//! When a store folder is synced between machines and both change the same
//! folder, the sync tool keeps both manifests by renaming one
//! (`manifest (conflicted copy).idx`, `manifest-PC.idx`,
//! `manifest.sync-conflict-….idx`, `manifest 2.idx`). [`merge_conflicts`]
//! folds those back in so neither side's files go missing.
//!
//! A very large directory's list is split across parts (`manifest.p00.idx`
//! …), so a change rewrites one part instead of the whole list; `manifest.idx`
//! then holds only a tag per part. See [`crate::dircache`], which reads and
//! writes listings in either form.

use crate::crypto::{self, Key, Nonce, NONCE_LEN};
use crate::durable;
use crate::envelope::{self, Envelope, FileId};
use crate::names;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// Reserved filename for the manifest within each on-disk directory. The boring
/// generator never produces this (it always appends `_NNNN`), and callers also
/// pass it as a reserved name so no child can collide with it.
pub const MANIFEST_NAME: &str = "manifest.idx";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Kind {
    Dir,
    File,
}

/// One child entry in a directory's manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Child {
    /// Name the user sees, e.g. `Taxes` or `Return.pdf`.
    pub real: String,
    /// Boring on-disk name within this directory, e.g. `index_shard_0472.idx`.
    pub boring: String,
    pub kind: Kind,
    /// The file's random ID (zero for directories).
    pub id: FileId,
    /// The file's own key, for its encrypted ends (zero for directories).
    pub key: Key,
    /// The file's current content nonce (zero for directories).
    pub nonce: [u8; NONCE_LEN],
    /// Plaintext file size when the entry was last saved (0 for directories).
    /// Only a hint: the boring file's length on disk is authoritative, since
    /// writes no longer rewrite the manifest.
    pub size: u64,
}

impl Child {
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Dir
    }

    /// A folder's entry.
    pub fn dir(real: String, boring: String) -> Child {
        Child { real, boring, kind: Kind::Dir, id: [0; 16], key: [0; 32], nonce: [0; NONCE_LEN], size: 0 }
    }

    /// A new file's entry, with a fresh ID, key and nonce.
    pub fn new_file(real: String, boring: String, size: u64) -> Child {
        Child {
            real,
            boring,
            kind: Kind::File,
            id: envelope::new_id(),
            key: envelope::new_key(),
            nonce: envelope::new_nonce(),
            size,
        }
    }

    /// The entry for a file found under `boring` with this envelope.
    pub fn from_envelope(e: Envelope, boring: String, size: u64) -> Child {
        Child { real: e.name, boring, kind: Kind::File, id: e.id, key: e.key, nonce: e.nonce, size }
    }

    /// A file's envelope, describing it as this entry does.
    pub fn envelope(&self) -> Envelope {
        Envelope { id: self.id, key: self.key, nonce: self.nonce, name: self.real.clone() }
    }

    /// The file's key and nonce together.
    pub fn crypt(&self) -> (Key, Nonce) {
        (self.key, self.nonce)
    }
}

/// The decrypted contents of one directory's manifest.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub children: Vec<Child>,
    /// The folder's own real name (none for the drive's top folder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// In a split directory's `manifest.idx`: the tag each part was last
    /// written with, so a part that hasn't caught up (a sync tool delivering
    /// files one at a time) is noticed. Empty for a list kept in one file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<u64>,
    /// In a part file: the tag it was written with.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tag: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Parts a directory's list is split into once it outgrows one file.
pub const PARTS: usize = 64;

/// The file holding part `i` of a split list.
pub fn part_name(i: usize) -> String {
    format!("manifest.p{i:02}.idx")
}

/// Does a file with this name hold (part of) a folder list? `manifest.idx`
/// or one of its parts; not a side file or a sync tool's conflict copy.
pub fn is_list_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == MANIFEST_NAME || is_part_name(&lower)
}

fn is_part_name(lower: &str) -> bool {
    lower.len() == 16
        && lower.starts_with("manifest.p")
        && lower.ends_with(".idx")
        && lower[10..12].bytes().all(|b| b.is_ascii_digit())
}

/// Which of `parts` parts holds the child with this boring name. Keyed by the
/// boring name, which a rename never changes, so a rename touches one part.
/// FNV-1a: it must give the same answer on every machine and Rust version.
pub fn part_of(boring: &str, parts: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in boring.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h % parts as u64) as usize
}

impl Manifest {
    /// Path of the manifest file inside the on-disk directory `dir`.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(MANIFEST_NAME)
    }

    /// Load and decrypt the manifest for `dir`. A directory with no manifest
    /// file yet (freshly created, or empty) reads as an empty manifest.
    pub fn load(dir: &Path, key: &Key) -> io::Result<Manifest> {
        let path = Self::path_in(dir);
        if !path.exists() {
            return Ok(Manifest::default());
        }
        Self::load_file(&path, key)
    }

    fn load_file(path: &Path, key: &Key) -> io::Result<Manifest> {
        Self::from_sealed(std::fs::read(path)?, key)
    }

    /// Decrypt and parse a manifest file's bytes.
    pub fn from_sealed(bytes: Vec<u8>, key: &Key) -> io::Result<Manifest> {
        if bytes.is_empty() {
            return Ok(Manifest::default());
        }
        Ok(serde_json::from_slice(&unseal(bytes, key)?)?)
    }

    /// Encrypt and write the manifest into `dir`, with a fresh random nonce.
    pub fn save(&self, dir: &Path, key: &Key) -> io::Result<()> {
        durable::write_atomic(&Self::path_in(dir), &seal(serde_json::to_vec(self)?, key))
    }

    // Name matching is case-insensitive and Unicode-normalization-insensitive:
    // a mounted drive is case-insensitive on both Windows and macOS, the OS hands
    // names back in varying case (Windows sends an uppercased source name on
    // rename), and macOS sends decomposed (NFD) accents where Windows sends
    // composed (NFC). See `names::same`. The stored name keeps its case.
    pub fn find(&self, real: &str) -> Option<&Child> {
        self.children.iter().find(|c| names::same(&c.real, real))
    }

    pub fn position(&self, real: &str) -> Option<usize> {
        self.children.iter().position(|c| names::same(&c.real, real))
    }

    /// The set of boring names in use here, plus the reserved manifest name, so
    /// the boring-name generator never collides with a sibling or the manifest.
    pub fn used_boring_names(&self) -> std::collections::HashSet<String> {
        let mut set: std::collections::HashSet<String> =
            self.children.iter().map(|c| c.boring.clone()).collect();
        set.insert(MANIFEST_NAME.to_string());
        set
    }
}

/// What a list is sealed as (see [`crypto::seal`]).
const LIST: &[u8] = b"cloak-list-v2";

/// Seal a list's JSON with the master key.
pub fn seal(body: Vec<u8>, key: &Key) -> Vec<u8> {
    crypto::seal(key, LIST, &body)
}

/// Undo [`seal`]; `InvalidData` if it isn't a list sealed with `key`, or was
/// changed since.
pub fn unseal(bytes: Vec<u8>, key: &Key) -> io::Result<Vec<u8>> {
    crypto::open(key, LIST, &bytes)
}

/// Is `name` a sync tool's renamed copy of a manifest? Boring names never
/// start with `manifest`, so anything else of the form `manifest….idx` is one.
pub fn is_conflict_copy(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower != MANIFEST_NAME
        && !is_part_name(&lower)
        && lower.starts_with("manifest")
        && lower.ends_with(".idx")
}

/// Three-way merge of a directory list: `ours` and `theirs` both started from
/// `base`. Entries are matched by boring name. An entry added on either side
/// is kept, one removed on either side is dropped (unless the other side
/// changed it), and one changed on both sides takes our version. Real names
/// that end up clashing get ` (conflict N)`.
pub fn merge3(base: &[Child], ours: &[Child], theirs: &[Child]) -> Vec<Child> {
    use std::collections::HashMap;
    let by = |v: &[Child]| v.iter().map(|c| (c.boring.clone(), c.clone())).collect::<HashMap<_, _>>();
    let (b, o, t) = (by(base), by(ours), by(theirs));
    let mut out = Vec::new();
    for c in ours {
        match (b.get(&c.boring), t.get(&c.boring)) {
            (None, _) => out.push(c.clone()),                     // we added it
            (Some(_), Some(tc)) if b[&c.boring] == *c => out.push(tc.clone()), // only they changed it
            (Some(_), Some(_)) => out.push(c.clone()),            // we changed it
            (Some(bc), None) if bc != c => out.push(c.clone()),   // they removed, we changed
            (Some(_), None) => {}                                 // they removed it
        }
    }
    for c in theirs {
        if o.contains_key(&c.boring) {
            continue;
        }
        match b.get(&c.boring) {
            None => out.push(c.clone()),                  // they added it
            Some(bc) if bc != c => out.push(c.clone()),   // we removed, they changed
            Some(_) => {}                                 // we removed it
        }
    }
    unique_names(out)
}

/// Rename the later of any two children whose real names clash.
fn unique_names(children: Vec<Child>) -> Vec<Child> {
    let mut kept: Vec<Child> = Vec::with_capacity(children.len());
    let mut seen = std::collections::HashSet::new();
    for mut child in children {
        let original = child.real.clone();
        let mut n = 1;
        while !seen.insert(names::fold(&child.real)) {
            child.real = conflict_name(&original, n);
            n += 1;
        }
        kept.push(child);
    }
    kept
}

/// Fold any sync-conflict copies of `dir`'s manifest back into it, then delete
/// them. Returns how many copies were merged.
///
/// The result is the union of every readable copy, keyed by boring name (the
/// main manifest wins where copies disagree), keeping only entries whose
/// boring file still exists — so a file deleted on one machine stays deleted,
/// and one added on either machine appears. Two different files that ended up
/// with the same real name get ` (conflict N)` added to the later one. A copy
/// that can't be read (wrong key, damaged) is left in place.
pub fn merge_conflicts(dir: &Path, key: &Key) -> io::Result<usize> {
    let mut copies: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().is_some_and(is_conflict_copy))
        .map(|e| e.path())
        .collect();
    if copies.is_empty() {
        return Ok(0);
    }
    copies.sort();

    let main_path = Manifest::path_in(dir);
    let listing = crate::dircache::read_listing(dir, key);
    let parts = listing.as_ref().map_or(0, |l| l.parts);
    let name = listing.as_ref().ok().and_then(|l| l.name.clone());
    let mut merged = Manifest {
        // A damaged main list: rebuild from the copies alone.
        children: listing.map(|l| l.children).unwrap_or_default(),
        ..Manifest::default()
    };
    let mut used = Vec::new();
    for copy in &copies {
        let Ok(other) = Manifest::load_file(copy, key) else {
            continue;
        };
        for child in other.children {
            if !merged.children.iter().any(|c| c.boring == child.boring) {
                merged.children.push(child);
            }
        }
        used.push(copy);
    }
    if used.is_empty() {
        return Ok(0);
    }
    merged.children.retain(|c| dir.join(&c.boring).exists());

    merged.children = unique_names(merged.children);
    crate::dircache::write_listing(dir, key, name.as_deref(), &merged.children, parts, &mut vec![0; parts], None)?;
    for copy in &used {
        if **copy != main_path {
            std::fs::remove_file(copy)?;
        }
    }
    durable::sync_dir(dir)?;
    Ok(used.len())
}

/// `report.pdf` -> `report (conflict 1).pdf`; folders and dotfiles get the tag
/// at the end.
pub fn conflict_name(real: &str, n: usize) -> String {
    match real.rfind('.') {
        Some(dot) if dot > 0 => format!("{} (conflict {n}){}", &real[..dot], &real[dot..]),
        _ => format!("{real} (conflict {n})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dir_child(real: &str, boring: &str) -> Child {
        Child::dir(real.into(), boring.into())
    }

    #[test]
    fn empty_dir_reads_empty() {
        let d = tempdir().unwrap();
        let m = Manifest::load(d.path(), &[1u8; 32]).unwrap();
        assert!(m.children.is_empty());
    }

    #[test]
    fn save_load_roundtrip_and_encrypted_on_disk() {
        let d = tempdir().unwrap();
        let key = [2u8; 32];
        let mut m = Manifest::default();
        m.children.push(dir_child("Taxes", "index_shard_0001.idx"));
        m.children.push(Child::new_file("Return.pdf".into(), "cache_0002.dat".into(), 4242));
        m.save(d.path(), &key).unwrap();

        // On disk, the real names must not appear in the clear.
        let raw = std::fs::read(Manifest::path_in(d.path())).unwrap();
        let hay = String::from_utf8_lossy(&raw);
        assert!(!hay.contains("Return.pdf"), "real names must be encrypted");
        assert!(!hay.contains("Taxes"));

        let back = Manifest::load(d.path(), &key).unwrap();
        assert_eq!(back.children.len(), 2);
        assert_eq!(back.find("Return.pdf").unwrap().size, 4242);
        assert!(back.find("Taxes").unwrap().is_dir());
    }

    #[test]
    fn wrong_key_does_not_decrypt() {
        let d = tempdir().unwrap();
        let mut m = Manifest::default();
        m.children.push(dir_child("Secret", "thumbs_0003.db"));
        m.save(d.path(), &[3u8; 32]).unwrap();
        // A wrong key fails the seal's check.
        assert!(Manifest::load(d.path(), &[4u8; 32]).is_err());
        // So does a changed byte.
        let path = Manifest::path_in(d.path());
        let mut raw = std::fs::read(&path).unwrap();
        raw[30] ^= 1;
        std::fs::write(&path, raw).unwrap();
        assert!(Manifest::load(d.path(), &[3u8; 32]).is_err());
    }

    #[test]
    fn used_names_includes_reserved_manifest() {
        let mut m = Manifest::default();
        m.children.push(dir_child("A", "cache_0001.dat"));
        let used = m.used_boring_names();
        assert!(used.contains("cache_0001.dat"));
        assert!(used.contains(MANIFEST_NAME));
    }

    fn file_child(real: &str, boring: &str) -> Child {
        let mut c = Child::new_file(real.into(), boring.into(), 0);
        // Fixed, so the same entry built twice compares equal.
        (c.id, c.key, c.nonce) = ([1; 16], [1; 32], [1; NONCE_LEN]);
        c
    }

    #[test]
    fn conflict_copy_names() {
        for n in [
            "manifest (Simon's conflicted copy 2026-11-02).idx",
            "manifest-DESKTOP-4F2.idx",
            "manifest.sync-conflict-20261102-101010-ABCDEF.idx",
            "manifest 2.idx",
            "manifest (1).idx",
        ] {
            assert!(is_conflict_copy(n), "{n}");
        }
        for n in ["manifest.idx", "update_manifest_0001.idx", "manifest.idx.new", "cache_0001.idx"] {
            assert!(!is_conflict_copy(n), "{n}");
        }
    }

    #[test]
    fn merges_both_sides_of_a_sync_conflict() {
        let d = tempdir().unwrap();
        let key = [4u8; 32];
        for b in ["cache_0001.dat", "cache_0002.dat", "cache_0003.dat", "cache_0004.dat"] {
            std::fs::write(d.path().join(b), b"x").unwrap();
        }
        // Machine A: added "a.txt"; machine B: added "b.txt". Both had "shared"
        // and "gone.txt" (deleted on one side, so its file is missing). B also
        // created a different "Notes.txt" than A's "notes.txt".
        let mut a = Manifest::default();
        a.children.push(file_child("shared", "cache_0001.dat"));
        a.children.push(file_child("a.txt", "cache_0002.dat"));
        a.children.push(file_child("notes.txt", "cache_0003.dat"));
        a.save(d.path(), &key).unwrap();
        let mut b = Manifest::default();
        b.children.push(file_child("shared", "cache_0001.dat"));
        b.children.push(file_child("gone.txt", "cache_0009.dat"));
        b.children.push(file_child("b.txt", "cache_0004.dat"));
        b.children.push(file_child("Notes.txt", "cache_0005.dat"));
        std::fs::write(d.path().join("cache_0005.dat"), b"y").unwrap();
        b.save(d.path(), &key).unwrap();
        std::fs::rename(Manifest::path_in(d.path()), d.path().join("manifest (conflicted copy).idx")).unwrap();
        a.save(d.path(), &key).unwrap();

        assert_eq!(merge_conflicts(d.path(), &key).unwrap(), 1);
        let m = Manifest::load(d.path(), &key).unwrap();
        let mut names: Vec<&str> = m.children.iter().map(|c| c.real.as_str()).collect();
        names.sort();
        assert_eq!(names, ["Notes (conflict 1).txt", "a.txt", "b.txt", "notes.txt", "shared"]);
        assert!(!d.path().join("manifest (conflicted copy).idx").exists());
        assert_eq!(merge_conflicts(d.path(), &key).unwrap(), 0);
    }
}
