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

use crate::boring::generate_unique;
use crate::crypto::{protected_ranges, transform_region, Key, Nonce, NONCE_LEN};
use crate::key::{self, SALT_LEN};
use crate::manifest::{Child, Kind, Manifest};
use crate::names;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

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
}

/// What a path points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub is_dir: bool,
    pub size: u64,
}

pub struct Store {
    backing_dir: PathBuf,
    key: Key,
    region: u64,
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
        Ok(Self {
            backing_dir,
            key,
            region,
        })
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
        let salt = key::random_salt();
        let derived = key::derive_key(passphrase, &salt);

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
        };
        std::fs::write(&meta_path, serde_json::to_vec_pretty(&meta)?)?;
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
        let meta: StoreMeta = serde_json::from_slice(&std::fs::read(&meta_path)?)?;
        let derived = key::derive_key(passphrase, &meta.salt);

        let mut check = meta.verifier.clone();
        transform_region(&derived, &meta.verifier_nonce, 0, &mut check);
        if check != VERIFY_TOKEN {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong password",
            ));
        }
        Self::open(backing_dir, derived, meta.region)
    }

    // ---- path resolution -------------------------------------------------

    /// Resolve a sequence of directory components to their on-disk path.
    fn resolve_dir(&self, comps: &[String]) -> io::Result<PathBuf> {
        let mut cur = self.backing_dir.clone();
        for name in comps {
            let manifest = Manifest::load(&cur, &self.key)?;
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
            return Ok(Some(Metadata {
                is_dir: true,
                size: 0,
            }));
        }
        let (parent, name) = (comps[..comps.len() - 1].to_vec(), comps[comps.len() - 1].clone());
        let parent_disk = match self.resolve_dir(&parent) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let manifest = Manifest::load(&parent_disk, &self.key)?;
        Ok(manifest.find(&name).map(|c| Metadata {
            is_dir: c.is_dir(),
            size: c.size,
        }))
    }

    /// The path with each component in its stored case (lookups are
    /// case-insensitive, so `photos/A.JPG` may name `Photos/a.jpg`). `None` if
    /// any component is missing. The root is `""`.
    pub fn canonical_path(&self, path: &str) -> io::Result<Option<String>> {
        let comps = components(path);
        let mut cur = self.backing_dir.clone();
        let mut out = Vec::with_capacity(comps.len());
        for (i, name) in comps.iter().enumerate() {
            let manifest = Manifest::load(&cur, &self.key)?;
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
        let disk = self.resolve_dir(&components(path))?;
        let manifest = Manifest::load(&disk, &self.key)?;
        Ok(manifest
            .children
            .iter()
            .map(|c| (c.real.clone(), c.is_dir(), c.size))
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
        let mut manifest = Manifest::load(&parent_disk, &self.key)?;
        if manifest.find(&name).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "name already exists",
            ));
        }
        let boring = generate_unique(&mut rand::thread_rng(), &manifest.used_boring_names());
        std::fs::create_dir_all(parent_disk.join(&boring))?;
        manifest.children.push(Child {
            real: name,
            boring,
            kind: Kind::Dir,
            nonce: [0u8; NONCE_LEN],
            size: 0,
        });
        manifest.save(&parent_disk, &self.key)
    }

    /// Create an empty file at `path` (parent must exist). Returns its boring
    /// name; if the name already exists, returns the existing boring name.
    pub fn create(&mut self, path: &str) -> io::Result<String> {
        let (parent, name) = parent_and_name(path)?;
        names::validate(&name)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let mut manifest = Manifest::load(&parent_disk, &self.key)?;
        if let Some(existing) = manifest.find(&name) {
            if existing.is_dir() {
                return Err(io::Error::new(io::ErrorKind::IsADirectory, "is a directory"));
            }
            return Ok(existing.boring.clone());
        }
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let boring = generate_unique(&mut rand::thread_rng(), &manifest.used_boring_names());
        std::fs::write(parent_disk.join(&boring), [])?;
        manifest.children.push(Child {
            real: name,
            boring: boring.clone(),
            kind: Kind::File,
            nonce,
            size: 0,
        });
        manifest.save(&parent_disk, &self.key)?;
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

    /// Write `data` at `offset`, growing the file if needed. Fast path: a write
    /// that neither changes the size nor touches an encrypted end goes straight
    /// to disk; otherwise read-modify-write the whole file.
    pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> io::Result<()> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let mut manifest = Manifest::load(&parent_disk, &self.key)?;
        let pos = manifest.position(&name).ok_or_else(not_found)?;
        if manifest.children[pos].is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "is a directory"));
        }
        let boring = manifest.children[pos].boring.clone();
        let nonce = manifest.children[pos].nonce;
        let old_size = manifest.children[pos].size;
        let blob = parent_disk.join(&boring);

        let write_end = offset + data.len() as u64;
        let new_size = max(old_size, write_end);

        if new_size == old_size && !range_hits_protected(offset, write_end, old_size, self.region) {
            let mut f = std::fs::OpenOptions::new().write(true).open(&blob)?;
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(data)?;
            return Ok(());
        }

        let mut plain = self.decrypt_blob(&blob, &nonce, old_size)?;
        if new_size as usize > plain.len() {
            plain.resize(new_size as usize, 0);
        }
        plain[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        for (s, e) in protected_ranges(new_size, self.region) {
            transform_region(&self.key, &nonce, s, &mut plain[s as usize..e as usize]);
        }
        std::fs::write(&blob, &plain)?;

        manifest.children[pos].size = new_size;
        manifest.save(&parent_disk, &self.key)
    }

    /// Set a file's length (shorter truncates, longer zero-extends).
    pub fn truncate(&mut self, path: &str, new_size: u64) -> io::Result<()> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let mut manifest = Manifest::load(&parent_disk, &self.key)?;
        let pos = manifest.position(&name).ok_or_else(not_found)?;
        let boring = manifest.children[pos].boring.clone();
        let nonce = manifest.children[pos].nonce;
        let old_size = manifest.children[pos].size;
        let blob = parent_disk.join(&boring);

        let mut plain = self.decrypt_blob(&blob, &nonce, old_size)?;
        plain.resize(new_size as usize, 0);
        for (s, e) in protected_ranges(new_size, self.region) {
            transform_region(&self.key, &nonce, s, &mut plain[s as usize..e as usize]);
        }
        std::fs::write(&blob, &plain)?;
        manifest.children[pos].size = new_size;
        manifest.save(&parent_disk, &self.key)
    }

    /// Delete a file, or a directory and its whole subtree.
    pub fn remove(&mut self, path: &str) -> io::Result<()> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let mut manifest = Manifest::load(&parent_disk, &self.key)?;
        let pos = match manifest.position(&name) {
            Some(p) => p,
            None => return Ok(()),
        };
        let child = manifest.children.remove(pos);
        let target = parent_disk.join(&child.boring);
        match child.kind {
            Kind::File => {
                let _ = std::fs::remove_file(&target);
            }
            Kind::Dir => {
                let _ = std::fs::remove_dir_all(&target);
            }
        }
        manifest.save(&parent_disk, &self.key)
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
        let mut old_manifest = Manifest::load(&old_parent_disk, &self.key)?;
        let pos = old_manifest.position(&old_name).ok_or_else(not_found)?;
        let moving_dir = old_manifest.children[pos].is_dir();
        let new_parent_disk = self.resolve_dir(&new_parent)?;
        let same_parent = old_parent_disk == new_parent_disk;

        // An existing *different* entry at the destination: replace or refuse.
        let target = if same_parent {
            old_manifest.position(&new_name).filter(|&p| p != pos)
        } else {
            Manifest::load(&new_parent_disk, &self.key)?.position(&new_name)
        };
        if target.is_some() {
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
            if dest.is_dir && !self.list_dir(new)?.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::DirectoryNotEmpty,
                    "destination directory not empty",
                ));
            }
            self.remove(new)?;
            // `remove` rewrote the manifest; reload so our copy isn't stale.
            old_manifest = Manifest::load(&old_parent_disk, &self.key)?;
        }
        let pos = old_manifest.position(&old_name).ok_or_else(not_found)?;

        if same_parent {
            old_manifest.children[pos].real = new_name;
            return old_manifest.save(&old_parent_disk, &self.key);
        }

        // Move across directories.
        let mut new_manifest = Manifest::load(&new_parent_disk, &self.key)?;
        let mut moved = old_manifest.children.remove(pos);
        let new_boring = generate_unique(&mut rand::thread_rng(), &new_manifest.used_boring_names());
        std::fs::rename(
            old_parent_disk.join(&moved.boring),
            new_parent_disk.join(&new_boring),
        )?;
        moved.boring = new_boring;
        moved.real = new_name;
        new_manifest.children.push(moved);

        old_manifest.save(&old_parent_disk, &self.key)?;
        new_manifest.save(&new_parent_disk, &self.key)
    }

    // ---- reads -----------------------------------------------------------

    /// Read `len` plaintext bytes at `offset` of the file at `path`.
    pub fn read_at(&self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let (parent, name) = parent_and_name(path)?;
        let parent_disk = self.resolve_dir(&parent)?;
        let manifest = Manifest::load(&parent_disk, &self.key)?;
        let child = manifest.find(&name).ok_or_else(not_found)?;
        if child.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "is a directory"));
        }
        let size = child.size;
        if offset >= size {
            return Ok(Vec::new());
        }
        let end = min(offset + len as u64, size);
        let read_len = (end - offset) as usize;

        let mut file = std::fs::File::open(parent_disk.join(&child.boring))?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; read_len];
        file.read_exact(&mut buf)?;

        for (rs, re) in protected_ranges(size, self.region) {
            let o_start = max(offset, rs);
            let o_end = min(end, re);
            if o_start < o_end {
                let ls = (o_start - offset) as usize;
                let le = (o_end - offset) as usize;
                transform_region(&self.key, &child.nonce, o_start, &mut buf[ls..le]);
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

    /// Read a blob file and decrypt its ends into plaintext.
    fn decrypt_blob(&self, blob: &Path, nonce: &Nonce, size: u64) -> io::Result<Vec<u8>> {
        let mut data = std::fs::read(blob)?;
        for (s, e) in protected_ranges(size, self.region) {
            transform_region(&self.key, nonce, s, &mut data[s as usize..e as usize]);
        }
        Ok(data)
    }
}

/// Does `[start, end)` overlap any encrypted region of a file of `size` bytes?
fn range_hits_protected(start: u64, end: u64, size: u64, region: u64) -> bool {
    protected_ranges(size, region)
        .into_iter()
        .any(|(rs, re)| start < re && rs < end)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
