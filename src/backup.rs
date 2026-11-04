//! Recovery backups: every folder list of a drive, for one drive or several,
//! in one password-protected file.
//!
//! A drive's files describe themselves (see `docs/FORMAT.md`), so a lost list
//! is rebuilt from them; but only a list knows a rename its files' envelopes
//! haven't caught up with yet, the names of folders whose lists were both
//! lost, and empty folders. The lists are small, so a backup of them is quick
//! to make and easy to keep somewhere safe. Each list carries the drive's
//! lock, so a backup also proves which drive it belongs to.
//!
//! The file is `CLOAKBAK`, a version byte, a salt and a nonce, then the
//! contents (JSON) sealed with XChaCha20-Poly1305 under an Argon2id key from
//! the backup's own password. Being authenticated, a wrong password or a
//! damaged file is reported as such rather than read as garbage.
//!
//! Restoring only replaces what's missing or can't be read: a list that
//! still opens is newer than the backup, and putting the old one back would
//! hide whatever was added since.

use crate::crypto::Key;
use crate::durable;
use crate::key::{derive_key, random_salt, KdfParams, SALT_LEN};
use crate::lock::{self, Keys};
use crate::manifest::{is_list_file, Manifest};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 8] = b"CLOAKBAK";
const VERSION: u8 = 2;
const NONCE_LEN: usize = 24;

/// One drive's recovery files.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DriveBackup {
    /// The name the drive had in the app.
    pub name: String,
    /// Where the drive's folder was when backed up.
    pub path: String,
    /// Each list file by its path inside the drive's folder (`/`-separated),
    /// the top folder's first.
    pub files: Vec<(String, Hex)>,
}

/// The contents of a backup file.
#[derive(Serialize, Deserialize, Debug)]
pub struct Backup {
    /// Seconds since 1970 when it was made.
    pub created: u64,
    pub drives: Vec<DriveBackup>,
}

/// Bytes, stored as hex in the JSON.
#[derive(Clone, Debug)]
pub struct Hex(pub Vec<u8>);

impl Serialize for Hex {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let text: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd-length hex"));
        }
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect::<Result<Vec<u8>, _>>()
            .map(Hex)
    }
}

/// Gather a drive's recovery files from its folder; `password` is the
/// drive's own (its lists' names come from its key).
pub fn collect(name: &str, store: &Path, password: &str) -> io::Result<DriveBackup> {
    let keys = crate::engine::unlock(store, password)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", store.display())))?;
    let mut files = Vec::new();
    let mut dirs = vec![(store.to_path_buf(), String::new())];
    while let Some((dir, rel)) = dirs.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            if e.file_type()?.is_dir() {
                dirs.push((e.path(), path));
            } else if is_list_file(&keys.master, &name) {
                files.push((path, Hex(std::fs::read(e.path())?)));
            }
        }
    }
    // The top folder's list first.
    files.sort_by_key(|(p, _)| p.contains('/'));
    Ok(DriveBackup { name: name.to_string(), path: store.display().to_string(), files })
}

/// Write `drives` to `out`, sealed with `password`.
pub fn write(out: &Path, password: &str, drives: Vec<DriveBackup>) -> io::Result<()> {
    if password.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a backup needs a password"));
    }
    let created = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let body = serde_json::to_vec(&Backup { created, drives })?;
    let salt = random_salt();
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let sealed = cipher(password, &salt)?
        .encrypt(XNonce::from_slice(&nonce), body.as_slice())
        .map_err(|_| io::Error::other("couldn't encrypt the backup"))?;
    let mut file = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + sealed.len());
    file.extend_from_slice(MAGIC);
    file.push(VERSION);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&sealed);
    durable::write_atomic(out, &file)
}

/// Open a backup file with its password.
pub fn read(file: &Path, password: &str) -> io::Result<Backup> {
    let bytes = std::fs::read(file)?;
    let head = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;
    if bytes.len() < head || &bytes[..MAGIC.len()] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "that isn't a cloak backup file"));
    }
    if bytes[MAGIC.len()] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "this backup was made by a newer version of cloak",
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[MAGIC.len() + 1..MAGIC.len() + 1 + SALT_LEN]);
    let nonce = XNonce::from_slice(&bytes[MAGIC.len() + 1 + SALT_LEN..head]);
    let body = cipher(password, &salt)?.decrypt(nonce, &bytes[head..]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong backup password, or the backup file is damaged",
        )
    })?;
    Ok(serde_json::from_slice(&body)?)
}

/// Version-1 backups always use the original Argon2id settings; a backup with
/// other settings would record them under a new version byte.
fn cipher(password: &str, salt: &[u8; SALT_LEN]) -> io::Result<XChaCha20Poly1305> {
    let key: Key = derive_key(password, salt, &KdfParams::ORIGINAL)?;
    Ok(XChaCha20Poly1305::new(&key.into()))
}

/// What a restore did, by path inside the drive's folder.
#[derive(Serialize, Debug, Default)]
pub struct Restored {
    /// Missing or unreadable, and put back from the backup.
    pub restored: Vec<String>,
    /// Still readable, so left alone.
    pub kept: Vec<String>,
    /// Their folder no longer exists, so there's nothing to restore them for.
    pub skipped: Vec<String>,
}

/// Put `backup`'s lists back into the drive folder `store`, where they're
/// missing or can't be read. `password` is the drive's own password: it
/// proves the backup belongs to this drive and decides which lists still
/// read.
pub fn restore(store: &Path, password: &str, backup: &DriveBackup) -> io::Result<Restored> {
    // The backup's drive, from the lock its lists carry.
    let tail = crate::envelope::LEN as usize;
    let first = backup
        .files
        .iter()
        .map(|(_, d)| &d.0)
        .find(|d| d.len() >= tail)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the backup holds no lists"))?;
    let keys: Keys = lock::unlock_one(&first[first.len() - tail..first.len() - tail + lock::LEN], password)
        .map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied => {
                io::Error::new(io::ErrorKind::PermissionDenied, "wrong password for this drive")
            }
            _ => e,
        })?;
    if !store.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "the drive's folder doesn't exist"));
    }
    // What's in the folder must be the same drive (or nothing at all).
    match crate::engine::unlock(store, password) {
        Ok(k) if k.master != keys.master => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "that folder holds a different drive than the one in the backup",
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "that folder holds a different drive than the one in the backup (or its password has changed since)",
            ))
        }
        _ => {}
    }

    let mut done = Restored::default();
    for (rel, data) in &backup.files {
        let path = rel.split('/').fold(store.to_path_buf(), |p, c| p.join(c));
        if !path.parent().is_some_and(Path::is_dir) {
            done.skipped.push(rel.clone());
            continue;
        }
        let readable = std::fs::read(&path).ok().is_some_and(|b| list_reads(b, &keys));
        if readable {
            done.kept.push(rel.clone());
        } else {
            durable::write_atomic(&path, &data.0)?;
            done.restored.push(rel.clone());
        }
    }
    Ok(done)
}

/// Does this folder-list file decrypt and parse with `keys`? One too short
/// to hold a sealed list and its tail is truncated, though the engine would
/// read an empty file as an empty list.
fn list_reads(bytes: Vec<u8>, keys: &Keys) -> bool {
    bytes.len() >= crate::envelope::LEN as usize + crate::crypto::SEAL_OVERHEAD && Manifest::from_sealed(bytes, keys).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Store;
    use tempfile::tempdir;

    fn drive(dir: &Path) -> Store {
        let mut s = Store::create_with_passphrase(dir, "drive-pass", 128).unwrap();
        s.mkdir("docs").unwrap();
        s.mkdir("docs/deep").unwrap();
        for p in ["a.txt", "docs/b.txt", "docs/deep/c.txt"] {
            s.create(p).unwrap();
            s.write_at(p, 0, p.as_bytes()).unwrap();
        }
        s.sync().unwrap();
        s
    }

    #[test]
    fn round_trip_and_wrong_password() {
        let d = tempdir().unwrap();
        let (one, two) = (d.path().join("one"), d.path().join("two"));
        drop(drive(&one));
        drop(drive(&two));
        let out = d.path().join("all.cloakbak");
        let both = vec![collect("One", &one, "drive-pass").unwrap(), collect("Two", &two, "drive-pass").unwrap()];
        write(&out, "backup-pass", both).unwrap();

        let b = read(&out, "backup-pass").unwrap();
        assert_eq!(b.drives.len(), 2);
        assert_eq!(b.drives[0].name, "One");
        // The lists of the root, docs and docs/deep, the root's first.
        assert_eq!(b.drives[0].files.len(), 3);
        assert!(!b.drives[0].files[0].0.contains('/'));
        assert!(collect("One", &one, "wrong").is_err(), "needs the drive's password");

        let err = read(&out, "nope").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let mut bytes = std::fs::read(&out).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&out, bytes).unwrap();
        assert!(read(&out, "backup-pass").is_err(), "tampering is detected");
        assert!(read(&out.with_extension("nope"), "x").is_err(), "not a backup file");
    }

    #[test]
    fn restore_puts_back_only_what_is_lost() {
        let d = tempdir().unwrap();
        let store = d.path().join("drive");
        drop(drive(&store));
        let backup = collect("Drive", &store, "drive-pass").unwrap();
        let keys = crate::engine::unlock(&store, "drive-pass").unwrap();

        // Damage the root list and delete a folder's list.
        let root_list = Manifest::path_in(&store, &keys);
        std::fs::write(&root_list, b"garbage that won't decrypt").unwrap();
        let docs_dir = backup
            .files
            .iter()
            .map(|(p, _)| p.clone())
            .find(|p| p.matches('/').count() == 1)
            .unwrap();
        std::fs::remove_file(docs_dir.split('/').fold(store.clone(), |p, c| p.join(c))).unwrap();

        assert!(restore(&store, "wrong", &backup).is_err(), "needs the drive's password");
        let r = restore(&store, "drive-pass", &backup).unwrap();
        assert_eq!(r.restored.len(), 2, "{r:?}");
        assert_eq!(r.kept.len(), 1, "{r:?}");

        let s = Store::open_with_passphrase(&store, "drive-pass").unwrap();
        assert_eq!(s.read_all("a.txt").unwrap(), b"a.txt");
        assert_eq!(s.read_all("docs/b.txt").unwrap(), b"docs/b.txt");
        assert_eq!(s.read_all("docs/deep/c.txt").unwrap(), b"docs/deep/c.txt");

        // A healthy list isn't rolled back to the backup's older copy.
        let mut s = s;
        s.create("docs/deep/new.txt").unwrap();
        s.sync().unwrap();
        drop(s);
        let r = restore(&store, "drive-pass", &backup).unwrap();
        assert!(r.restored.is_empty(), "{r:?}");
        let s = Store::open_with_passphrase(&store, "drive-pass").unwrap();
        assert!(s.metadata("docs/deep/new.txt").unwrap().is_some());
    }

    #[test]
    fn refuses_to_overwrite_another_drive() {
        let d = tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        drop(drive(&a));
        Store::create_with_passphrase(&b, "other-pass", 128).unwrap();
        let backup = collect("A", &a, "drive-pass").unwrap();
        let err = restore(&b, "drive-pass", &backup).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_truncated_list_counts_as_damaged() {
        let d = tempdir().unwrap();
        let store = d.path().join("drive");
        drop(drive(&store));
        let backup = collect("Drive", &store, "drive-pass").unwrap();
        let keys = crate::engine::unlock(&store, "drive-pass").unwrap();
        std::fs::write(Manifest::path_in(&store, &keys), b"cut").unwrap();
        let r = restore(&store, "drive-pass", &backup).unwrap();
        assert_eq!(r.restored, [keys.list_name()], "{r:?}");
        let s = Store::open_with_passphrase(&store, "drive-pass").unwrap();
        assert_eq!(s.read_all("a.txt").unwrap(), b"a.txt");
    }
}
