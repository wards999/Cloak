//! The drive's keys, and the lock every file and folder list carries.
//!
//! A drive has one random master key. It's kept only *locked*: sealed under a
//! key derived from the password (Argon2id over the drive's salt). The lock,
//! [`LEN`] bytes, sits at the start of every file's envelope and every
//! folder list's tail, so any one hidden file, with nothing but the password,
//! is enough to recover the master key: there is no `meta.json`.
//!
//! Layout: `salt (16) || generation (8, little-endian) || nonce (24) ||
//! sealed(master key (32) || region (8)) || tag (16)`. The salt and the
//! generation are plain: the salt is where the password's key starts from,
//! and the generation says which lock is newest after a password change
//! (each change makes a new salt and the next generation). Every lock is
//! sealed afresh, so only the salt and generation repeat across a drive: a
//! cost of password-only recovery (see `docs/FORMAT.md`).
//!
//! The Argon2id settings are fixed by the format (they can't be stored: they
//! must be known before anything opens), as are the names a drive gives its
//! folder lists and records, derived from the master key so they look like
//! any other file in the drive.

use crate::boring;
use crate::crypto::{self, transform_region, Key, KEY_LEN};
use crate::envelope;
use crate::key::{self, KdfParams, Salt, SALT_LEN};
use std::io;
use std::path::Path;

/// A lock's size.
pub const LEN: usize = SALT_LEN + 8 + crypto::SEAL_OVERHEAD + KEY_LEN + 8;
const LABEL: &[u8] = b"cloak-lock-v3";
/// The password settings of this format.
const KDF: KdfParams = KdfParams::CURRENT;

/// A drive's keys, once unlocked.
#[derive(Clone)]
pub struct Keys {
    pub master: Key,
    /// Bytes encrypted at each end of a file.
    pub region: u64,
    /// The lock's generation (one more with each password change).
    pub gen: u64,
    salt: Salt,
    /// The password's key: seals new locks without asking again.
    kek: Key,
}

impl Keys {
    /// Keys for a new drive protected by `password`.
    pub fn new(password: &str, region: u64) -> io::Result<Keys> {
        let salt = key::random_salt();
        let kek = key::derive_key(password, &salt, &KDF)?;
        Ok(Keys { master: envelope::new_key(), region, gen: 1, salt, kek })
    }

    /// Keys with a raw master key and no password, for tests and for
    /// opening a drive whose master key is already known.
    pub fn bare(master: Key, region: u64) -> Keys {
        Keys { master, region, gen: 1, salt: [0; SALT_LEN], kek: master }
    }

    /// The same drive locked with `password` instead: a new salt and the
    /// next generation.
    pub fn relocked(&self, password: &str) -> io::Result<Keys> {
        let salt = key::random_salt();
        let kek = key::derive_key(password, &salt, &KDF)?;
        Ok(Keys { master: self.master, region: self.region, gen: self.gen + 1, salt, kek })
    }

    /// A lock for this drive, sealed afresh.
    pub fn lock(&self) -> [u8; LEN] {
        let mut plain = [0u8; KEY_LEN + 8];
        plain[..KEY_LEN].copy_from_slice(&self.master);
        plain[KEY_LEN..].copy_from_slice(&self.region.to_le_bytes());
        let sealed = crypto::seal(&self.kek, LABEL, &plain);
        let mut out = [0u8; LEN];
        out[..SALT_LEN].copy_from_slice(&self.salt);
        out[SALT_LEN..SALT_LEN + 8].copy_from_slice(&self.gen.to_le_bytes());
        out[SALT_LEN + 8..].copy_from_slice(&sealed);
        out
    }

    /// The name of every folder's list in this drive.
    pub fn list_name(&self) -> &'static str {
        // Leaked once per drive opened: a few dozen bytes.
        names(&self.master).list
    }
}

/// A lock's plain parts: its salt and generation.
pub fn peek(lock: &[u8]) -> Option<(Salt, u64)> {
    if lock.len() < LEN {
        return None;
    }
    let salt: Salt = lock[..SALT_LEN].try_into().ok()?;
    let gen = u64::from_le_bytes(lock[SALT_LEN..SALT_LEN + 8].try_into().ok()?);
    Some((salt, gen))
}

/// Open a lock with the password's key for its salt. `InvalidData` if it
/// doesn't open.
pub fn open_with(kek: &Key, lock: &[u8]) -> io::Result<(Key, u64, u64)> {
    let (_, gen) = peek(lock).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a lock"))?;
    let plain = crypto::open(kek, LABEL, &lock[SALT_LEN + 8..LEN])?;
    let master: Key = plain[..KEY_LEN].try_into().expect("32 bytes");
    let region = u64::from_le_bytes(plain[KEY_LEN..].try_into().expect("8 bytes"));
    Ok((master, gen, region))
}

/// The password's key for a lock's salt (the slow step).
pub fn kek_for(password: &str, salt: &Salt) -> io::Result<Key> {
    key::derive_key(password, salt, &KDF)
}

/// Keys from one lock (bytes) and its password.
pub fn unlock_one(lock: &[u8], password: &str) -> io::Result<Keys> {
    let (salt, _) = peek(lock).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a lock"))?;
    let kek = kek_for(password, &salt)?;
    let (master, gen, region) = open_with(&kek, lock)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "wrong password"))?;
    Ok(Keys { master, region, gen, salt, kek })
}

/// The lock a hidden file carries: the first [`LEN`] bytes of its last 512
/// (a file's envelope, or a folder list's tail). `None` for a file too short
/// to have one.
pub fn lock_of_file(path: &Path) -> Option<[u8; LEN]> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len < envelope::LEN {
        return None;
    }
    let mut lock = [0u8; LEN];
    f.seek(SeekFrom::Start(len - envelope::LEN)).ok()?;
    f.read_exact(&mut lock).ok()?;
    Some(lock)
}

/// Could `l` be a drive's lock? Its generation is a small count (each
/// password change adds one); the same bytes from anything else almost never
/// look like that.
pub fn plausible(l: &[u8; LEN]) -> bool {
    peek(l).is_some_and(|(_, gen)| (1..1_000_000).contains(&gen))
}

/// Does a file directly in `dir` carry a drive's lock (is `dir` a drive, as
/// far as can be told without its password)?
pub fn holds_locks(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    rd.flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .any(|e| lock_of_file(&e.path()).is_some_and(|l| plausible(&l)))
}

/// The names a drive with `master` gives its own files.
pub struct Names {
    /// Every folder's list.
    pub list: &'static str,
    /// The record of items gone missing, at the top.
    pub missing: &'static str,
}

/// A dull name worked out from `master` and `what`, in the same style as
/// the names [`boring`] makes up.
fn derived(master: &Key, what: &[u8; 12]) -> String {
    let mut bytes = [0u8; 8];
    transform_region(master, what, 0, &mut bytes);
    boring::from_bytes(&bytes)
}

/// The names for `master` (worked out once per key, then kept).
pub fn names(master: &Key) -> &'static Names {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static NAMES: Mutex<Option<HashMap<Key, &'static Names>>> = Mutex::new(None);
    let mut map = NAMES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = map.get_or_insert_with(HashMap::new);
    map.entry(*master).or_insert_with(|| {
        let list = derived(master, b"cloak-list-n");
        let mut missing = derived(master, b"cloak-missin");
        if missing == list {
            missing = derived(master, b"cloak-missi2");
        }
        Box::leak(Box::new(Names { list: Box::leak(list.into_boxed_str()), missing: Box::leak(missing.into_boxed_str()) }))
    })
}

/// The file holding part `i` of a split list, in a drive with `master`.
pub fn part_name(master: &Key, i: usize) -> String {
    let list = names(master).list;
    let (stem, ext) = list.rsplit_once('.').unwrap_or((list, ""));
    format!("{stem}_p{i:02}.{ext}")
}

/// Is `name` (or the side file of a save of it) one of a drive's list
/// files: its list or a part of one?
pub fn is_list_file(master: &Key, name: &str) -> bool {
    let list = names(master).list;
    let (stem, ext) = list.rsplit_once('.').unwrap_or((list, ""));
    let lower = name.to_ascii_lowercase();
    lower == list.to_ascii_lowercase() || {
        let rest = lower.strip_prefix(&format!("{}_p", stem.to_ascii_lowercase()));
        rest.is_some_and(|r| r.len() == 3 + ext.len() && r[..2].bytes().all(|b| b.is_ascii_digit()) && r[2..] == format!(".{}", ext.to_ascii_lowercase()))
    }
}

/// Is `name` a sync tool's renamed copy of a drive's list (`<list stem>
/// (conflicted copy).<ext>`, `<list stem>-PC.<ext>`, …)?
pub fn is_conflict_copy(master: &Key, name: &str) -> bool {
    let list = names(master).list;
    let (stem, ext) = list.rsplit_once('.').unwrap_or((list, ""));
    let lower = name.to_ascii_lowercase();
    !is_list_file(master, name)
        && lower.starts_with(&stem.to_ascii_lowercase())
        && lower.ends_with(&format!(".{}", ext.to_ascii_lowercase()))
        && lower.len() > list.len()
}

/// The keys of the drive in `dir`, with its password: from the lock of any
/// file or folder in it (the top folder's first). `NotFound` if nothing in
/// `dir` carries a lock, `PermissionDenied` for a wrong password, and
/// `PermissionDenied` naming a password change if the password opens only
/// an older generation than the drive's newest.
pub fn unlock_drive(dir: &Path, password: &str) -> io::Result<Keys> {
    // Gather locks from the top folder, then deeper, until enough are seen
    // to know the drive's salt: random bytes never repeat a salt, a drive's
    // locks always do.
    let mut locks: Vec<[u8; LEN]> = Vec::new();
    let mut folders = vec![dir.to_path_buf()];
    while let Some(folder) = folders.pop() {
        let Ok(rd) = std::fs::read_dir(&folder) else { continue };
        let mut subs = Vec::new();
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => subs.push(e.path()),
                Ok(t) if t.is_file() => {
                    if let Some(l) = lock_of_file(&e.path()).filter(plausible) {
                        locks.push(l);
                    }
                }
                _ => {}
            }
            if locks.len() >= 64 {
                break;
            }
        }
        if locks.len() >= 64 {
            break;
        }
        folders.extend(subs);
    }
    if locks.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no drive here"));
    }
    // Salts by how often they occur, most common first; generation newest
    // first within a salt.
    let mut salts: Vec<(Salt, usize, u64)> = Vec::new();
    for l in &locks {
        let (salt, gen) = peek(l).expect("LEN bytes");
        match salts.iter_mut().find(|(s, _, _)| *s == salt) {
            Some(e) => {
                e.1 += 1;
                e.2 = e.2.max(gen);
            }
            None => salts.push((salt, 1, gen)),
        }
    }
    salts.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
    let newest = salts.iter().map(|s| s.2).max().unwrap_or(0);
    // A repeated salt is the drive's; with nothing repeated (a drive of one
    // file), each salt is tried.
    let tries: Vec<&(Salt, usize, u64)> =
        if salts[0].1 > 1 { salts.iter().filter(|s| s.1 > 1).collect() } else { salts.iter().take(4).collect() };
    for (salt, _, _) in tries {
        let kek = kek_for(password, salt)?;
        let mut best: Option<(Key, u64, u64)> = None;
        for l in locks.iter().filter(|l| peek(l.as_slice()).is_some_and(|(s, _)| s == *salt)) {
            if let Ok((master, gen, region)) = open_with(&kek, l) {
                if best.as_ref().is_none_or(|b| gen > b.1) {
                    best = Some((master, gen, region));
                }
            }
        }
        if let Some((master, gen, region)) = best {
            if gen < newest {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "this drive's password was changed: use the new password",
                ));
            }
            return Ok(Keys { master, region, gen, salt: *salt, kek });
        }
    }
    Err(io::Error::new(io::ErrorKind::PermissionDenied, "wrong password"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_opens_with_its_password_only() {
        let k = Keys::new("pw", 65536).unwrap();
        let lock = k.lock();
        let back = unlock_one(&lock, "pw").unwrap();
        assert_eq!((back.master, back.region, back.gen), (k.master, 65536, 1));
        assert_eq!(unlock_one(&lock, "nope").err().map(|e| e.kind()), Some(io::ErrorKind::PermissionDenied));
        assert_ne!(k.lock(), lock, "sealed afresh every time");
        assert_eq!(k.lock()[..SALT_LEN], lock[..SALT_LEN], "the salt repeats");
    }

    #[test]
    fn relocking_keeps_the_master_key() {
        let k = Keys::new("old", 1024).unwrap();
        let n = k.relocked("new").unwrap();
        assert_eq!(n.master, k.master);
        assert_eq!(n.gen, 2);
        assert!(unlock_one(&n.lock(), "old").is_err());
        assert_eq!(unlock_one(&n.lock(), "new").unwrap().master, k.master);
    }

    #[test]
    fn names_are_dull_stable_and_per_drive() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(names(&a).list, names(&a).list);
        assert_ne!(names(&a).list, names(&b).list);
        assert_ne!(names(&a).list, names(&a).missing);
        assert!(names(&a).list.contains('_') && names(&a).list.contains('.'));
        let p = part_name(&a, 7);
        assert!(is_list_file(&a, names(&a).list) && is_list_file(&a, &p));
        assert!(!is_list_file(&b, &p));
        let (stem, ext) = names(&a).list.rsplit_once('.').unwrap();
        assert!(is_conflict_copy(&a, &format!("{stem} (conflicted copy).{ext}")));
        assert!(!is_conflict_copy(&a, names(&a).list));
        assert!(!is_conflict_copy(&a, &p));
    }
}
