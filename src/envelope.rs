//! The envelope: the last [`LEN`] bytes of every file, describing it.
//!
//! A file's list entry is what the drive normally goes by; the envelope is a
//! sealed copy of what's needed to read the file without its list: its ID,
//! its key, its content nonce and its real name (which may lag a rename, see
//! `docs/FORMAT.md`). It's how a file that turns up in a folder whose list
//! doesn't name it (moved there by hand, or a list that was lost) is
//! recognized and taken back in. Every envelope is the same size and has no
//! plaintext marker: it opens under the drive's master key or it doesn't.
//!
//! It starts with the drive's lock (see [`crate::lock`]): the master key,
//! sealed under the password's key, so this one file and the password are
//! all it takes to read it.

use crate::crypto::{self, Key, Nonce, KEY_LEN, NONCE_LEN, SEAL_OVERHEAD};
use crate::lock;
use crate::names::MAX_NAME_BYTES;
use std::io;

/// An envelope's size on disk.
pub const LEN: u64 = 512;
const PLAIN: usize = LEN as usize - lock::LEN - SEAL_OVERHEAD;
const LABEL: &[u8] = b"cloak-envelope-v3";
const LAYOUT: u8 = 1;

/// A file's random ID, kept for the life of the file.
pub type FileId = [u8; 16];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub id: FileId,
    pub key: Key,
    pub nonce: Nonce,
    pub name: String,
}

impl Envelope {
    /// Sealed with the drive's master key, after the drive's `lock`, ready to
    /// write as the file's last [`LEN`] bytes.
    pub fn seal(&self, master: &Key, lock: &[u8; lock::LEN]) -> [u8; LEN as usize] {
        let mut plain = [0u8; PLAIN];
        let name = self.name.as_bytes();
        // Names are validated to fit; cut at a character boundary just in case.
        let mut n = name.len().min(MAX_NAME_BYTES);
        while !self.name.is_char_boundary(n) {
            n -= 1;
        }
        let mut at = 0;
        for part in [&[LAYOUT][..], &self.id, &self.key, &self.nonce, &(n as u16).to_le_bytes(), &name[..n]] {
            plain[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        let sealed = crypto::seal(master, LABEL, &plain);
        let mut out = [0u8; LEN as usize];
        out[..lock::LEN].copy_from_slice(lock);
        out[lock::LEN..].copy_from_slice(&sealed);
        out
    }

    /// Open the last [`LEN`] bytes of a file with `master`. `InvalidData` if
    /// they aren't an envelope sealed with it.
    pub fn open(master: &Key, bytes: &[u8]) -> io::Result<Envelope> {
        let sealed = bytes.get(lock::LEN..).unwrap_or_default();
        let plain = crypto::open(master, LABEL, sealed)?;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "not an envelope this drive can read");
        if plain.len() != PLAIN || plain[0] != LAYOUT {
            return Err(bad());
        }
        let mut at = 1;
        let mut take = |n: usize| {
            let s = &plain[at..at + n];
            at += n;
            s
        };
        let id: FileId = take(16).try_into().expect("16 bytes");
        let key: Key = take(KEY_LEN).try_into().expect("32 bytes");
        let nonce: Nonce = take(NONCE_LEN).try_into().expect("12 bytes");
        let n = u16::from_le_bytes(take(2).try_into().expect("2 bytes")) as usize;
        if n > MAX_NAME_BYTES {
            return Err(bad());
        }
        let name = String::from_utf8(take(n).to_vec()).map_err(|_| bad())?;
        Ok(Envelope { id, key, nonce, name })
    }

    /// Read and open the envelope of the file at `path`, if it has one that
    /// `master` opens.
    pub fn read(path: &std::path::Path, master: &Key) -> io::Result<Envelope> {
        Envelope::open(master, &read_tail(path)?)
    }
}

/// The last [`LEN`] bytes of the file at `path`.
pub fn read_tail(path: &std::path::Path) -> io::Result<[u8; LEN as usize]> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len < LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too short to have an envelope"));
    }
    let mut bytes = [0u8; LEN as usize];
    f.seek(SeekFrom::Start(len - LEN))?;
    f.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// A new random file ID.
pub fn new_id() -> FileId {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// A new random file key.
pub fn new_key() -> Key {
    use rand::RngCore;
    let mut k = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

/// A new random content nonce.
pub fn new_nonce() -> Nonce {
    use rand::RngCore;
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: [u8; lock::LEN] = [5; lock::LEN];

    fn sample(name: &str) -> Envelope {
        Envelope { id: new_id(), key: new_key(), nonce: new_nonce(), name: name.into() }
    }

    #[test]
    fn seals_to_a_fixed_size_and_opens_back() {
        let master = [7u8; 32];
        for name in ["a", "Caf\u{e9} \u{1f600}.txt", &"x".repeat(255)] {
            let e = sample(name);
            let sealed = e.seal(&master, &LOCK);
            assert_eq!(sealed.len() as u64, LEN);
            assert_eq!(sealed[..lock::LEN], LOCK, "the lock comes first");
            assert_eq!(Envelope::open(&master, &sealed).unwrap(), e);
        }
    }

    #[test]
    fn another_key_or_a_changed_byte_fails() {
        let e = sample("a.doc");
        let mut sealed = e.seal(&[1u8; 32], &LOCK);
        assert!(Envelope::open(&[2u8; 32], &sealed).is_err());
        sealed[200] ^= 1;
        assert!(Envelope::open(&[1u8; 32], &sealed).is_err());
    }

    #[test]
    fn same_contents_seal_differently() {
        // No two envelopes look alike, even of the same file.
        let e = sample("a");
        assert_ne!(e.seal(&[1u8; 32], &LOCK)[lock::LEN..], e.seal(&[1u8; 32], &LOCK)[lock::LEN..]);
    }
}
