//! Per-directory manifest (Approach A).
//!
//! Each logical directory is a real on-disk directory with a *boring* name, and
//! inside it sits one manifest file listing that directory's immediate children:
//! for each child, its real name, its boring on-disk name, whether it's a file
//! or subdirectory, and (for files) the per-file crypto params.
//!
//! The manifest is the only place real names live, so it is encrypted: a random
//! 12-byte nonce prefix followed by the ChaCha20 keystream XORed over the JSON.
//! Losing or corrupting one manifest costs you only that one directory's child
//! names — not the whole store — which is the resilience win of per-directory
//! manifests over a single global index.

use crate::crypto::{transform_region, Key, NONCE_LEN};
use crate::names;
use rand::RngCore;
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Child {
    /// Name the user sees, e.g. `Taxes` or `Return.pdf`.
    pub real: String,
    /// Boring on-disk name within this directory, e.g. `index_shard_0472.idx`.
    pub boring: String,
    pub kind: Kind,
    /// Per-file ChaCha20 nonce (unused / zeroed for directories).
    pub nonce: [u8; NONCE_LEN],
    /// Plaintext file size (0 for directories).
    pub size: u64,
}

impl Child {
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Dir
    }
}

/// The decrypted contents of one directory's manifest.
#[derive(Default, Serialize, Deserialize)]
pub struct Manifest {
    pub children: Vec<Child>,
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
        let mut bytes = std::fs::read(&path)?;
        if bytes.len() < NONCE_LEN {
            return Ok(Manifest::default());
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);
        let body = &mut bytes[NONCE_LEN..];
        // Symmetric stream cipher: XOR the keystream from offset 0 to decrypt.
        transform_region(key, &nonce, 0, body);
        let manifest: Manifest = serde_json::from_slice(body)?;
        Ok(manifest)
    }

    /// Encrypt and write the manifest into `dir`, with a fresh random nonce.
    pub fn save(&self, dir: &Path, key: &Key) -> io::Result<()> {
        let mut body = serde_json::to_vec(self)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        transform_region(key, &nonce, 0, &mut body);

        let mut out = Vec::with_capacity(NONCE_LEN + body.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        std::fs::write(Self::path_in(dir), out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dir_child(real: &str, boring: &str) -> Child {
        Child {
            real: real.into(),
            boring: boring.into(),
            kind: Kind::Dir,
            nonce: [0; NONCE_LEN],
            size: 0,
        }
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
        m.children.push(Child {
            real: "Return.pdf".into(),
            boring: "cache_0002.dat".into(),
            kind: Kind::File,
            nonce: [9; NONCE_LEN],
            size: 4242,
        });
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
        // A wrong key yields garbage bytes, so JSON parsing fails.
        assert!(Manifest::load(d.path(), &[4u8; 32]).is_err());
    }

    #[test]
    fn used_names_includes_reserved_manifest() {
        let mut m = Manifest::default();
        m.children.push(dir_child("A", "cache_0001.dat"));
        let used = m.used_boring_names();
        assert!(used.contains("cache_0001.dat"));
        assert!(used.contains(MANIFEST_NAME));
    }
}
