//! Header/footer encryption.
//!
//! We use ChaCha20 as a *seekable* stream cipher. A stream cipher produces a
//! keystream that is simply XORed with the data, so:
//!
//!   * encryption and decryption are the **same** operation (XOR twice = identity);
//!   * we can jump the keystream to any byte offset and transform just that slice.
//!
//! That second property is the whole point: to protect a large file we encrypt
//! only the first `N` bytes (the header) and the last `N` bytes (the footer),
//! positioning the keystream at each region's absolute file offset. The gigabytes
//! in between are left as raw passthrough, so a read of the middle costs nothing
//! and random-access seeks stay native-speed.
//!
//! Security note: this makes a file fail to *open* (its structural metadata is
//! genuinely unrecoverable without the key) but the body remains plaintext on
//! disk. That is obfuscation hardened at the edges, not full confidentiality.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

pub type Key = [u8; KEY_LEN];
pub type Nonce = [u8; NONCE_LEN];

/// ChaCha20 (IETF, 32-bit counter) addresses at most 256 GiB of keystream per
/// nonce. The footer of a file larger than this cannot be reached; callers
/// should fall back to a per-region nonce for such files. Headers are unaffected.
pub const MAX_ADDRESSABLE: u64 = (1u64 << 32) * 64;

/// Transform `buf` in place, where `buf[0]` sits at absolute `file_offset` in the
/// file. XORs the ChaCha20 keystream positioned at that same offset. Symmetric:
/// run it again over the same bytes at the same offset to restore the original.
pub fn transform_region(key: &Key, nonce: &Nonce, file_offset: u64, buf: &mut [u8]) {
    debug_assert!(
        file_offset + buf.len() as u64 <= MAX_ADDRESSABLE,
        "region exceeds ChaCha20 single-nonce keystream limit"
    );
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.seek(file_offset);
    cipher.apply_keystream(buf);
}

/// Bytes that [`seal`] adds: its random nonce and the tag.
pub const SEAL_OVERHEAD: usize = 24 + 16;

/// Encrypt and authenticate `plain` under `key` (XChaCha20-Poly1305), bound
/// to `label` so one kind of sealed record can't stand in for another:
/// `24-byte random nonce || ciphertext || 16-byte tag`.
pub fn seal(key: &Key, label: &[u8], plain: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use rand::RngCore;
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let sealed = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: label })
        .expect("XChaCha20-Poly1305 encryption doesn't fail");
    let mut out = Vec::with_capacity(24 + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
}

/// Undo [`seal`]. `InvalidData` if `bytes` weren't sealed under `key` with
/// `label`, or were changed since.
pub fn open(key: &Key, label: &[u8], bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let damaged = || std::io::Error::new(std::io::ErrorKind::InvalidData, "damaged, or not sealed with this key");
    if bytes.len() < SEAL_OVERHEAD {
        return Err(damaged());
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(&bytes[..24]), Payload { msg: &bytes[24..], aad: label })
        .map_err(|_| damaged())
}

/// The byte ranges (`[start, end)`) a file of `len` bytes should have encrypted,
/// given a protected-region size of `n` at each end.
///
/// When the two ends would overlap (`len <= 2*n`) the whole file is a single
/// region, so no byte is ever encrypted twice.
pub fn protected_ranges(len: u64, n: u64) -> Vec<(u64, u64)> {
    if len == 0 || n == 0 {
        return Vec::new();
    }
    if len <= 2 * n {
        vec![(0, len)]
    } else {
        vec![(0, n), (len - n, len)]
    }
}

/// Convenience for in-memory buffers: encrypt/decrypt both ends of `data` with
/// protected-region size `n`. Used by tests and the benchmark.
pub fn transform_ends(key: &Key, nonce: &Nonce, data: &mut [u8], n: u64) {
    let len = data.len() as u64;
    for (start, end) in protected_ranges(len, n) {
        let (s, e) = (start as usize, end as usize);
        transform_region(key, nonce, start, &mut data[s..e]);
    }
}

/// Transform an entire buffer as one region starting at offset 0. This is the
/// full-file baseline the benchmark compares ends-only against.
pub fn transform_whole(key: &Key, nonce: &Nonce, data: &mut [u8]) {
    transform_region(key, nonce, 0, data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> (Key, Nonce) {
        ([7u8; KEY_LEN], [3u8; NONCE_LEN])
    }

    #[test]
    fn roundtrip_whole_is_identity() {
        let (k, n) = fixtures();
        let original = b"The quick brown fox jumps over the lazy dog".to_vec();
        let mut buf = original.clone();
        transform_whole(&k, &n, &mut buf);
        assert_ne!(buf, original, "ciphertext must differ from plaintext");
        transform_whole(&k, &n, &mut buf);
        assert_eq!(buf, original, "two transforms must restore the original");
    }

    #[test]
    fn ends_only_leaves_middle_untouched() {
        let (k, n) = fixtures();
        let original: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut buf = original.clone();
        let region = 16u64;
        transform_ends(&k, &n, &mut buf, region);

        // Ends changed...
        assert_ne!(buf[..16], original[..16]);
        assert_ne!(buf[984..], original[984..]);
        // ...middle is byte-for-byte identical (the passthrough region).
        assert_eq!(buf[16..984], original[16..984]);

        // And it round-trips.
        transform_ends(&k, &n, &mut buf, region);
        assert_eq!(buf, original);
    }

    #[test]
    fn overlapping_ends_encrypt_once_and_roundtrip() {
        let (k, n) = fixtures();
        // len (10) < 2*n (2*8=16): single whole-file region, no double-encrypt.
        let original = b"0123456789".to_vec();
        let mut buf = original.clone();
        transform_ends(&k, &n, &mut buf, 8);
        assert_ne!(buf, original);
        transform_ends(&k, &n, &mut buf, 8);
        assert_eq!(buf, original);
    }

    #[test]
    fn ranges_math() {
        assert_eq!(protected_ranges(0, 16), vec![]);
        assert_eq!(protected_ranges(100, 0), vec![]);
        assert_eq!(protected_ranges(10, 8), vec![(0, 10)]);
        assert_eq!(protected_ranges(16, 8), vec![(0, 16)]);
        assert_eq!(protected_ranges(100, 16), vec![(0, 16), (84, 100)]);
    }

    #[test]
    fn partial_region_reads_match() {
        // Simulate the mount reading a sub-slice of the header at an offset:
        // transforming [a, b) directly must equal transforming the whole header
        // and then slicing. This is what keeps seek-reads correct.
        let (k, n) = fixtures();
        let mut full: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        let original = full.clone();
        transform_region(&k, &n, 0, &mut full); // encrypt first 256 bytes

        // Now decrypt just bytes [100, 140) in isolation.
        let mut slice = full[100..140].to_vec();
        transform_region(&k, &n, 100, &mut slice);
        assert_eq!(slice, original[100..140]);
    }
}
