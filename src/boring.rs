//! Boring decoy-name generator.
//!
//! The on-disk name is just a key into the index, so it can be anything. We make
//! it *boring* on purpose: names that read as machine-generated infrastructure
//! (caches, logs, shard indexes) so a human scrolling the folder's eye slides
//! straight past. The enemy of hidden data is curiosity, not suspicion.
//!
//! We deliberately pick extensions that desktop shells do NOT auto-preview
//! (`.dat`, `.bin`, `.idx`, `.tmp`, `.db`, `.pf`). That dodges the thumbnailer,
//! which is exactly where a "name says JPEG, bytes say PDF" mismatch would leak.

use rand::seq::SliceRandom;
use rand::Rng;

/// Dull stems that look like something an application manages, never something a
/// person filed on purpose.
const STEMS: &[&str] = &[
    "cache",
    "index_shard",
    "telemetry_log",
    "session_cache",
    "update_manifest",
    "prefetch",
    "thumbs",
    "crashreport",
    "page_pool",
    "wal_segment",
];

/// Extensions nothing opens on purpose and nothing auto-previews.
const EXTS: &[&str] = &["dat", "bin", "idx", "tmp", "db", "pf"];

/// Generate one boring name, e.g. `index_shard_0472.idx`.
///
/// Uniformity is a feature: reusing a couple of stems across hundreds of files
/// is *more* ignorable than variety, so we keep the pool small and repeat.
pub fn generate<R: Rng + ?Sized>(rng: &mut R) -> String {
    let stem = STEMS.choose(rng).expect("STEMS is non-empty");
    let ext = EXTS.choose(rng).expect("EXTS is non-empty");
    let n: u16 = rng.gen_range(0..10_000);
    format!("{stem}_{n:04}.{ext}")
}

/// A boring name chosen by `bytes` rather than at random, so the same bytes
/// always give the same name (for names a drive works out from its key).
pub fn from_bytes(bytes: &[u8; 8]) -> String {
    let stem = STEMS[bytes[0] as usize % STEMS.len()];
    let ext = EXTS[bytes[1] as usize % EXTS.len()];
    let n = u16::from_le_bytes([bytes[2], bytes[3]]) % 10_000;
    format!("{stem}_{n:04}.{ext}")
}

/// Generate a name guaranteed not to collide with `existing` (the set of names
/// already used in the backing store). Retries a bounded number of times, then
/// widens the numeric space to guarantee termination.
pub fn generate_unique<R, S>(rng: &mut R, existing: &S) -> String
where
    R: Rng + ?Sized,
    S: Contains,
{
    for _ in 0..64 {
        let candidate = generate(rng);
        if !existing.contains(&candidate) {
            return candidate;
        }
    }
    // Fallback: a wide random suffix makes a collision astronomically unlikely.
    loop {
        let stem = STEMS.choose(rng).expect("STEMS is non-empty");
        let ext = EXTS.choose(rng).expect("EXTS is non-empty");
        let n: u64 = rng.gen();
        let candidate = format!("{stem}_{n:016x}.{ext}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }
}

/// Minimal membership test so the generator doesn't care whether the caller
/// holds a `HashSet`, a map's keyset, or something backed by the index file.
pub trait Contains {
    fn contains(&self, name: &str) -> bool;
}

impl Contains for std::collections::HashSet<String> {
    fn contains(&self, name: &str) -> bool {
        std::collections::HashSet::contains(self, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn looks_boring() {
        let mut rng = rand::thread_rng();
        for _ in 0..200 {
            let name = generate(&mut rng);
            let (stem_num, ext) = name.rsplit_once('.').expect("has extension");
            assert!(EXTS.contains(&ext), "unexpected extension: {ext}");
            assert!(
                STEMS.iter().any(|s| stem_num.starts_with(s)),
                "unexpected stem: {name}"
            );
        }
    }

    #[test]
    fn uniqueness_against_existing() {
        let mut rng = rand::thread_rng();
        let mut used: HashSet<String> = HashSet::new();
        for _ in 0..1000 {
            let name = generate_unique(&mut rng, &used);
            assert!(used.insert(name), "generator returned a duplicate name");
        }
    }
}
