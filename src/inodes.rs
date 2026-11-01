//! Inode numbers for the FUSE adapter (macOS/Linux).
//!
//! FUSE addresses everything by inode number while the store is addressed by
//! path, so the adapter keeps this table: each logical path gets a stable
//! number for as long as the mount lives. Paths are keyed by their
//! case/normalization-folded form (`names::fold`) so `Photos/a.jpg` and
//! `photos/A.JPG` are one inode, matching the store's lookups. Renaming or
//! moving a directory re-keys its whole subtree in place, so open handles and
//! the kernel's cached inodes stay valid.
//!
//! Kept in the library (not the adapter binary) so it's unit-tested on every
//! platform, including where no FUSE driver can be built.

use crate::names;
use std::collections::HashMap;

/// The root directory's inode (fixed by FUSE).
pub const ROOT_INO: u64 = 1;

pub struct Inodes {
    by_ino: HashMap<u64, String>,
    by_key: HashMap<String, u64>,
    next: u64,
}

impl Default for Inodes {
    fn default() -> Self {
        let mut t = Inodes {
            by_ino: HashMap::new(),
            by_key: HashMap::new(),
            next: ROOT_INO + 1,
        };
        t.by_ino.insert(ROOT_INO, String::new());
        t.by_key.insert(String::new(), ROOT_INO);
        t
    }
}

/// `parent/name`, or just `name` at the root.
pub fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// The parent of a logical path (`""` for top-level entries and the root).
pub fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

/// Is `path` equal to `prefix` or inside it? Both are folded keys.
fn within(path: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || path == prefix
        || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

impl Inodes {
    /// The path an inode refers to.
    pub fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }

    /// The inode for `path`, allocating one on first sight. `path` should be
    /// the stored (canonical) spelling so the table reports names as stored.
    pub fn ino(&mut self, path: &str) -> u64 {
        let key = names::fold(path);
        if let Some(&ino) = self.by_key.get(&key) {
            // Keep the latest spelling (e.g. after a case-only rename elsewhere).
            self.by_ino.insert(ino, path.to_string());
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_key.insert(key, ino);
        self.by_ino.insert(ino, path.to_string());
        ino
    }

    /// Point `old` and everything under it at `new` (a rename or move),
    /// keeping their inode numbers.
    pub fn rename(&mut self, old: &str, new: &str) {
        let old_key = names::fold(old);
        if old_key.is_empty() {
            return; // never re-key the root
        }
        let moved: Vec<(u64, String)> = self
            .by_ino
            .iter()
            .filter(|(_, p)| within(&names::fold(p), &old_key))
            .map(|(&ino, p)| (ino, p.clone()))
            .collect();
        let depth = old_key.split('/').count();
        for (ino, path) in moved {
            self.by_key.remove(&names::fold(&path));
            // `path` is `old` (up to folding) plus a tail; keep the tail as stored.
            let renamed = path
                .split('/')
                .skip(depth)
                .fold(new.to_string(), |acc, c| join(&acc, c));
            self.by_key.insert(names::fold(&renamed), ino);
            self.by_ino.insert(ino, renamed);
        }
    }

    /// Drop `path` and everything under it (after a delete or a replace).
    pub fn forget(&mut self, path: &str) {
        let key = names::fold(path);
        if key.is_empty() {
            return;
        }
        let gone: Vec<u64> = self
            .by_ino
            .iter()
            .filter(|(_, p)| within(&names::fold(p), &key))
            .map(|(&ino, _)| ino)
            .collect();
        for ino in gone {
            if let Some(p) = self.by_ino.remove(&ino) {
                self.by_key.remove(&names::fold(&p));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_case_insensitive() {
        let mut t = Inodes::default();
        assert_eq!(t.path(ROOT_INO), Some(""));
        let a = t.ino("Photos");
        assert_eq!(t.ino("photos"), a);
        assert_eq!(t.ino("Cafe\u{301}"), t.ino("Caf\u{e9}"));
        assert_ne!(t.ino("Photos/a.jpg"), a);
    }

    #[test]
    fn rename_moves_subtree_and_keeps_inodes() {
        let mut t = Inodes::default();
        let dir = t.ino("A");
        let sub = t.ino("A/Sub");
        let file = t.ino("A/Sub/f.txt");
        let other = t.ino("AB/x"); // shares a prefix string, not a path prefix
        t.rename("a", "Moved/B");
        assert_eq!(t.path(dir), Some("Moved/B"));
        assert_eq!(t.path(sub), Some("Moved/B/Sub"));
        assert_eq!(t.path(file), Some("Moved/B/Sub/f.txt"));
        assert_eq!(t.path(other), Some("AB/x"));
        assert_eq!(t.ino("moved/b/sub/F.TXT"), file);
    }

    #[test]
    fn forget_drops_subtree_only() {
        let mut t = Inodes::default();
        let a = t.ino("A");
        let f = t.ino("A/f");
        let ab = t.ino("AB");
        t.forget("A");
        assert_eq!(t.path(a), None);
        assert_eq!(t.path(f), None);
        assert_eq!(t.path(ab), Some("AB"));
        assert_ne!(t.ino("A"), a); // a new entry gets a new number
    }

    #[test]
    fn path_helpers() {
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("a/b", "c"), "a/b/c");
        assert_eq!(parent_of("a/b/c"), "a/b");
        assert_eq!(parent_of("a"), "");
    }
}
