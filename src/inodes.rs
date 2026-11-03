//! Inode numbers for the FUSE adapter (macOS/Linux).
//!
//! FUSE addresses everything by inode number while the store is addressed by
//! path, so the adapter keeps this table: each logical path gets a stable
//! number for as long as the kernel holds it. Paths are keyed by their
//! case/normalization-folded form (`names::fold`) so `Photos/a.jpg` and
//! `photos/A.JPG` are one inode, matching the store's lookups. Renaming or
//! moving a directory re-keys its whole subtree in place, so open handles and
//! the kernel's cached inodes stay valid.
//!
//! The table stays bounded: each entry counts the lookups the kernel holds
//! and goes when the kernel forgets them all, and numbers that only appeared
//! in directory listings (which the kernel doesn't hold) are dropped in bulk
//! once there are many.
//!
//! Kept in the library (not the adapter binary) so it's unit-tested on every
//! platform, including where no FUSE driver can be built.

use crate::names;
use std::collections::HashMap;

/// The root directory's inode (fixed by FUSE).
pub const ROOT_INO: u64 = 1;

/// Entries the kernel was never handed (numbers given out in directory
/// listings, which the kernel doesn't hold on to) are dropped once there are
/// this many, so browsing a huge tree can't grow the table without bound.
const MAX_UNCOUNTED: usize = 16 * 1024;

struct Node {
    path: String,
    /// How many times the kernel has been given this number (lookup, create,
    /// mkdir) and not yet forgotten it. Zero for numbers only listed.
    lookups: u64,
}

pub struct Inodes {
    by_ino: HashMap<u64, Node>,
    by_key: HashMap<String, u64>,
    next: u64,
    /// Entries with no lookups (the root aside).
    uncounted: usize,
}

impl Default for Inodes {
    fn default() -> Self {
        let mut t = Inodes {
            by_ino: HashMap::new(),
            by_key: HashMap::new(),
            next: ROOT_INO + 1,
            uncounted: 0,
        };
        t.by_ino.insert(ROOT_INO, Node { path: String::new(), lookups: 0 });
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
        self.by_ino.get(&ino).map(|n| n.path.as_str())
    }

    /// The inode for `path`, allocating one on first sight, without counting
    /// a lookup: for numbers the kernel only sees in a directory listing.
    /// `path` should be the stored (canonical) spelling so the table reports
    /// names as stored.
    pub fn ino(&mut self, path: &str) -> u64 {
        let key = names::fold(path);
        if let Some(&ino) = self.by_key.get(&key) {
            // Keep the latest spelling (e.g. after a case-only rename elsewhere).
            if let Some(n) = self.by_ino.get_mut(&ino) {
                n.path = path.to_string();
            }
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_key.insert(key, ino);
        self.by_ino.insert(ino, Node { path: path.to_string(), lookups: 0 });
        self.uncounted += 1;
        ino
    }

    /// The inode for `path`, counting one lookup: for every number handed to
    /// the kernel in a lookup, create or mkdir reply, which it holds until it
    /// sends `forget`.
    pub fn looked_up(&mut self, path: &str) -> u64 {
        let ino = self.ino(path);
        if ino != ROOT_INO {
            if let Some(n) = self.by_ino.get_mut(&ino) {
                if n.lookups == 0 {
                    self.uncounted -= 1;
                }
                n.lookups += 1;
            }
        }
        ino
    }

    /// The kernel has dropped `nlookup` of its references to `ino` (FUSE
    /// `forget`). With none left the entry goes; the root always stays.
    /// Numbers are never reused, so a stale `forget` can't hit a newer entry.
    pub fn forget(&mut self, ino: u64, nlookup: u64) {
        if ino == ROOT_INO {
            return;
        }
        let Some(n) = self.by_ino.get_mut(&ino) else {
            return; // already gone (deleted, or dropped as uncounted)
        };
        if n.lookups == 0 {
            return; // never counted: nothing the kernel holds
        }
        n.lookups = n.lookups.saturating_sub(nlookup);
        if n.lookups == 0 {
            if let Some(n) = self.by_ino.remove(&ino) {
                self.by_key.remove(&names::fold(&n.path));
            }
        }
    }

    /// Drop every entry the kernel holds no reference to, once there are
    /// many. Called before a directory listing hands out numbers, never
    /// during one, so a listing's own numbers stay put while it's answered.
    pub fn trim(&mut self) {
        if self.uncounted < MAX_UNCOUNTED {
            return;
        }
        self.by_ino.retain(|&ino, n| ino == ROOT_INO || n.lookups > 0);
        let by_ino = &self.by_ino;
        self.by_key.retain(|_, ino| by_ino.contains_key(ino));
        self.uncounted = 0;
    }

    /// How many entries the table holds, the root included.
    pub fn len(&self) -> usize {
        self.by_ino.len()
    }

    /// Never true: the root is always there.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Point `old` and everything under it at `new` (a rename or move),
    /// keeping their inode numbers and lookup counts.
    pub fn rename(&mut self, old: &str, new: &str) {
        let old_key = names::fold(old);
        if old_key.is_empty() {
            return; // never re-key the root
        }
        let moved: Vec<(u64, String)> = self
            .by_ino
            .iter()
            .filter(|(_, n)| within(&names::fold(&n.path), &old_key))
            .map(|(&ino, n)| (ino, n.path.clone()))
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
            if let Some(n) = self.by_ino.get_mut(&ino) {
                n.path = renamed;
            }
        }
    }

    /// Drop `path` and everything under it (after a delete or a replace).
    pub fn remove(&mut self, path: &str) {
        let key = names::fold(path);
        if key.is_empty() {
            return;
        }
        let gone: Vec<u64> = self
            .by_ino
            .iter()
            .filter(|(_, n)| within(&names::fold(&n.path), &key))
            .map(|(&ino, _)| ino)
            .collect();
        for ino in gone {
            if let Some(n) = self.by_ino.remove(&ino) {
                self.by_key.remove(&names::fold(&n.path));
                if n.lookups == 0 {
                    self.uncounted -= 1;
                }
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
    fn remove_drops_subtree_only() {
        let mut t = Inodes::default();
        let a = t.ino("A");
        let f = t.ino("A/f");
        let ab = t.ino("AB");
        t.remove("A");
        assert_eq!(t.path(a), None);
        assert_eq!(t.path(f), None);
        assert_eq!(t.path(ab), Some("AB"));
        assert_ne!(t.ino("A"), a); // a new entry gets a new number
    }

    #[test]
    fn forget_drops_an_entry_once_every_lookup_is_forgotten() {
        let mut t = Inodes::default();
        let a = t.looked_up("A");
        assert_eq!(t.looked_up("a"), a);
        t.forget(a, 1);
        assert_eq!(t.path(a), Some("a")); // one lookup still held (latest spelling)
        t.forget(a, 1);
        assert_eq!(t.path(a), None);
        assert_ne!(t.looked_up("A"), a); // numbers are never reused
        t.forget(a, 5); // a stale forget for the old number is harmless
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn root_and_listed_entries_ignore_forget() {
        let mut t = Inodes::default();
        t.forget(ROOT_INO, 1);
        assert_eq!(t.path(ROOT_INO), Some(""));
        let listed = t.ino("listed");
        t.forget(listed, 1);
        assert_eq!(t.path(listed), Some("listed"));
    }

    #[test]
    fn browsing_a_huge_tree_stays_bounded() {
        let mut t = Inodes::default();
        let held = t.looked_up("kept/open.txt");
        // Listings of 1,000 entries each, as readdir hands them out.
        for listing in 0..5 * MAX_UNCOUNTED / 1000 {
            t.trim();
            for i in 0..1000 {
                t.ino(&format!("big/{listing}/{i}"));
            }
        }
        assert!(t.len() <= MAX_UNCOUNTED + 1000 + 2, "table grew to {}", t.len());
        assert_eq!(t.path(held), Some("kept/open.txt")); // held entries survive
        assert_eq!(t.path(ROOT_INO), Some(""));
    }

    #[test]
    fn looking_up_a_listed_entry_counts_it() {
        let mut t = Inodes::default();
        let a = t.ino("A");
        assert_eq!(t.looked_up("A"), a);
        for i in 0..2 * MAX_UNCOUNTED {
            t.ino(&format!("big/{i}"));
        }
        t.trim();
        assert_eq!(t.path(a), Some("A")); // counted now, so not dropped as listed
        t.forget(a, 1);
        assert_eq!(t.path(a), None);
    }

    #[test]
    fn removing_listed_entries_keeps_the_bound_honest() {
        let mut t = Inodes::default();
        for i in 0..100 {
            t.ino(&format!("dir/{i}"));
        }
        t.remove("dir");
        assert_eq!(t.uncounted, 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn rename_keeps_lookup_counts() {
        let mut t = Inodes::default();
        let f = t.looked_up("A/f");
        t.rename("A", "B");
        assert_eq!(t.path(f), Some("B/f"));
        t.forget(f, 1);
        assert_eq!(t.path(f), None);
    }

    #[test]
    fn path_helpers() {
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("a/b", "c"), "a/b/c");
        assert_eq!(parent_of("a/b/c"), "a/b");
        assert_eq!(parent_of("a"), "");
    }
}
