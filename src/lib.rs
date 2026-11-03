//! cloak — a name-mapping overlay filesystem with header/footer encryption.
//!
//! Architecture (see the module docs for detail):
//!
//! ```text
//!   OS / Finder / Explorer
//!            │  real names, normal reads & seeks
//!   ┌────────▼─────────┐
//!   │  mount adapter   │  fuser (macOS/Linux) · winfsp (Windows)   [src/bin/mount.rs]
//!   └────────┬─────────┘
//!            │  by original name, byte ranges
//!   ┌────────▼─────────┐
//!   │   Store (engine) │  ingest / read_at / list                 [engine.rs]
//!   └──┬────────┬──────┘
//!      │        │
//!  ┌───▼──┐  ┌──▼─────┐  ┌──────────┐
//!  │index │  │ crypto │  │  boring  │  scrambled↔original · ends cipher · decoy names
//!  └──────┘  └────────┘  └──────────┘
//! ```
//!
//! The engine and all three leaf modules are platform-independent and fully
//! unit-tested without a FUSE driver. Only the mount adapter is OS-specific.
//!
//! This is an **obfuscation** tool hardened at the file edges, not a
//! confidentiality guarantee: the body of each file stays plaintext on disk.
//! See README.md for the threat model.

pub mod backup;
pub mod boring;
pub mod convert;
pub mod crypto;
pub mod dircache;
pub mod durable;
pub mod engine;
pub mod inodes;
pub mod key;
pub mod manifest;
pub mod names;

pub use crypto::{Key, Nonce, KEY_LEN, NONCE_LEN};
pub use engine::{DirEntry, Metadata, Store};
pub use key::{derive_key, KdfParams, Salt};
pub use manifest::{Child, Kind, Manifest};
