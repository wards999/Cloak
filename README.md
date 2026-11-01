# cloak

A name-mapping overlay filesystem with **header/footer encryption**. You mount a
drive; through the mount you see your real filenames and read files normally. On
disk, the backing store holds the same files under **boring, machine-looking
names** (`index_shard_0472.idx`) with only their **first and last N bytes
encrypted** so they won't open, while the bulk of each file is left as untouched
passthrough.

It is one portable core engine plus a thin, OS-specific mount adapter — so the
same logic runs on **Windows** (via WinFsp) and **macOS** (via macFUSE/FSKit).

## Why this shape

- **Boring names** beat random hex: a folder of `a9f3b201.dat` blobs screams
  "hidden data." Dull infrastructure-looking names (and extensions nothing
  auto-previews) make the eye — and the thumbnailer — slide past.
- **Header/footer encryption** beats full-file encryption *for large files*:
  the structural metadata that makes a file openable lives at the ends, so
  encrypting ~64 KiB at each end makes the file fail to open while leaving
  gigabytes of body as zero-cost passthrough. Random-access seeks in the middle
  stay native speed — which matters a lot through a userspace mount.

## ⚠️ Threat model — read this

This is **obfuscation hardened at the edges, not confidentiality.**

| Defends against | Does **not** defend against |
|---|---|
| A human scrolling a directory listing | `file *` / content carving (PhotoRec, binwalk) |
| Casual double-click (file won't open) | A forensic examiner scanning the plaintext body |
| Thumbnailer tells (boring extensions) | Anyone with the index **and** the key |

The body of every file stays **plaintext on disk**. For large media that is
self-describing (video frames, audio, embedded thumbnails), a determined
examiner can recover a lot from the middle even though the file won't "open."
If your threat model includes that, you want **full-file authenticated
encryption** (VeraCrypt, gocryptfs, Cryptomator) instead — this tool is for the
"casual glance / mild obscurity, keep it fast" end of the spectrum.

Two more honest caveats:
- The **index** (`index.json`) is single point of failure: lose it and the store
  is anonymous blobs. Back it up; encrypt it in a real deployment.
- Only the ends are authenticated-free XOR keystream here; there's no integrity
  check over the passthrough body. Tampering with the middle is undetectable.

## Layout

```
src/crypto.rs   seekable ChaCha20; encrypt first-N and last-N bytes
src/boring.rs   boring decoy-name generator
src/manifest.rs per-directory encrypted boring<->real mapping (the tree)
src/key.rs      Argon2id passphrase -> master key (key never stored)
src/engine.rs   Store: path/tree ops (mkdir / create / write_at / rename / move / remove)
src/names.rs    cross-platform name rules (NFC, case folding, limits, Windows mapping)
src/inodes.rs   inode <-> path table for the fuser adapter
src/bin/mount.rs     read-write fuser mount adapter (macOS/Linux)
src/bin/winmount.rs  read-write WinFsp mount adapter (Windows, MSVC)
src/bin/gui.rs       cross-platform eframe GUI (mount/unmount + passphrase)
benches/crypto_bench.rs  full-file vs ends-only timing
```

The engine and all leaf modules are platform-independent and fully unit-tested
with **no FUSE driver required**.

## One drive, Windows and macOS

A store folder (synced or copied) mounts the same on both systems. The on-disk
format is OS-neutral (lowercase-ASCII boring names, JSON manifests), and real
names follow one set of rules (`src/names.rs`):

- **Unicode form:** names are stored and compared in NFC, so a name a Mac app
  hands over decomposed (`e` + accent) is the same file as Windows' `é`.
- **Case:** case-insensitive and case-preserving on both, with Unicode folding
  (`Ä.txt` = `ä.txt`, like NTFS/APFS).
- **Limits:** a name must fit both OSes — at most 255 UTF-8 bytes (macOS),
  no `/` or NUL. Longer names are refused at creation.
- **Mac-only characters:** `" * : < > ? \ |`, control characters, a trailing
  space/dot and device names (`CON`, `aux.txt`) are legal on macOS but not on
  Windows. The Windows adapter shows them through the Services-for-Macintosh
  mapping macOS's own SMB client uses (private-use look-alikes such as U+F022
  for `:`); nothing is renamed on disk and the mapping round-trips.
- **Mac litter:** the macOS adapter mounts with `noappledouble`/`noapplexattr`
  and refuses `._*`/`.DS_Store`, so Finder metadata never lands in the store.
- **Saving:** both adapters support rename-over-existing (how most editors
  save) and case-only renames.

## Build & run

```bash
# core engine + all unit tests (works anywhere, no driver needed)
cargo test

# the full-file vs ends-only benchmark
cargo bench

# the GUI (cross-platform): pick a store folder, mount point, passphrase
cargo run --features gui --bin cloak-gui

# mount via CLI (macOS: install macFUSE first; Linux: libfuse3)
# Holds the mount until Enter / stdin closes, then unmounts.
CLOAK_PASSPHRASE=... cargo run --features mount --bin cloak-mount -- ./store ./mnt
```

On **Windows** the mount adapter uses [WinFsp](https://winfsp.dev) and must be
built with the **MSVC** toolchain (the `winfsp` crate delay-loads via an
MSVC-only linker feature; it does not build under GNU):

```bash
# needs WinFsp installed + Visual Studio Build Tools (Desktop C++) + LLVM
cargo build --features winfsp --bin cloak-winmount
set CLOAK_PASSPHRASE=... & cloak-winmount .\store X:
```

Don't want the local MSVC install? The GitHub Actions workflow
(`.github/workflows/ci.yml`) compiles the WinFsp adapter on a Windows MSVC
runner for you, and builds the core + GUI + fuser adapter across all three OSes.

## Status

- [x] Seekable header/footer crypto + tests
- [x] Boring-name generator + tests
- [x] Lookup index with persistence + tests
- [x] Storage engine (ingest / ranged read / write path) + tests
- [x] Read-write fuser mount adapter (macOS/Linux)
- [x] WinFsp mount adapter (Windows, MSVC)
- [x] Passphrase-derived key (Argon2id); key never stored
- [x] Folder tree: boring-named dirs + per-directory encrypted manifests
- [x] Cross-platform GUI (mount/unmount + passphrase; Windows drive-letter picker)
- [x] Full-file vs ends-only benchmark
- [x] GitHub Actions CI (core + adapters + GUI across 3 OSes)
- [ ] FSKit adapter for modern macOS (kext-free; via a C-ABI core)
- [ ] Code signing / notarization for public distribution
- [ ] Optional per-region nonce for files > 256 GiB
