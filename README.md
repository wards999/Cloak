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

What it does guarantee (drive format 2, see [`docs/FORMAT.md`](docs/FORMAT.md)):
- **Each file has its own key**, and its ends get a fresh nonce whenever an
  editing session changes them, so two copies of a file from either side of
  an edit (from sync history or a backup) don't give each other away.
- **Lists, file envelopes and the drive header are authenticated**: a damaged
  or tampered one is reported, never read as garbage. The plain middle of a
  file has no integrity check, by design.
- **Nothing hangs on one file**: every file ends with a sealed envelope (its
  key, nonce and real name) and every folder's list records the folder's own
  name, so a lost list is rebuilt from what's on disk.

## Layout

```
src/crypto.rs   seekable ChaCha20 for the ends; XChaCha20-Poly1305 sealing
src/envelope.rs the 512-byte envelope that ends every file
src/boring.rs   boring decoy-name generator
src/manifest.rs per-directory encrypted boring<->real mapping (the tree)
src/key.rs      Argon2id passphrase -> key that unwraps the drive's master key
src/engine.rs   Store: path/tree ops (mkdir / create / write_at / rename / move / remove)
src/names.rs    cross-platform name rules (NFC, case folding, limits, Windows mapping)
src/durable.rs  crash-safe metadata writes (side file + flush + rename)
src/backup.rs   password-protected recovery backups of headers and folder lists
src/convert.rs  turn an existing folder into a drive in place (and back), crash-safe
src/dircache.rs folder-list cache, delayed saving, and split lists for big folders
src/inodes.rs   inode <-> path table for the fuser adapter
src/bin/mount.rs     read-write fuser mount adapter (macOS/Linux)
src/bin/winmount.rs  read-write WinFsp mount adapter (Windows, MSVC)
pyapp/cloak_app.py   desktop app (PySide6 + QFluentWidgets): create, lock, unlock
pyapp/package.py     packages the app with the engine inside (PyInstaller)
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
- **Mac litter:** the macOS adapter mounts with `noappledouble`, refuses
  `._*`/`.DS_Store`, and accepts but drops extended attributes (tags,
  quarantine, provenance), so Finder metadata never lands in the store.
- **Saving:** both adapters support rename-over-existing (how most editors
  save) and case-only renames.

## Crash safety

- **Manifests and the store header** are written to a side file, flushed to the
  disk and renamed into place, so a crash or power cut leaves the old or the
  new version, never a torn one.
- **Folder lists are saved half a second after they change**, in one batch,
  not on every create, delete or rename (that wait for the disk was most of
  the time spent on small files). Like any disk, a crash or power cut can lose
  the last moment of changes, but never mixes them up: every folder comes back
  as it was at its last save. Unmounting, closing the CLI, and an app flushing
  a file all save at once.
- **Deletes** leave the folder list at once and the disk only after the list
  is saved, so a crash can't leave a name pointing at nothing. The deletion
  is journaled (`journal.idx`, encrypted, at the store root) and finished on
  the next mount if interrupted. A file created just before a crash whose
  name wasn't saved yet stays on disk unnamed.
- **Moves between folders** change two lists and the disk, so they are
  journaled and saved before they return; a crash part-way is finished on
  the next mount. Nothing ends up listed twice, missing, or left behind.
- **File writes** behave like a normal filesystem: data an app has flushed
  (`fsync`, `FlushFileBuffers`) survives a crash; unflushed writes may not.
  When a write has to re-encode bytes that were already safely on disk (the
  encrypted end moving as a file grows or shrinks), the originals are
  journaled first and restored if the write is interrupted. Plain copies and
  appends never need this, so they run at full speed.
- **Sync conflicts:** when two machines change the same folder, sync tools
  keep both manifests (`manifest (conflicted copy).idx` and the like). On
  mount these are merged: files added on either side appear, files deleted on
  either side stay deleted, and a name clash becomes `name (conflict 1).ext`.
- **Changes from other machines** (a sync tool replacing a folder list while
  mounted) show up within a second, and are merged with any unsaved changes
  here rather than overwritten.
- **Big folders:** past 2,048 entries a folder's list can be split into 64
  parts (`manifest.pNN.idx`). A save that changes only a few entries rewrites
  just their parts; one that changes entries all over (a bulk copy) writes
  the list as one file, a single disk wait instead of 65.
- A file's size is its boring file's length; manifests aren't rewritten on
  every write. Use the same cloak version on every machine sharing a store:
  v0.1.1 and earlier read sizes from the manifest and would see stale ones,
  and can't read a split folder list.

## The desktop app is portable

The Cloak app keeps its drive list and settings in a `cloak-data` folder next
to itself: beside `Cloak.exe` on Windows, beside `Cloak.app` on macOS.
Nothing is written to your user profile, so the app can live on a USB stick.

On macOS the release is a disk image (`.dmg`). Drag Cloak to Applications
for a normal install (it then keeps its data in `~/.cloak`), or copy it to
any other folder, such as a USB stick, to run it portably.

- A drive on the same disk as the app is remembered by its path relative to
  the app too, so it's still found when the stick gets a different drive
  letter (or mount point) on another computer.
- On first run the app copies in the drive list and settings that earlier
  versions kept in `~/.cloak`.
- If the app's folder can't be written to (Program Files, `/Applications`,
  or a macOS quarantine copy), it uses `~/.cloak` instead. The Settings page
  shows which folder is in use.
- Passwords are never stored. Each drive's own folder holds everything needed
  to open it.

## Size and free space

A mounted drive reports the size and free space of the disk its folder is on.
Nothing is reserved: the drive's files are ordinary files in that folder, so
the drive grows as you add to it and shares its free space with everything
else on that disk. A drive whose folder is on C: shows C:'s numbers, and
copying 1 GB into it uses 1 GB of C:. On Windows the free space shown updates
whenever something is written to the drive; space used on the same disk by
other programs shows up then, or on remount.

## Recovery backups

Two kinds of file matter most: a drive's `meta.json` (without it no password
can open the drive) and each folder's list, `manifest.idx` (without it that
folder's names, and the keys to the encrypted ends of its files, are gone).
The app can back these up, for one drive (the save button on its card) or
all of them (Settings → Recovery), into one `.cloakbak` file protected by a
password of your choice (Argon2id + XChaCha20-Poly1305, so a wrong password
or a damaged file is detected). It holds no file contents: keep a normal
backup of each drive's folder too.

**Restore from a backup…** puts a drive's header and lists back only where
they're missing or can't be read. A list that still reads is newer than the
backup and is left alone, so files added since aren't hidden. Restoring
needs both the backup's password and the drive's own, and won't overwrite a
different drive. The same is available from the command line:

```bash
CLOAK_BACKUP_PASSPHRASE=... cloak backup out.cloakbak "Personal" D:/Personal "Work" E:/Work
CLOAK_BACKUP_PASSPHRASE=... cloak backup-list out.cloakbak
CLOAK_BACKUP_PASSPHRASE=... CLOAK_PASSPHRASE=... cloak restore out.cloakbak "Personal" D:/Personal
```

## Converting a folder you already have

**Convert folder** makes an existing folder into a drive where it lies,
without copying it. A drive's files hold their original bytes apart from the
encrypted ends, so converting only renames each file and folder and encrypts
each file's first and last 64 KiB: a 40 GB file costs no more than a small
one, and almost no free space is needed. A dry run checks the folder first
and changes nothing if anything is in the way (names a drive can't hold,
links, read-only or cloud-only files, names cloak keeps for itself);
`.DS_Store`, `Thumbs.db` and similar clutter are deleted.

It's crash-safe: each folder's list is written before anything in it
changes, and each file's original ends are journaled before they're touched,
with its rename as the commit. An interrupted conversion shows **Resume** on
the drive's card and carries on where it stopped; the drive can't be unlocked
until it's finished. The return button on a locked drive's card turns it back
into a plain folder the same way.

The originals' plaintext ends may survive in the disk's free space (SSDs and
copy-on-write file systems write elsewhere), real names linger in search
indexes and recent-file lists, and a synced folder's service keeps the
originals in its version history: the dry run warns about the last.

```bash
cloak convert-scan D:/Photos                 # the dry run: a JSON report
CLOAK_PASSPHRASE=... cloak convert D:/Photos   # convert (or resume)
CLOAK_PASSPHRASE=... cloak unconvert D:/Photos # back to a plain folder
```

## Moving files between drives by hand

Every file describes itself (its envelope) and every folder knows its own
name, so the hidden files can be moved around outside cloak:

- **Within one drive** (moving a hidden file or folder into another hidden
  folder of the same drive): it shows up in its new place the next time that
  folder is opened, under its real name.
- **Into another drive's folder**: it's left untouched until it's brought in,
  since it's sealed for the drive it came from. The app counts what's waiting
  on the drive's card; **More → Bring in files from another drive** asks for
  both drives' passwords and re-seals each envelope (about 512 bytes per file,
  whatever its size). Do this with both drives locked.

The same from the command line, plus the password change that format 2 makes
instant (only `meta.json` changes):

```bash
CLOAK_PASSPHRASE=... cloak strays D:/Work                    # -> {"foreign": n}
CLOAK_PASSPHRASE=... CLOAK_OTHER_PASSPHRASE=... cloak adopt D:/Work D:/Holiday
CLOAK_PASSPHRASE=old CLOAK_NEW_PASSPHRASE=new cloak passwd D:/Work
```

## Performance notes

- **Open files are read and written by handle.** A mount adapter opens a file
  once (`Store::open_file`) and its reads and writes go straight to the hidden
  file, without looking the path up again; the handle follows renames and
  moves.
- **Reads run in parallel.** The store sits behind a read-write lock: reads,
  lookups and listings run side by side, changes one at a time. WinFsp calls
  in on many threads already; the macOS/Linux adapter hands reads to four
  worker threads, since fuser delivers one request at a time.
- **Windows caching** is on for file data and file details (read-ahead,
  gathered small writes) but off for folder listings, so file managers see
  changes at once. A file's cached writes reach the store when the app
  closes it.

## Build & run

```bash
# core engine + all unit tests (works anywhere, no driver needed)
cargo test

# the full-file vs ends-only benchmark
cargo bench

# the desktop app (needs Python 3.12 and the engine built in target/release)
pip install -r pyapp/requirements.txt
python pyapp/cloak_app.py

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
runner for you, builds the core and fuser adapter across all three OSes, and
checks the desktop app.

## Status

- [x] Seekable header/footer crypto + tests
- [x] Boring-name generator + tests
- [x] Lookup index with persistence + tests
- [x] Storage engine (ingest / ranged read / write path) + tests
- [x] Read-write fuser mount adapter (macOS/Linux)
- [x] WinFsp mount adapter (Windows, MSVC)
- [x] Passphrase-derived key (Argon2id) wrapping a random master key; per-file keys
- [x] Format 2: envelopes, authenticated lists, fresh nonce per edit, strays
- [x] Folder tree: boring-named dirs + per-directory encrypted manifests
- [x] Desktop app (Fluent design; create, lock/unlock, auto-lock on sleep)
- [x] Full-file vs ends-only benchmark
- [x] GitHub Actions CI (core + adapters across 3 OSes, desktop app)
- [ ] FSKit adapter for modern macOS (kext-free; via a C-ABI core)
- [ ] Code signing / notarization for public distribution
- [ ] Optional per-region nonce for files > 256 GiB
