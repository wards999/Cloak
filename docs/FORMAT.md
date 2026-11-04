# cloak drive format, version 2

A drive is a folder. Its tree mirrors the drive's tree, with every file and
folder under a random dull name. What a drive keeps for itself:

| File | Where | What |
|---|---|---|
| `meta.json` | top | format version, password settings, the wrapped master key |
| `manifest.idx` (+ `manifest.pNN.idx`) | every folder | that folder's list (the "notebook") |
| `journal.idx` | top | a change in progress, while it is |
| envelope | last 512 bytes of every file | the file's own description |

## Keys

* **Password → key-encryption key (KEK).** Argon2id with the settings
  recorded in `meta.json` (`kdf`), over a random 16-byte salt.
* **Master key.** 32 random bytes, made when the drive is. Stored only
  wrapped: `meta.json`'s `wrapped` is XChaCha20-Poly1305 of the master key
  under the KEK. A wrong password fails the wrap's tag, which is how it's
  told apart. Changing the password rewraps this one value.
* **File key.** 32 random bytes per file, made when the file is. It encrypts
  that file's ends and nothing else. It's kept in the file's list entry and
  in its envelope, both sealed with the master key.

## Sealing

Lists, envelopes and journals are sealed with XChaCha20-Poly1305 under the
master key: `24-byte random nonce || ciphertext || 16-byte tag`. Each kind
binds a label as associated data (`cloak-list-v2`, `cloak-envelope-v2`,
`cloak-journal-v2`), so one can't be passed off as another. Anything that
fails its tag is damaged or tampered with and is reported as such, never
read as garbage.

## File contents

A file on disk is `data || envelope`. Its real length is its length on disk
minus 512.

The data is the file's bytes, with its first and last `region` bytes
(64 KiB; the whole file when it's at most twice that) XORed with ChaCha20
under the file key and the file's content nonce, keyed by file offset. The
middle is stored as is, by design.

**Fresh nonce per editing session.** The first change in a session (between
opening a file and its last close) that overwrites bytes in its encrypted
ends, or shortens it, first gives the file a new random content nonce:
both ends are re-encrypted, and the list and envelope are updated. Two
copies of a file from either side of an edit therefore never share a
keystream. Appending, writing a new file and writing only the middle don't
need it: they never encrypt different bytes at an offset already used.

## Envelope (512 bytes)

`24-byte nonce || sealed 472 bytes || 16-byte tag`, sealed with the master
key. The 472 plaintext bytes:

| Bytes | Field |
|---|---|
| 1 | layout version (1) |
| 16 | file ID (random, stable) |
| 32 | file key |
| 12 | content nonce |
| 2 | real-name length in bytes (≤ 255), little-endian |
| 255 | real name, UTF-8, zero-padded |
| rest | zeros |

There's no plaintext marker: a file is recognized by its envelope opening
under a key. Every envelope is the same size, so the name's length doesn't
show.

**Names are lazy.** A rename changes only the list. The envelope's name is
brought up to date the next time the envelope is rewritten (a new nonce,
or the file being adopted elsewhere), so after a rename it can be stale. The
list is authoritative; the envelope is for recovery and adoption.

## Lists

JSON, sealed as above: `children` (each with its real name, dull name,
kind, file ID, file key, content nonce and a size hint), and `name`: the
folder's own real name (none for the top). A big list is split into parts as
before; the folder's own name is in `manifest.idx`.

## Strays

When a folder is listed (its disk scan happens anyway), names on disk are
checked against its list in memory:

* **On disk, not listed:** a stray. A folder whose list opens under the
  master key, or a file whose envelope does, came from elsewhere in this
  drive and is added to the list under its real name (`(conflict N)` added
  if the name is taken). Anything else is from another drive: it's left
  untouched, never shown or deleted, and counted for the app.
* **Listed, not on disk:** moved out or deleted outside cloak; the entry is
  dropped.

A folder is only rescanned when its modified time has changed. Bringing in
another drive's strays (`cloak adopt`) needs both drives' passwords: each
envelope (and each list, for a folder) is opened with the other drive's
master key and sealed again with this one's. A file's data and file key
don't change, so it costs about 512 bytes per file.

## Crash safety

As in version 1 (atomic list writes, the journal for moves and purges, and
undo records for bytes that move between encrypted and plain), plus:

* **New nonce:** the file's original ends and envelope are journaled,
  then re-encrypted and the file synced, then its list saved. After a crash,
  if the list still has the old nonce, the original bytes are put back.
* **Envelope rewrites** (adoption) journal the old envelope first.
* **Resizing** journals the old envelope along with the other bytes it
  undoes.

## Version 1

Drives made by earlier test versions (`meta.json` without `"version": 2`)
aren't opened: the app says so rather than reporting a wrong password.
