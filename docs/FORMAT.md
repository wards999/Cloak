# cloak drive format, version 3

A drive is a folder. Its tree mirrors the drive's tree, with every file and
folder under a random dull name. Nothing in it is plain text, and nothing
has a fixed name that marks it as cloak's: even the drive's own records are
named like everything else.

| What | Where | Name |
|---|---|---|
| a folder's list (the "notebook") | every folder | a dull name worked out from the drive's key (the same in each folder of a drive; different per drive) |
| parts of a big folder's list | that folder | the list's name with `_pNN` added |
| items found gone from the disk, until dismissed | top | another name worked out from the key |
| a change in progress, while it is | top | `journal.idx` |
| envelope | last 512 bytes of every file | |

There's no `meta.json`: every file and every list carries the drive's lock.

## Keys

* **Master key.** 32 random bytes, made when the drive is. Everything else
  is sealed with it.
* **The lock.** The master key (and the drive's `region`), sealed with
  XChaCha20-Poly1305 under a key derived from the password: Argon2id, with
  the settings this format fixes (19 MiB, 2 passes, 1 lane), over the
  drive's random 16-byte salt. 104 bytes:
  `salt (16) || generation (8, LE) || nonce (24) || sealed master key and
  region (40) || tag (16)`. The salt and generation are in the clear: the
  salt is where the password's key starts from, and the generation counts
  password changes. Each copy is sealed afresh, so only the salt and the
  generation repeat across a drive. That's the price of recovering any one
  file with its password alone: two files of the same drive can be shown to
  belong together.
* **File key.** 32 random bytes per file, made when the file is. It encrypts
  that file's ends and nothing else. It's kept in the file's list entry and
  in its envelope, both sealed with the master key.

**Unlocking** reads the lock from the last 512 bytes of the files in the
drive's folder (top folder first): a lock's generation is a small number,
so the bytes at that place in anything else almost never pass for one, and
a drive's locks share a salt. One Argon2id step with the password, then the
lock opens or the password is wrong. If the password opens only an older
generation than the drive's newest, the password has been changed and the
user is told so.

**Changing the password** makes a new salt and the next generation, and
rewrites the lock in every list (the top folder's first) and every file's
envelope; nothing else changes. A marker at the top (a name worked out
from the key) says a change is under way, so if it's interrupted, opening
the drive with the new password finishes it.

## Sealing

Lists, envelopes, the missing-items record and journals are sealed with
XChaCha20-Poly1305 under the master key: `24-byte random nonce ||
ciphertext || 16-byte tag`. Each kind binds a label as associated data
(`cloak-list-v3`, `cloak-envelope-v3`, `cloak-missing-v3`,
`cloak-journal-v3`), so one can't be passed off as another. Anything that
fails its tag is damaged or tampered with and is reported as such, never
read as garbage.

## File contents

A file on disk is `data || envelope`. Its real length is its length on disk
minus 512. The one exception is a new file that's still empty: it may be 0
bytes with no envelope yet (it gets one with its first data, or when it's
closed or the drive saves), so a new file is written once, not twice.

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

`lock (104) || 24-byte nonce || sealed 368 bytes || 16-byte tag`, the
sealed part under the master key. The 368 plaintext bytes:

| Bytes | Field |
|---|---|
| 1 | layout version (1) |
| 16 | file ID (random, stable) |
| 32 | file key |
| 12 | content nonce |
| 2 | real-name length in bytes (≤ 255), little-endian |
| 255 | real name, UTF-8, zero-padded |
| rest | zeros |

There's no plaintext marker. Every envelope is the same size, so the name's
length doesn't show.

**Names are lazy.** A rename changes only the list. The envelope's name is
brought up to date the next time the envelope is rewritten (a new nonce,
or the file being adopted elsewhere), so after a rename it can be stale. The
list is authoritative; the envelope is for recovery and adoption.

## Lists

JSON, sealed as above, followed by a 512-byte tail shaped like an envelope:
the drive's lock, then random bytes. So every hidden file of a drive, list
or not, carries the lock in the same place. The JSON holds `children` (each
with its real name, dull name, kind, file ID, file key, content nonce and a
size hint) and `name`: the folder's own real name (none for the top). A big
list is split into parts; the folder's own name is in the main list.

## Strays

When a folder is listed (its disk scan happens anyway), names on disk are
checked against its list in memory:

* **On disk, not listed:** a stray. A folder whose list opens under the
  master key, or a file whose envelope does, came from elsewhere in this
  drive and is added to the list under its real name (`(conflict N)` added
  if the name is taken). Anything else that carries a lock is from another
  drive: it's left untouched, never shown or deleted, and counted for the
  app. Bringing it in needs only that drive's password, not its folder:
  the stray's own lock gives that drive's master key. Each envelope (and
  each list, for a folder) is then sealed again for this drive; a file's
  data and file key don't change, so it costs about 512 bytes per file.
  Another drive's list file copied in with its files is removed once they
  are brought in.
* **Listed, not on disk:** moved out or deleted outside cloak; the entry is
  dropped and recorded (sealed: its path, whether it's a folder, when it
  went), for the app to show. If it comes back it's taken in as a stray and
  its record clears; a move between two folders of the drive isn't
  recorded, whichever folder is seen first.

**A list that won't open** (damaged, or another drive's list copied over
it) is set aside as `unreadable-list-<time>-<name>.bak`, never deleted, and
the folder's list is rebuilt the same way: its files by their envelopes,
its subfolders by their own lists (repaired too when unreadable but holding
this drive's files), its own name from its parent's list. A folder whose
name was only in unreadable lists comes back as "Recovered folder". A
missing top list is simply rebuilt: the drive still unlocks from any file,
as long as every lock in the folder is this drive's. If other drives' items
are there too, a folder whose top list is lost can't be told apart from
another drive's folder holding this drive's items, so unlocking stops and
says how many items the password opens; only once the user confirms it's
their drive ("claim") is it opened and its top list rebuilt.

A folder is only rescanned when its modified time has changed.

## Crash safety

Atomic list writes, the journal for moves and purges, and undo records for
bytes that move between encrypted and plain, plus:

* **New nonce:** the file's original ends and envelope are journaled,
  then re-encrypted and the file synced, then its list saved. After a crash,
  if the list still has the old nonce, the original bytes are put back.
* **Envelope rewrites** (adoption) journal the old envelope first.
* **Resizing** journals the old envelope along with the other bytes it
  undoes.
* **Password changes** rewrite only locks: a torn write there leaves the
  rest of an envelope, and the file's list entry, as they were. The change
  is resumed on the next open with the new password.

## Earlier versions

Drives made by earlier test versions (with a `meta.json`) aren't opened:
the app says so rather than reporting a wrong password.
