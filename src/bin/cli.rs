//! `cloak` — a headless command bridge over the engine, for the GUI to call.
//!
//! Every command takes the drive folder as the first argument and the password
//! from the `CLOAK_PASSPHRASE` environment variable (kept off argv). Output is a
//! single line of JSON on stdout; on error it prints `{"error": "..."}` and
//! exits non-zero.
//!
//!   cloak create <dir>                 create a new drive
//!   cloak open   <dir>                 verify the password opens the drive
//!   cloak claim  <dir>                 open it as the password's drive though
//!                                      its top list is missing and other
//!                                      drives' items are there too (after
//!                                      `open` said so); rebuilds the list
//!   cloak ls     <dir> <path>          list a directory -> [{name,is_dir,size}]
//!   cloak stat   <dir> <path>          -> {exists,is_dir,size}
//!   cloak mkdir  <dir> <path>          make a folder
//!   cloak write  <dir> <path> <src>    import a real file into the drive
//!   cloak read   <dir> <path> <dest>   extract a file out to disk
//!   cloak rm     <dir> <path>          delete a file or folder
//!   cloak mv     <dir> <old> <new>     rename / move
//!
//! Converting a folder in place (see `cloak::convert`):
//!
//!   cloak convert-scan <dir>           dry run, no password -> the report
//!   cloak convert      <dir>           make the folder a drive (or resume)
//!   cloak unconvert    <dir>           make a drive a plain folder again
//!
//! `convert` and `unconvert` also print `{"progress": n, "total": t}` lines
//! while they run; the last line is the result as usual.
//!
//! Files and folders moved in from elsewhere (see `docs/FORMAT.md`):
//!
//!   cloak strays <dir>                 check the whole drive -> {foreign, missing}
//!   cloak missing <dir>                what has gone missing -> {missing:
//!                                      [{path, is_dir, since}]}
//!   cloak missing-clear <dir>          dismiss that record
//!   cloak adopt-check <dir> [<other-dir>]  what adopt would bring in, changing
//!                                      nothing -> {found: [{path, name,
//!                                      is_dir, items}], left}
//!   cloak adopt  <dir> [<other-dir>]   bring in what came from another drive
//!                                      (its password in CLOAK_OTHER_PASSPHRASE;
//!                                      its folder isn't needed: the strays
//!                                      carry its lock) -> {adopted, left}
//!   cloak passwd <dir>                 change the password (the new one in
//!                                      CLOAK_NEW_PASSPHRASE); prints progress

use cloak::Store;
use std::env;
use std::error::Error;

const REGION: u64 = 64 * 1024;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => println!("{out}"),
        Err(e) => {
            println!("{}", serde_json::json!({ "error": e.to_string() }));
            std::process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<String, Box<dyn Error>> {
    let cmd = args.first().map(String::as_str).ok_or("usage: cloak <command> <dir> ...")?;
    if let Some(out) = backup_command(cmd, args)? {
        return Ok(out);
    }
    let dir = args.get(1).ok_or("missing <dir>")?;
    if cmd == "convert-scan" {
        return Ok(serde_json::to_string(&cloak::convert::scan(std::path::Path::new(dir), REGION)?)?);
    }
    let pass = env::var("CLOAK_PASSPHRASE").map_err(|_| "CLOAK_PASSPHRASE not set")?;
    match cmd {
        "strays" => {
            // Taking this drive's own strays back in happens on the way.
            let s = Store::open_with_passphrase(dir, &pass)?;
            let foreign = s.sweep()?;
            let missing = s.missing_count();
            drop(s); // saves the lists that changed
            return Ok(serde_json::json!({ "foreign": foreign, "missing": missing }).to_string());
        }
        "missing" => {
            let s = Store::open_with_passphrase(dir, &pass)?;
            s.sweep()?;
            return Ok(serde_json::json!({ "missing": s.missing() }).to_string());
        }
        "missing-clear" => {
            Store::open_with_passphrase(dir, &pass)?.clear_missing()?;
            return Ok(ok());
        }
        "adopt" | "adopt-check" => {
            let other_pass =
                env::var("CLOAK_OTHER_PASSPHRASE").map_err(|_| "CLOAK_OTHER_PASSPHRASE not set")?;
            let mut s = Store::open_with_passphrase(dir, &pass)?;
            // The other drive's key: from its folder if given, otherwise from
            // the locks the strays here carry.
            let others = match args.get(2) {
                Some(other_dir) => vec![
                    cloak::engine::unlock(std::path::Path::new(other_dir), &other_pass)
                        .map_err(|e| format!("the other drive: {e}"))?
                        .master,
                ],
                None => s.keys_for_strays(&other_pass)?,
            };
            if others.is_empty() {
                return Err("the other drive: wrong password (nothing waiting here opens with it)".into());
            }
            if cmd == "adopt-check" {
                let mut found = Vec::new();
                for k in &others {
                    found.extend(s.preview_from(k)?.0);
                }
                let left = s.foreign_count().saturating_sub(found.len());
                return Ok(serde_json::json!({ "found": found, "left": left }).to_string());
            }
            let mut adopted = 0;
            for k in &others {
                adopted += s.adopt_from(k)?.0;
            }
            let left = s.foreign_count();
            return Ok(serde_json::json!({ "adopted": adopted, "left": left }).to_string());
        }
        "passwd" => {
            let new = env::var("CLOAK_NEW_PASSPHRASE").map_err(|_| "CLOAK_NEW_PASSPHRASE not set")?;
            let mut progress = progress_lines();
            cloak::engine::change_password(std::path::Path::new(dir), &pass, &new, &mut progress)?;
            return Ok(ok());
        }
        _ => {}
    }
    if cmd == "convert" || cmd == "unconvert" {
        let dir = std::path::Path::new(dir);
        let mut progress = progress_lines();
        if cmd == "convert" {
            cloak::convert::convert(dir, &pass, REGION, &mut progress)?;
        } else {
            cloak::convert::unconvert(dir, &pass, &mut progress)?;
        }
        return Ok(ok());
    }

    match cmd {
        "create" => {
            Store::create_with_passphrase(dir, &pass, REGION)?;
            Ok(ok())
        }
        "open" => {
            Store::open_with_passphrase(dir, &pass)?;
            Ok(ok())
        }
        "claim" => {
            Store::claim_with_passphrase(dir, &pass)?;
            Ok(ok())
        }
        "ls" => {
            let path = arg(args, 2);
            let store = Store::open_with_passphrase(dir, &pass)?;
            let rows: Vec<_> = store
                .list_dir(&path)?
                .into_iter()
                .map(|(name, is_dir, size)| serde_json::json!({ "name": name, "is_dir": is_dir, "size": size }))
                .collect();
            Ok(serde_json::to_string(&rows)?)
        }
        "stat" => {
            let path = arg(args, 2);
            let store = Store::open_with_passphrase(dir, &pass)?;
            Ok(match store.metadata(&path)? {
                Some(m) => serde_json::json!({ "exists": true, "is_dir": m.is_dir, "size": m.size }).to_string(),
                None => serde_json::json!({ "exists": false }).to_string(),
            })
        }
        "mkdir" => {
            let path = req(args, 2)?;
            let mut store = Store::open_with_passphrase(dir, &pass)?;
            store.mkdir(&path)?;
            store.sync()?;
            Ok(ok())
        }
        "write" => {
            let path = req(args, 2)?;
            let src = req(args, 3)?;
            let data = std::fs::read(&src)?;
            let mut store = Store::open_with_passphrase(dir, &pass)?;
            store.create(&path)?;
            store.write_at(&path, 0, &data)?;
            store.sync()?;
            Ok(ok())
        }
        "read" => {
            let path = req(args, 2)?;
            let dest = req(args, 3)?;
            let store = Store::open_with_passphrase(dir, &pass)?;
            let data = store.read_all(&path)?;
            std::fs::write(&dest, data)?;
            Ok(ok())
        }
        "rm" => {
            let path = req(args, 2)?;
            let mut store = Store::open_with_passphrase(dir, &pass)?;
            store.remove(&path)?;
            store.sync()?;
            Ok(ok())
        }
        "mv" => {
            let old = req(args, 2)?;
            let new = req(args, 3)?;
            let mut store = Store::open_with_passphrase(dir, &pass)?;
            store.rename_path(&old, &new)?;
            store.sync()?;
            Ok(ok())
        }
        other => Err(format!("unknown command: {other}").into()),
    }
}

/// Recovery backups (see `cloak::backup`). The backup's password comes from
/// CLOAK_BACKUP_PASSPHRASE. Backing up needs each drive's own password too:
/// CLOAK_DRIVE_PASSPHRASES, a JSON list in the order the drives are given,
/// or CLOAK_PASSPHRASE for them all; restoring needs it in CLOAK_PASSPHRASE.
///
///   backup <out-file> <name> <drive-dir> [<name> <drive-dir> ...]
///   backup-list <file>              -> [{name, path, files}], plus created
///   restore <file> <name> <drive-dir> -> {restored, kept, skipped}
fn backup_command(cmd: &str, args: &[String]) -> Result<Option<String>, Box<dyn Error>> {
    use cloak::backup;
    use std::path::Path;
    let backup_pass = || env::var("CLOAK_BACKUP_PASSPHRASE").map_err(|_| "CLOAK_BACKUP_PASSPHRASE not set");
    Ok(Some(match cmd {
        "backup" => {
            let out = req(args, 1)?;
            let pairs = &args[2..];
            if pairs.is_empty() || pairs.len() % 2 != 0 {
                return Err("usage: cloak backup <out-file> <name> <drive-dir> [...]".into());
            }
            let passwords: Vec<String> = match env::var("CLOAK_DRIVE_PASSPHRASES") {
                Ok(list) => serde_json::from_str(&list).map_err(|e| format!("CLOAK_DRIVE_PASSPHRASES: {e}"))?,
                Err(_) => {
                    let one = env::var("CLOAK_PASSPHRASE").map_err(|_| "set CLOAK_DRIVE_PASSPHRASES or CLOAK_PASSPHRASE")?;
                    vec![one; pairs.len() / 2]
                }
            };
            if passwords.len() != pairs.len() / 2 {
                return Err("CLOAK_DRIVE_PASSPHRASES needs one password per drive".into());
            }
            let drives = pairs
                .chunks(2)
                .zip(&passwords)
                .map(|(p, pw)| backup::collect(&p[0], Path::new(&p[1]), pw))
                .collect::<Result<Vec<_>, _>>()?;
            let files: usize = drives.iter().map(|d| d.files.len()).sum();
            let count = drives.len();
            backup::write(Path::new(&out), &backup_pass()?, drives)?;
            serde_json::json!({ "ok": true, "drives": count, "files": files }).to_string()
        }
        "backup-list" => {
            let b = backup::read(Path::new(&req(args, 1)?), &backup_pass()?)?;
            let drives: Vec<_> = b
                .drives
                .iter()
                .map(|d| serde_json::json!({ "name": d.name, "path": d.path, "files": d.files.len() }))
                .collect();
            serde_json::json!({ "created": b.created, "drives": drives }).to_string()
        }
        "restore" => {
            let file = req(args, 1)?;
            let name = req(args, 2)?;
            let dir = req(args, 3)?;
            let pass = env::var("CLOAK_PASSPHRASE").map_err(|_| "CLOAK_PASSPHRASE not set")?;
            let b = backup::read(Path::new(&file), &backup_pass()?)?;
            let drive = b
                .drives
                .iter()
                .find(|d| d.name == name)
                .ok_or_else(|| format!("no drive called {name} in that backup"))?;
            serde_json::to_string(&backup::restore(Path::new(&dir), &pass, drive)?)?
        }
        _ => return Ok(None),
    }))
}

/// Print `{"progress": n, "total": t}` lines as work goes on (a line every
/// so often is plenty for a progress bar).
fn progress_lines() -> impl FnMut(u64, u64) {
    let mut shown = std::time::Instant::now();
    move |done: u64, total: u64| {
        if done == total || shown.elapsed() >= std::time::Duration::from_millis(200) {
            shown = std::time::Instant::now();
            println!("{}", serde_json::json!({ "progress": done, "total": total }));
        }
    }
}

fn ok() -> String {
    serde_json::json!({ "ok": true }).to_string()
}

fn arg(args: &[String], i: usize) -> String {
    args.get(i).cloned().unwrap_or_default()
}

fn req(args: &[String], i: usize) -> Result<String, Box<dyn Error>> {
    args.get(i).cloned().ok_or_else(|| format!("missing argument #{i}").into())
}
