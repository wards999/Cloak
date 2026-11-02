//! `cloak` — a headless command bridge over the engine, for the GUI to call.
//!
//! Every command takes the drive folder as the first argument and the password
//! from the `CLOAK_PASSPHRASE` environment variable (kept off argv). Output is a
//! single line of JSON on stdout; on error it prints `{"error": "..."}` and
//! exits non-zero.
//!
//!   cloak create <dir>                 create a new drive
//!   cloak open   <dir>                 verify the password opens the drive
//!   cloak ls     <dir> <path>          list a directory -> [{name,is_dir,size}]
//!   cloak stat   <dir> <path>          -> {exists,is_dir,size}
//!   cloak mkdir  <dir> <path>          make a folder
//!   cloak write  <dir> <path> <src>    import a real file into the drive
//!   cloak read   <dir> <path> <dest>   extract a file out to disk
//!   cloak rm     <dir> <path>          delete a file or folder
//!   cloak mv     <dir> <old> <new>     rename / move

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
    let dir = args.get(1).ok_or("missing <dir>")?;
    let pass = env::var("CLOAK_PASSPHRASE").map_err(|_| "CLOAK_PASSPHRASE not set")?;

    match cmd {
        "create" => {
            Store::create_with_passphrase(dir, &pass, REGION)?;
            Ok(ok())
        }
        "open" => {
            Store::open_with_passphrase(dir, &pass)?;
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

fn ok() -> String {
    serde_json::json!({ "ok": true }).to_string()
}

fn arg(args: &[String], i: usize) -> String {
    args.get(i).cloned().unwrap_or_default()
}

fn req(args: &[String], i: usize) -> Result<String, Box<dyn Error>> {
    args.get(i).cloned().ok_or_else(|| format!("missing argument #{i}").into())
}
