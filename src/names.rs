//! Real-name handling that has to agree between Windows and macOS.
//!
//! A drive written on one OS must read identically on the other, so every
//! real name goes through the rules here:
//!
//! * **Unicode form.** macOS hands most names over decomposed (NFD: `e` +
//!   combining accent) while Windows uses composed (NFC: `é`). Names are stored
//!   NFC and compared NFC, so `café` from either side is the same file.
//! * **Case.** Both drives are case-insensitive and case-preserving, with full
//!   Unicode case folding (`Ä.txt` and `ä.txt` collide, as on NTFS and APFS).
//! * **Portability limits.** A name must be storable on both systems: no `/`
//!   or NUL (illegal everywhere), not `.`/`..`, and at most 255 UTF-8 bytes
//!   (the macOS/Linux limit, which also keeps it within Windows' 255 UTF-16
//!   units).
//! * **Windows-illegal characters.** macOS allows `" * : < > ? \ |`, control
//!   characters, trailing spaces/dots and device names like `CON`. The Windows
//!   adapter shows those through the Services-for-Macintosh mapping macOS's own
//!   SMB client uses (each character swapped for a private-use look-alike), so
//!   nothing is renamed on disk and the mapping round-trips exactly.

use std::io;
use unicode_normalization::UnicodeNormalization;

/// Longest name either OS accepts, in UTF-8 bytes (macOS/Linux `NAME_MAX`).
pub const MAX_NAME_BYTES: usize = 255;

/// The stored form of a name: Unicode NFC.
pub fn normalize(name: &str) -> String {
    name.nfc().collect()
}

/// Comparison key: NFC, then per-character simple uppercase. Two names that
/// collide on a case-insensitive Windows or macOS volume have equal keys. Like
/// NTFS's upcase table this maps one character to one (so `ς` and `σ` both
/// become `Σ`, and `ß` stays `ß` rather than expanding to `SS`).
pub fn fold(name: &str) -> String {
    name.nfc()
        .map(|c| {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

/// Do two names refer to the same entry on a case-insensitive volume?
pub fn same(a: &str, b: &str) -> bool {
    a == b || fold(a) == fold(b)
}

/// Reject a name that could not be created on both Windows and macOS.
/// Windows-only illegal characters are *not* rejected: they are mapped for
/// display by [`to_windows`] instead.
pub fn validate(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid name"));
    }
    if name.contains(['/', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidFilename,
            "name contains '/' or NUL",
        ));
    }
    if normalize(name).len() > MAX_NAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidFilename,
            "name longer than 255 bytes",
        ));
    }
    Ok(())
}

// ---- Windows display mapping (Services for Macintosh) ----------------------

/// Private-use base of the SFM range: control characters 0x01–0x1F map to
/// U+F001–U+F01F, and the punctuation below to U+F020–U+F029.
const SFM_BASE: u32 = 0xF000;
const SFM_PUNCT: [(char, u32); 8] = [
    ('"', 0xF020),
    ('*', 0xF021),
    (':', 0xF022),
    ('<', 0xF023),
    ('>', 0xF024),
    ('?', 0xF025),
    ('\\', 0xF026),
    ('|', 0xF027),
];
const SFM_TRAILING_SPACE: u32 = 0xF028;
const SFM_TRAILING_DOT: u32 = 0xF029;
/// cloak's own addition to the SFM range: marks a device-name stem (`CON`,
/// `aux`, `com1`…) so Windows doesn't treat the file as a device.
const DEVICE_MARK: char = '\u{F02A}';

fn sfm(c: char) -> Option<char> {
    let u = c as u32;
    if (0x01..=0x1F).contains(&u) {
        return char::from_u32(SFM_BASE + u);
    }
    SFM_PUNCT
        .iter()
        .find(|(p, _)| *p == c)
        .and_then(|(_, m)| char::from_u32(*m))
}

fn unsfm(c: char) -> Option<char> {
    let u = c as u32;
    if (SFM_BASE + 0x01..=SFM_BASE + 0x1F).contains(&u) {
        return char::from_u32(u - SFM_BASE);
    }
    match u {
        SFM_TRAILING_SPACE => Some(' '),
        SFM_TRAILING_DOT => Some('.'),
        _ => SFM_PUNCT.iter().find(|(_, m)| *m == u).map(|(p, _)| *p),
    }
}

/// Is `stem` (the part before the first `.`) a Windows device name?
fn is_device_stem(stem: &str) -> bool {
    let s = stem.trim_end_matches(' ').to_ascii_uppercase();
    matches!(s.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((s.starts_with("COM") || s.starts_with("LPT"))
            && s.len() == 4
            && matches!(s.as_bytes()[3], b'0'..=b'9'))
        || ((s.starts_with("COM") || s.starts_with("LPT"))
            && matches!(&s[3..], "¹" | "²" | "³"))
}

/// The name as a Windows volume shows it. Identity for any name that is
/// already legal on Windows.
pub fn to_windows(name: &str) -> String {
    let mut out: String = name.chars().map(|c| sfm(c).unwrap_or(c)).collect();
    // A trailing space or dot is silently stripped by Win32, so map the last one.
    match out.chars().last() {
        Some(' ') => {
            out.pop();
            out.push(char::from_u32(SFM_TRAILING_SPACE).unwrap());
        }
        Some('.') if name != "." && name != ".." => {
            out.pop();
            out.push(char::from_u32(SFM_TRAILING_DOT).unwrap());
        }
        _ => {}
    }
    let stem_len = out.find('.').unwrap_or(out.len());
    if is_device_stem(&out[..stem_len]) {
        out.insert(stem_len, DEVICE_MARK);
    }
    out
}

/// Inverse of [`to_windows`]: the stored name for a name Windows passed in.
pub fn from_windows(name: &str) -> String {
    name.chars()
        .filter(|&c| c != DEVICE_MARK)
        .map(|c| unsfm(c).unwrap_or(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfd_and_nfc_are_the_same_name() {
        let nfc = "caf\u{e9}.txt";
        let nfd = "cafe\u{301}.txt";
        assert_ne!(nfc, nfd);
        assert!(same(nfc, nfd));
        assert_eq!(normalize(nfd), nfc);
    }

    #[test]
    fn unicode_case_folding() {
        assert!(same("Ä.TXT", "ä.txt"));
        assert!(same("ΣΊΣΥΦΟΣ", "σίσυφος"));
        assert!(same("Report.PDF", "report.pdf"));
        assert!(!same("a.txt", "b.txt"));
    }

    #[test]
    fn validate_limits() {
        assert!(validate("ok name.txt").is_ok());
        assert!(validate("Meeting 10:30?.txt").is_ok()); // mapped on Windows, not rejected
        assert!(validate("").is_err());
        assert!(validate("..").is_err());
        assert!(validate("a/b").is_err());
        assert!(validate("a\0b").is_err());
        assert!(validate(&"x".repeat(255)).is_ok());
        assert!(validate(&"x".repeat(256)).is_err());
        // 100 CJK chars = 300 UTF-8 bytes: fine on Windows, too long for macOS.
        assert!(validate(&"漢".repeat(100)).is_err());
        assert!(validate(&"漢".repeat(85)).is_ok());
    }

    #[test]
    fn windows_mapping_round_trips() {
        for name in [
            "plain.txt",
            "Meeting 10:30.txt",
            r#"a"b*c:d<e>f?g\h|i"#,
            "tab\there",
            "trailing space ",
            "trailing dot.",
            "CON",
            "con.txt",
            "Aux.tar.gz",
            "COM1",
            "lpt9.log",
            "CONSOLE.txt", // not a device
            "COM10",       // not a device
        ] {
            let w = to_windows(name);
            assert_eq!(from_windows(&w), name, "round trip of {name:?} via {w:?}");
        }
    }

    #[test]
    fn windows_mapping_only_touches_illegal_names() {
        assert_eq!(to_windows("plain.txt"), "plain.txt");
        assert_eq!(to_windows("CONSOLE.txt"), "CONSOLE.txt");
        assert_eq!(to_windows("dots.in.middle"), "dots.in.middle");
        assert_eq!(to_windows("10:30"), "10\u{F022}30");
        assert_eq!(to_windows("end."), "end\u{F029}");
        assert_eq!(to_windows("con.txt"), "con\u{F02A}.txt");
        let w = to_windows(r#"a"b*c:d<e>f?g\h|i "#);
        assert!(!w.contains(['"', '*', ':', '<', '>', '?', '\\', '|']));
        assert!(!w.ends_with(' '));
    }
}
