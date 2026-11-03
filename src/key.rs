//! Master-key derivation.
//!
//! The master key is never stored. It's derived from a passphrase with Argon2id
//! (memory-hard, the current standard for password hashing) plus a random,
//! non-secret salt kept in the store's `meta.json`. Same passphrase + same salt
//! + same settings => same key. `meta.json` also holds a verifier (see
//! `engine.rs`) so a wrong passphrase is reported as such; Argon2id is what
//! makes each guess against it expensive.
//!
//! The Argon2id settings are pinned here and recorded with each drive, never
//! taken from the library's defaults: if those changed in an update, every
//! existing drive would derive a different key and refuse its password.

use crate::crypto::{Key, KEY_LEN};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io;

pub const SALT_LEN: usize = 16;
pub type Salt = [u8; SALT_LEN];

/// Argon2id (version 1.3) settings a key is derived with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory, in KiB.
    pub m_cost: u32,
    /// Passes over the memory.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl KdfParams {
    /// What every drive (and version-1 backup) made before the settings were
    /// recorded used: argon2 0.5's defaults. Never change these.
    pub const ORIGINAL: KdfParams = KdfParams { m_cost: 19 * 1024, t_cost: 2, p_cost: 1 };

    /// Settings for new drives. Raising them is safe: each drive records its own.
    pub const CURRENT: KdfParams = KdfParams::ORIGINAL;

    /// Upper bounds for settings read from a drive, so a damaged or hostile
    /// `meta.json` can't make an unlock exhaust memory or run for hours.
    const MAX_M_COST: u32 = 4 * 1024 * 1024; // 4 GiB
    const MAX_T_COST: u32 = 64;
    const MAX_P_COST: u32 = 64;
}

/// A drive without recorded settings was made with the original ones.
impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::ORIGINAL
    }
}

/// A fresh random salt for a brand-new store.
pub fn random_salt() -> Salt {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive the 32-byte master key from a passphrase, the store's salt and its
/// Argon2id settings. `InvalidData` if the settings are out of range.
pub fn derive_key(passphrase: &str, salt: &Salt, params: &KdfParams) -> io::Result<Key> {
    let invalid = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
    if params.m_cost > KdfParams::MAX_M_COST
        || params.t_cost > KdfParams::MAX_T_COST
        || params.p_cost > KdfParams::MAX_P_COST
    {
        return Err(invalid(format!("password settings out of range: {params:?}")));
    }
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| invalid(format!("password settings not usable ({e}): {params:?}")))?;
    let mut key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| invalid(format!("password settings not usable ({e}): {params:?}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive(passphrase: &str, salt: &Salt) -> Key {
        derive_key(passphrase, salt, &KdfParams::ORIGINAL).unwrap()
    }

    fn hex(key: &Key) -> String {
        key.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn same_inputs_same_key() {
        let salt = [5u8; SALT_LEN];
        assert_eq!(derive("hunter2", &salt), derive("hunter2", &salt));
    }

    #[test]
    fn different_passphrase_differs() {
        let salt = [5u8; SALT_LEN];
        assert_ne!(derive("hunter2", &salt), derive("hunter3", &salt));
    }

    #[test]
    fn different_salt_differs() {
        assert_ne!(derive("hunter2", &[1u8; SALT_LEN]), derive("hunter2", &[2u8; SALT_LEN]));
    }

    /// The key existing drives were made with, captured from argon2 0.5.3's
    /// `Argon2::default()`. If this fails, drives made so far won't open.
    #[test]
    fn original_settings_give_the_original_key() {
        assert_eq!(
            hex(&derive("hunter2", &[5u8; SALT_LEN])),
            "b0ce1e19481ac46dd84f0c7b471fc8b6c5544537a89dab65fbc300a3c6acf522"
        );
    }

    #[test]
    fn settings_change_the_key() {
        let salt = [5u8; SALT_LEN];
        let heavier = KdfParams { t_cost: 3, ..KdfParams::ORIGINAL };
        assert_ne!(derive_key("hunter2", &salt, &heavier).unwrap(), derive("hunter2", &salt));
    }

    #[test]
    fn out_of_range_settings_are_refused() {
        let salt = [5u8; SALT_LEN];
        for bad in [
            KdfParams { m_cost: u32::MAX, ..KdfParams::ORIGINAL },
            KdfParams { t_cost: 0, ..KdfParams::ORIGINAL },
            KdfParams { p_cost: 0, ..KdfParams::ORIGINAL },
            KdfParams { t_cost: 1000, ..KdfParams::ORIGINAL },
        ] {
            let err = derive_key("hunter2", &salt, &bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{bad:?}");
        }
    }
}
