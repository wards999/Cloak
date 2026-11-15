//! Password-key derivation.
//!
//! A drive's master key is random and kept only locked (see `lock.rs`): sealed
//! under a key derived from the password with Argon2id (memory-hard, the
//! current standard for password hashing) and a random, non-secret salt that
//! each lock carries. Argon2id is what makes each password guess expensive.
//!
//! The Argon2id settings are fixed here, never taken from the library's
//! defaults: they can't be stored with a drive (they're needed before
//! anything opens), so if they changed in an update, every existing drive
//! would derive a different key and refuse its password.

use crate::crypto::{Key, KEY_LEN};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::io;

pub const SALT_LEN: usize = 16;
pub type Salt = [u8; SALT_LEN];

/// Argon2id settings: memory in KiB, passes, lanes. argon2 0.5's defaults,
/// which every drive and backup so far was made with. Never change these.
const M_COST: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

/// A fresh random salt for a brand-new lock or backup.
pub fn random_salt() -> Salt {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive the 32-byte key for a password and salt.
pub fn derive_key(passphrase: &str, salt: &Salt) -> io::Result<Key> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(KEY_LEN)).map_err(|e| io::Error::other(e.to_string()))?;
    let mut key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive(passphrase: &str, salt: &Salt) -> Key {
        derive_key(passphrase, salt).unwrap()
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
    fn the_settings_give_the_original_key() {
        assert_eq!(
            hex(&derive("hunter2", &[5u8; SALT_LEN])),
            "b0ce1e19481ac46dd84f0c7b471fc8b6c5544537a89dab65fbc300a3c6acf522"
        );
    }
}
