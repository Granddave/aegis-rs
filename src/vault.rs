use color_eyre::eyre::{eyre, Result};
use serde::Deserialize;

use crate::otp;

/// Cryptographic functions and data structures used to decrypt database with OTP entries
///
/// The official Aegis documentation for vault decryption and contents can be found
/// [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md#aegis-vault).
mod crypto;

/// Database containing OTP entries
#[derive(Debug, Deserialize)]
pub struct Database {
    /// Database version
    version: u32,
    /// List of OTP entries
    pub entries: Vec<otp::Entry>,
}

/// Vault database as found in the JSON file
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VaultDatabase {
    /// Database in plain text
    Plain(Database),
    /// Base64 decoded AES265 encrypted JSON
    Encrypted(String),
}

pub trait PasswordGetter {
    /// Get the password from the user or from the environment
    fn get_password(&self) -> Result<String>;
}

/// Aegis vault backup
#[derive(Debug, Deserialize)]
pub struct Vault {
    /// Backup version
    pub version: u32,
    /// Information to decrypt master key
    pub header: crypto::Header,
    pub db: VaultDatabase,
}

/// Parse vault from JSON. A list of entries are returned.
pub fn parse_vault(
    vault_backup_contents: &str,
    password_getter: impl PasswordGetter,
) -> Result<Vec<otp::Entry>> {
    let vault: Vault = serde_json::from_str(vault_backup_contents)?;
    if vault.version != 1 {
        return Err(eyre!(format!(
            "Unsupported vault version: {}",
            vault.version
        )));
    }
    let db = match vault.db {
        VaultDatabase::Plain(db) => Ok(db),
        VaultDatabase::Encrypted(_) => {
            let password = password_getter.get_password()?;
            crypto::decrypt(&password, vault)
        }
    }?;
    if db.version != 2 {
        return Err(eyre!(format!(
            "Unsupported database version: {}",
            db.version
        )));
    }

    Ok(db.entries)
}
