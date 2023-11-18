use color_eyre::eyre::{eyre, Result};
use serde::Deserialize;

use crate::{crypto, Entry};

/// Database containing TOTP entries
#[derive(Debug, Deserialize)]
pub struct Database {
    /// Database version
    version: u32,
    /// List of TOTP entries
    pub entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VaultDatabase {
    /// Database in plain text
    Plain(Database),
    /// Base64 decoded AES265 encrypted JSON
    Encrypted(String),
}

/// Encrypted Aegis vault backup
#[derive(Debug, Deserialize)]
pub struct Vault {
    /// Backup version
    pub version: u32,
    /// Information to decrypt master key
    pub header: crypto::Header,
    pub db: VaultDatabase,
}

impl Vault {
    /// Parse vault from JSON. A list of entries are returned.
    /// password_fn is a function that returns the password used to decrypt the vault.
    pub fn parse(
        vault_backup_contents: &str,
        password_fn: fn() -> Result<String>,
    ) -> Result<Vec<Entry>> {
        let vault: Vault = serde_json::from_str(vault_backup_contents)?;
        if vault.version != 1 {
            return Err(eyre!(format!(
                "Unsupported vault version: {}",
                vault.version
            )));
        }
        let db = match vault.db {
            VaultDatabase::Plain(db) => Ok(db),
            VaultDatabase::Encrypted(_) => crypto::decrypt(password_fn()?.as_str(), vault),
        }?;
        if db.version != 2 {
            return Err(eyre!(format!(
                "Unsupported database version: {}",
                db.version
            )));
        }

        Ok(db.entries)
    }
}
