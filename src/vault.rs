use color_eyre::eyre::{eyre, Result};
use serde::Deserialize;

use crate::otp;

/// Cryptographic functions and data structures used to decrypt database with OTP entries
///
/// The official Aegis documentation for vault decryption and contents can be found
/// [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md#aegis-vault).
mod crypto;

/// Database containing the user data
#[derive(Debug, Deserialize)]
pub struct Database {
    /// Database version
    pub version: u32,
    /// List of OTP entries
    pub entries: Vec<otp::Entry>,
}

/// Vault database as found in the JSON vault backup file. It can be either plain text or encrypted.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VaultDatabase {
    /// Database in plain text
    Plain(Database),
    /// Base64 decoded AES265 encrypted JSON
    Encrypted(String),
}

/// Trait for getting the password from the user or from the environment.
///
pub trait PasswordGetter {
    /// Get the password from the user or from the environment used to decrypt the vault
    /// with [`parse_vault`].
    fn get_password(&self) -> Result<String>;
}

/// Aegis vault backup file contents
#[derive(Debug, Deserialize)]
pub struct Vault {
    /// Backup version
    pub version: u32,
    /// Information to decrypt master key
    pub header: crypto::Header,
    /// Entry database in plain text or encrypted
    pub db: VaultDatabase,
}

/// Parse vault from JSON as found in the vault backup file
///
/// # Arguments
/// - `vault_backup_contents` - JSON string containing vault backup, encrypted or not
/// - `password_getter` - Password getter implementation. Used to get the password to decrypt the vault.
///
/// Required even if the vault is not encrypted.
///
/// # Returns
/// - `Result` containing the parsed [database][`Database`]
pub fn parse_vault(
    vault_backup_contents: &str,
    password_getter: &impl PasswordGetter,
) -> Result<Database> {
    let vault: Vault = serde_json::from_str(vault_backup_contents)?;
    if vault.version != 1 {
        return Err(eyre!(format!(
            "Unsupported vault version: {}",
            vault.version
        )));
    }
    let db = match vault.db {
        VaultDatabase::Plain(db) => db,
        VaultDatabase::Encrypted(_) => {
            let password = password_getter.get_password()?;
            let json = crypto::decrypt_database(&password, vault)?;
            let db: Database = serde_json::from_str(&json)?;
            db
        }
    };

    // The models are delevoped for the version 2 of the database
    // but the changes have after version 2 are not significant
    // so we can still use the same models.
    if db.version > 3 {
        return Err(eyre!(format!(
            "Unsupported database version: {}",
            db.version
        )));
    }

    Ok(db)
}
