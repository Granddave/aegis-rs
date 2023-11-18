use color_eyre::eyre::{eyre, Result};
use dialoguer::{theme::ColorfulTheme, Password};
use serde::Deserialize;
use std::io;
use std::{env, fs, path::PathBuf};

/// Cryptographic functions and data structures used to decrypt database with TOTP entries
///
/// The official Aegis documentation for vault decryption and contents can be found
/// [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md#aegis-vault).
mod crypto;

/// Module for generating TOTP codes
///
/// The official Aegis documentation for code generation can be found
/// [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md#entries).
pub mod totp;

/// Database containing TOTP entries
#[derive(Debug, Deserialize)]
pub struct Database {
    /// Database version
    version: u32,
    /// List of TOTP entries
    pub entries: Vec<Entry>,
}

/// TOTP entry with information used to generate one time codes
#[derive(Debug, Deserialize)]
pub struct Entry {
    pub r#type: totp::EntryType,
    // pub uuid: String,
    pub name: String,
    pub issuer: String,
    // pub note: String,
    // pub favorite: bool,
    // pub icon: String,
    pub info: totp::EntryInfo,
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
    version: u32,
    /// Information to decrypt master key
    header: crypto::Header,
    db: VaultDatabase,
}

/// Parse vault from JSON. A list of entries are returned.
pub fn parse_aegis_vault(vault_backup_contents: &str) -> Result<Vec<Entry>> {
    let vault: Vault = serde_json::from_str(vault_backup_contents)?;
    if vault.version != 1 {
        return Err(eyre!(format!(
            "Unsupported vault version: {}",
            vault.version
        )));
    }
    let db = match vault.db {
        VaultDatabase::Plain(db) => Ok(db),
        VaultDatabase::Encrypted(_) => crypto::decrypt(get_password()?.as_str(), vault),
    }?;
    if db.version != 2 {
        return Err(eyre!(format!(
            "Unsupported database version: {}",
            db.version
        )));
    }

    Ok(db.entries)
}

/// Get password from user
fn get_password() -> io::Result<String> {
    // TODO: Refactor out password filepath
    let home = env::var("HOME").expect("Failed to expand $HOME");
    let password_filepath = PathBuf::from(home).join(".config/aegis-pass.txt");

    if fs::metadata(&password_filepath).is_ok() {
        println!("Found password file");
        let password = fs::read_to_string(&password_filepath)?;
        return Ok(password.trim().to_string());
    } else {
        return Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Insert Aegis Password")
            .interact();
    }
}
