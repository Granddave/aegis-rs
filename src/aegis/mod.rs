use color_eyre::eyre::{eyre, Result};
use dialoguer::{theme::ColorfulTheme, Password};
use serde::Deserialize;
use std::io::Read;
use std::{env, fs, path::PathBuf};
use std::{fs::File, io};

/// Cryptographic functions and data structures used to decrypt database with TOTP entries
mod crypto;
/// Module for generating TOTP codes
pub mod totp;

/// Database containing TOTP entries
#[derive(Debug, Deserialize)]
pub struct Database {
    version: u32,
    pub entries: Vec<Entry>,
}

/// TOTP entry with information used to generate one time codes
#[derive(Debug, Deserialize)]
pub struct Entry {
    pub r#type: totp::EntryTypes,
    // pub uuid: String,
    pub name: String,
    pub issuer: String,
    // pub note: String,
    // pub favorite: bool,
    // pub icon: String,
    pub info: totp::EntryInfo,
}

/// Aegis backup in JSON
#[derive(Debug, Deserialize)]
pub struct AegisBackup {
    /// Backup version
    version: u32,
    /// Information to decrypt master key
    header: crypto::Header,
    /// Base64 decoded AES265 encrypted JSON
    db: String,
}

/// Parse database from JSON file. A list of entries are returned.
pub fn parse_aegis_backup_file(path: &str) -> Result<Vec<Entry>> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let aegis_backup: AegisBackup = serde_json::from_str(&contents)?;

    if aegis_backup.version != 1 {
        return Err(eyre!(format!(
            "Unsupported vault version: {}",
            aegis_backup.version
        )));
    }

    // TODO: Allow plaintext backup
    let password = get_password()?;
    let db = crypto::decrypt(password.as_str(), aegis_backup); // TODO: Return a result

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
    // TODO: Break out
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
