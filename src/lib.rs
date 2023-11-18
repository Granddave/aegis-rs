use serde::Deserialize;

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

/// Aegis vault backup data structures and parsing
pub mod vault;

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
