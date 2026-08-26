//! Utility crate for interacting and generating OTP codes from a backup vault from the Android app
//! [Aegis Authenticator](https://github.com/beemdevelopment/Aegis).
//!
//! # Example
//! ```no_run
//! use aegis_rs::{
//!     otp::generate_otp,
//!     vault::{parse_vault, PasswordGetter},
//! };
//! use color_eyre::eyre::Result;
//!
//! // Implement the PasswordGetter trait to get the password from the environment
//! struct EnvPasswordGetter;
//! impl PasswordGetter for EnvPasswordGetter {
//!     fn get_password(&self) -> Result<String> {
//!         Ok("test".to_string())
//!     }
//! }
//!
//! fn main() -> Result<()> {
//!     // Read and parse the vault
//!     let vault_backup_contents = std::fs::read_to_string("res/aegis_encrypted.json")?;
//!     let db = parse_vault(&vault_backup_contents, &EnvPasswordGetter)?;
//!
//!     // Get the first entry and generate the OTP code
//!     let entry = db.entries.iter().next().unwrap();
//!     let otp = generate_otp(&entry.info)?;
//!
//!     // Print e.g.: "Deno (Mason): 591295"
//!     println!("{} ({}): {}", entry.issuer, entry.name, otp);
//!
//!     Ok(())
//! }
//! ```

/// The [vault][`vault::Vault`] is parsed from a JSON file exported from the Aegis app containing
/// [database][`vault::Database`] of OTP entries. The database inside the vault can be either
/// [plain text or encrypted][`vault::VaultDatabase`].
///
/// To decrypt the vault, a [`PasswordGetter`][`vault::PasswordGetter`] trait is used to get the
/// password and the [`parse_vault`][`vault::parse_vault`] function is used to parse the vault.
///
/// Example:
/// ```no_run
// NOTE: Enable the test once all vault versions are supported
/// # use aegis_rs::vault::{parse_vault, PasswordGetter};
/// # use color_eyre::eyre::Result;
/// struct EnvPasswordGetter;
/// impl PasswordGetter for EnvPasswordGetter {
///     fn get_password(&self) -> Result<String> {
///         Ok("test".to_string())
///     }
/// }
///
/// # fn main() -> Result<()> {
/// let vault_backup_contents = std::fs::read_to_string("res/aegis_encrypted.json")?;
/// let db = parse_vault(&vault_backup_contents, &EnvPasswordGetter)?;
/// db.entries.iter().for_each(|entry| {
///     println!("{:?}: {:?}", entry.name, entry.issuer);
/// });
/// # Ok(())
/// # }
/// ```
pub mod vault;

/// Module for generating OTP (One Time Pad) codes
///
/// The official Aegis documentation for code generation can be found
/// [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md#entries).
///
/// Example:
/// ```rust
/// # use aegis_rs::otp::{generate_otp, Entry, EntryInfo, EntryInfoTotp, HashAlgorithm};
/// # use color_eyre::eyre::Result;
/// # fn main() -> Result<()> {
/// // Example entry from the vault
/// let entry = Entry {
///     info: EntryInfo::Totp(EntryInfoTotp {
///         secret: "4SJHB4GSD43FZBAI7C2HLRJGPQ".to_string(),
///         algo: HashAlgorithm::Sha1,
///         digits: 6,
///         period: 30,
///     }),
///     name: "Mason".to_string(),
///     issuer: "Deno".to_string(),
/// };
///
/// // Generate the OTP code
/// let otp = generate_otp(&entry.info)?;
///
/// // Print e.g.: "Deno (Mason): 591295"
/// println!("{} ({}): {}", entry.issuer, entry.name, otp);
/// # Ok(())
/// # }
/// ```
pub mod otp;
