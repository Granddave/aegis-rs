/// Cryptographic functions and data structures used to decrypt database with OTP entries
///
/// The official Aegis documentation for vault decryption and contents can be found
/// [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md#aegis-vault).
mod crypto;

/// Module for generating OTP (One Time Pad) codes
///
/// The official Aegis documentation for code generation can be found
/// [here](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md#entries).
pub mod otp;

/// Aegis vault backup data structures and parsing
pub mod vault;
