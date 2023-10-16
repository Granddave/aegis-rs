use super::{Database, Vault};
use aes_gcm::{aead::AeadMut, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use color_eyre::eyre::{eyre, Result};
use hex::FromHex;
use password_hash::Output;
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};
use serde::Deserialize;
use serde_repr::Deserialize_repr;

/// AES-GCM encryption parameters
#[derive(Debug, Deserialize)]
struct KeyParams {
    nonce: String,
    tag: String,
}

/// Master key decryption slot types supported by Aegis
#[derive(Debug, Deserialize_repr, PartialEq)]
#[repr(u8)]
enum SlotType {
    Raw = 0,
    Password = 1,
    Biometric = 2,
}

/// Master key decryption slot. The master key is encrypted with a key derived from the password.
/// The key derivation parameters are stored in the slot.
#[derive(Debug, Deserialize)]
struct Slot {
    r#type: SlotType,
    // uuid: String,
    key: String,
    key_params: KeyParams,
    n: Option<i32>,
    r: Option<i32>,
    p: Option<i32>,
    salt: Option<String>,
    // repaired: Option<bool>,
    // is_backup: Option<bool>,
}

/// Database encryption header
#[derive(Debug, Deserialize)]
pub struct Header {
    /// List of master key decryption slots
    slots: Option<Vec<Slot>>,
    /// Master key encryption parameters
    params: Option<KeyParams>,
}

impl Header {
    /// The fields in the encryption header will not be set if the database in the vault is in
    /// plain text.
    pub fn is_set(&self) -> bool {
        self.slots.is_some() && self.params.is_some()
    }
}

enum DecryptionError {
    IncorrectPassword,
    ParamError(String),
}

/// Derive master key from password
fn derive_key(password: &[u8], slot: &Slot) -> Result<Output> {
    let salt_hex = slot.salt.as_ref().ok_or(eyre!("Salt is unavailable"))?;
    let salt_bytes =
        Vec::from_hex(salt_hex).map_err(|e| eyre!("Failed to decode salt hex: {}", e))?;
    let salt = SaltString::encode_b64(&salt_bytes)?;

    let n = (slot.n.ok_or(eyre!("n parameter unavailable"))? as f32).log2() as u8;
    let r = slot.r.ok_or(eyre!("r parameter unavailable"))? as u32;
    let p = slot.p.ok_or(eyre!("p parameter unavailable"))? as u32;

    let scrypt_params = scrypt::Params::new(n, r, p, 32)?;
    let derived_key =
        Scrypt.hash_password_customized(password, None, None, scrypt_params, &salt)?;

    derived_key
        .hash
        .ok_or(eyre!("Failed to get hash of derived key"))
}

fn decrypt_master_key(password: &str, slot: &Slot) -> Result<Vec<u8>, DecryptionError> {
    let derived_key = derive_key(password.as_bytes(), slot)
        .map_err(|e| DecryptionError::ParamError(format!("Failed to derive key: {}", e)))?;

    let key_nonce = Vec::from_hex(&slot.key_params.nonce)
        .map_err(|_| DecryptionError::ParamError("Failed to decode nonce".to_string()))?;

    let mut master_key_cipher = Vec::from_hex(&slot.key)
        .map_err(|_| DecryptionError::ParamError("Failed to decode master key cipher".to_string()))?
        .to_vec();
    master_key_cipher.extend_from_slice(
        &Vec::from_hex(&slot.key_params.tag)
            .map_err(|_| DecryptionError::ParamError("Failed to decode tag".to_string()))?,
    );

    // Decrypt master key
    let mut cipher = Aes256Gcm::new(derived_key.as_bytes().into());
    cipher
        .decrypt(Nonce::from_slice(&key_nonce), master_key_cipher.as_ref())
        .map_err(|_| DecryptionError::IncorrectPassword)
}

fn try_decrypt_master_key(password: &str, slots: &[Slot]) -> Result<Vec<u8>> {
    // Only password based master key decryptions are supported
    for slot in slots
        .iter()
        .filter(|s| s.r#type == SlotType::Password)
        .collect::<Vec<&Slot>>()
    {
        let master_key = match decrypt_master_key(password, slot) {
            Ok(key) => key,
            Err(DecryptionError::IncorrectPassword) => {
                eprintln!("Incorrect password");
                continue;
            }
            Err(DecryptionError::ParamError(e)) => {
                eprintln!("{}", e);
                continue;
            }
        };

        return Ok(master_key);
    }

    Err(eyre!("Failed to decrypt master key"))
}

fn decrypt_database(params: &KeyParams, master_key: &Vec<u8>, db: &String) -> Result<Database> {
    let db_nonce = Vec::from_hex(&params.nonce)?;
    let db_tag = Vec::from_hex(&params.tag)?;
    let db_contents_cipher = general_purpose::STANDARD.decode(db)?;

    let mut aes_context = Aes256Gcm::new(master_key.as_slice().into());
    let mut db_cipher: Vec<u8> = db_contents_cipher;
    db_cipher.extend_from_slice(&db_tag);

    let db_contents = aes_context
        .decrypt(Nonce::from_slice(&db_nonce), db_cipher.as_ref())
        .map_err(|e| eyre!("Failed to decrypt database: {}", e))?;
    let db_contents_str = String::from_utf8(db_contents)?;
    let db: Database = serde_json::from_str(&db_contents_str)?;

    Ok(db)
}

pub fn decrypt(password: &str, vault: Vault) -> Result<Database> {
    let slots = vault
        .header
        .slots
        .ok_or(eyre!("Vault header slots are unavailable"))?;
    let params = vault
        .header
        .params
        .ok_or(eyre!("Vault header parameters are unavailable"))?;

    let master_key = try_decrypt_master_key(password, &slots)?;

    decrypt_database(&params, &master_key, &vault.db)
}
