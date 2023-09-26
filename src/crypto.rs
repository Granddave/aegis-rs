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

#[derive(Debug, Deserialize)]
struct KeyParams {
    nonce: String,
    tag: String,
}

#[derive(Debug, Deserialize_repr, PartialEq)]
#[repr(u8)]
enum SlotType {
    Raw = 0,
    Password = 1,
    Biometric = 2,
}

/// Information for decrypting the master key
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

/// Information about the database encryption
#[derive(Debug, Deserialize)]
pub struct Header {
    /// Master key decryption slots
    slots: Option<Vec<Slot>>,
    /// AES encryption parameters for the database
    params: Option<KeyParams>,
}

impl Header {
    /// The fields in the encryption header will not be set if the database in the vault is
    /// in plain text.
    pub fn is_set(&self) -> bool {
        self.slots.is_some() && self.params.is_some()
    }
}

/// Derive master key from password and return Output or KeyDecryptionError
fn derive_key(password: &[u8], slot: &Slot) -> Result<Output> {
    let salt_hex = slot.salt.as_ref().ok_or(eyre!("Salt is unavailable"))?;
    let salt_bytes = Vec::from_hex(salt_hex).map_err(|e| eyre!("Failed to decode hex: {}", e))?;
    let salt = SaltString::from_b64(&general_purpose::STANDARD_NO_PAD.encode(salt_bytes))
        .map_err(|e| eyre!("Failed to decode base64: {}", e))?;

    let n = (slot.n.ok_or(eyre!("n parameter missing"))? as f32).log2() as u8;
    let r = slot.r.ok_or(eyre!("r parameter missing"))? as u32;
    let p = slot.p.ok_or(eyre!("p parameter missing"))? as u32;

    let scrypt_params = scrypt::Params::new(n, r, p, 32)?;
    let derived_key = Scrypt
        .hash_password_customized(password, None, None, scrypt_params, &salt)
        .map_err(|e| eyre!("Failed to derive key: {}", e))?;

    derived_key
        .hash
        .ok_or(eyre!("Failed to get hash of derived key"))
}

fn decrypt_master_key(password: &str, slot: &Slot) -> Result<Vec<u8>> {
    // Derive a key from the provided password and the salt from the file
    let derived_key = derive_key(password.as_bytes(), slot)?;
    let key_nonce = match Vec::from_hex(&slot.key_params.nonce) {
        Ok(nonce) => nonce,
        Err(_) => return Err(eyre!("Failed to decode nonce")),
    };

    let mut master_key_cipher = match Vec::from_hex(&slot.key) {
        Ok(cipher) => cipher,
        Err(_) => return Err(eyre!("Failed to decode master key cipher")),
    }
    .to_vec();
    master_key_cipher.extend_from_slice(match &Vec::from_hex(&slot.key_params.tag) {
        Ok(tag) => tag,
        Err(_) => return Err(eyre!("Failed to decode tag")),
    });

    // Decrypt master key
    let mut cipher = Aes256Gcm::new(derived_key.as_bytes().into());
    match cipher.decrypt(Nonce::from_slice(&key_nonce), master_key_cipher.as_ref()) {
        Ok(master_key) => return Ok(master_key),
        Err(_) => return Err(eyre!("Failed to decrypt master key")),
    }
}

fn try_decrypt_master_key(password: &str, slots: &[Slot]) -> Result<Vec<u8>> {
    // Only password based master key decryptions are supported
    for slot in slots
        .iter()
        .filter(|s| s.r#type == SlotType::Password)
        .collect::<Vec<&Slot>>()
    {
        let master_key = decrypt_master_key(password, slot)?;
        // Ok(key) => key,
        // Err(_) => {
        //     println!("Incorrect password");
        //     continue;
        // }
        // };

        return Ok(master_key);
    }

    Err(eyre!("No matching decryption slot found"))
}

fn decrypt_database(params: &KeyParams, master_key: &Vec<u8>, db: &String) -> Result<Database> {
    let db_nonce = match Vec::from_hex(&params.nonce) {
        Ok(nonce) => nonce,
        Err(_) => return Err(eyre!("Failed to decode nonce")),
    };
    let db_tag = match Vec::from_hex(&params.tag) {
        Ok(tag) => tag,
        Err(_) => return Err(eyre!("Failed to decode tag")),
    };
    let db_contents_cipher = match general_purpose::STANDARD.decode(db) {
        Ok(cipher) => cipher,
        Err(_) => return Err(eyre!("Failed to decode database")),
    };

    let mut cipher_db = Aes256Gcm::new(master_key.as_slice().into());
    let mut db_cipher: Vec<u8> = db_contents_cipher;
    db_cipher.extend_from_slice(&db_tag);

    let db_contents = match cipher_db.decrypt(Nonce::from_slice(&db_nonce), db_cipher.as_ref()) {
        Ok(contents) => contents,
        Err(_) => return Err(eyre!("Failed to decrypt database")),
    };

    let db_contents_str = String::from_utf8(db_contents)?;
    let db: Database = serde_json::from_str(&db_contents_str)?;

    Ok(db)
}

pub fn decrypt(password: &str, vault: Vault) -> Result<Database> {
    let slots = match vault.header.slots {
        Some(slots) => slots,
        None => return Err(eyre!("Vault header slots are unavailable")),
    };
    let params = match vault.header.params {
        Some(slots) => slots,
        None => return Err(eyre!("Vault header parameters are unavailable")),
    };

    let master_key = try_decrypt_master_key(password, &slots)?;

    decrypt_database(&params, &master_key, &vault.db)
}
