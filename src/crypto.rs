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

/// Derive master key from password
fn derive_key(password: &[u8], slot: &Slot) -> Output {
    let salt = SaltString::from_b64(
        &general_purpose::STANDARD_NO_PAD
            .encode(Vec::from_hex(slot.salt.as_ref().unwrap()).expect("Failed to decode hex")),
    )
    .expect("Failed to parse salt");

    let n = (slot.n.unwrap() as f32).log2() as u8;
    let r = slot.r.unwrap() as u32;
    let p = slot.p.unwrap() as u32;

    let scrypt_params = scrypt::Params::new(n, r, p, 32).expect("Failed to set scrypt params");
    let derived_key = Scrypt
        .hash_password_customized(password, None, None, scrypt_params, &salt)
        .expect("Failed to derive key");

    derived_key.hash.expect("Failed to get hash of derived key")
}

fn decrypt_master_key(password: &str, slots: &[Slot]) -> Option<Vec<u8>> {
    // Only password based master key decryptions are supported
    for slot in slots
        .iter()
        .filter(|s| s.r#type == SlotType::Password)
        .collect::<Vec<&Slot>>()
    {
        // Derive a key from the provided password and the salt from the file
        let derived_key = derive_key(password.as_bytes(), slot);
        let key_nonce = Vec::from_hex(&slot.key_params.nonce).expect("Unexpected nonce format");
        let mut master_key_cipher = Vec::from_hex(&slot.key)
            .expect("Unexpected key format")
            .to_vec();
        master_key_cipher.extend_from_slice(
            &Vec::from_hex(&slot.key_params.tag).expect("Unexpected tag format"),
        );

        // Decrypt master key
        let mut cipher = Aes256Gcm::new(derived_key.as_bytes().into());
        match cipher.decrypt(Nonce::from_slice(&key_nonce), master_key_cipher.as_ref()) {
            Ok(master_key) => {
                return Some(master_key);
            }
            Err(_) => continue,
        };
    }

    None
}

fn decrypt_database(params: &KeyParams, master_key: &Vec<u8>, db: &String) -> Database {
    let db_nonce = Vec::from_hex(&params.nonce).expect("Unexpected nonce format");
    let db_tag = Vec::from_hex(&params.tag).expect("Unexpected tag format");
    let db_contents_cipher = general_purpose::STANDARD
        .decode(db)
        .expect("Unexpected database format");

    let mut cipher_db = Aes256Gcm::new(master_key.as_slice().into());
    let mut db_cipher: Vec<u8> = db_contents_cipher;
    db_cipher.extend_from_slice(&db_tag);
    let db_contents = cipher_db
        .decrypt(Nonce::from_slice(&db_nonce), db_cipher.as_ref())
        .expect("Failed to decrypt database");

    let db_contents_str = String::from_utf8(db_contents).expect("Unexpected UTF-8 format");
    let db: Database = serde_json::from_str(&db_contents_str).expect("Failed to parse JSON");

    db
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

    let master_key = match decrypt_master_key(password, &slots) {
        Some(master_key) => master_key,
        None => return Err(eyre!("Failed to decrypt database")),
    };
    Ok(decrypt_database(&params, &master_key, &vault.db))
}
