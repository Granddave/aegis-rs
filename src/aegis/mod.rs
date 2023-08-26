use aes_gcm::{aead::AeadMut, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use color_eyre::eyre::Result;
use dialoguer::{theme::ColorfulTheme, Password};
use hex::FromHex;
use libreauth::{hash::HashFunction, oath::TOTPBuilder};
use password_hash::Output;
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use std::io::Read;
use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{fs::File, io};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Deserialize)]
pub struct EntryInfo {
    secret: String,
    algo: HashAlgorithm,
    digits: i32,
    pub period: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EntryTypes {
    Hotp,
    Totp,
    Steam,
    Yandex,
}

#[derive(Debug, Deserialize)]
pub struct Entry {
    pub r#type: EntryTypes,
    // pub uuid: String,
    pub name: String,
    pub issuer: String,
    // pub note: String,
    // pub favorite: bool,
    // pub icon: String,
    pub info: EntryInfo,
}

#[derive(Debug, Deserialize)]
pub struct Database {
    version: u32,
    pub entries: Vec<Entry>,
}

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

#[derive(Debug, Deserialize)]
struct Header {
    slots: Vec<Slot>,
    params: KeyParams,
}

#[derive(Debug, Deserialize)]
struct AegisBackup {
    version: u32,
    header: Header,
    db: String,
}

pub fn parse_aegis_backup_file(path: &str) -> Result<Vec<Entry>> {
    let mut file = File::open(path).expect("Failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    let aegis_backup: AegisBackup = serde_json::from_str(&contents).expect("Failed to parse JSON");

    if aegis_backup.version != 1 {
        println!("Unsupported vault version: {}", aegis_backup.version);
        std::process::exit(1);
    }

    let password = get_password()?;
    let master_key = match decrypt_master_key(password.as_str(), &aegis_backup.header.slots) {
        Some(master_key) => master_key,
        None => {
            println!("Wrong password, try again.");
            std::process::exit(1);
        }
    };
    let db = decrypt_database(&aegis_backup.header.params, &master_key, &aegis_backup.db);

    if db.version != 2 {
        println!("Unsupported database version: {}", db.version);
        std::process::exit(1);
    }

    Ok(db.entries)
}

fn get_password() -> io::Result<String> {
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

pub fn generate_totp(info: &EntryInfo) -> Result<String> {
    let code = TOTPBuilder::new()
        .base32_key(&info.secret.to_string())
        .hash_function(match info.algo {
            HashAlgorithm::Sha1 => HashFunction::Sha1,
            HashAlgorithm::Sha256 => HashFunction::Sha256,
            HashAlgorithm::Sha512 => HashFunction::Sha512,
        })
        .output_len(info.digits.try_into()?)
        .period(info.period.try_into()?)
        .finalize()?
        .generate();
    Ok(code)
}

pub fn calculate_remaining_time(period_length_s: i32) -> i32 {
    let current_time = SystemTime::now();
    let seconds_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let seconds = seconds_since_epoch.as_secs() as i32;

    period_length_s - (seconds % period_length_s)
}

fn decrypt_master_key(password: &str, slots: &[Slot]) -> Option<Vec<u8>> {
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
