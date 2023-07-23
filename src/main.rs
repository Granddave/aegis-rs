extern crate serde_json;

use aes_gcm::{aead::AeadMut, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use color_eyre::eyre::Result;
use console::Term;
use dialoguer::{theme::ColorfulTheme, FuzzySelect, Password};
use hex::FromHex;
use libreauth::oath::TOTPBuilder;
use password_hash::Output;
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Deserialize)]
struct EntryInfo {
    secret: String,
    algo: String,
    digits: i32,
    period: i32,
}

#[derive(Debug, Deserialize)]
struct Entry {
    r#type: String,
    uuid: String,
    name: String,
    issuer: String,
    note: String,
    favorite: bool,
    // #[serde(skip)]
    // icon: String,
    info: EntryInfo,
}

#[derive(Debug, Deserialize)]
struct Database {
    version: u32, // TODO: Check version
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct KeyParams {
    nonce: String,
    tag: String,
}

#[derive(Debug, Deserialize)]
struct Slot {
    r#type: i32,
    uuid: String,
    key: String,
    key_params: KeyParams,
    n: Option<i32>,
    r: Option<i32>,
    p: Option<i32>,
    salt: Option<String>,
    repaired: Option<bool>,
    is_backup: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Header {
    slots: Vec<Slot>,
    params: KeyParams,
}

#[derive(Debug, Deserialize)]
struct AegisBackup {
    version: u32, // TODO: Check version
    header: Header,
    db: String,
}

fn parse_aegis_json(path: &str) -> AegisBackup {
    let mut file = File::open(path).expect("Failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    serde_json::from_str(&contents).expect("Failed to parse JSON")
}

fn derive_key(password: &[u8], salt_hex: &str) -> Output {
    let salt = SaltString::from_b64(
        &general_purpose::STANDARD_NO_PAD
            .encode(Vec::from_hex(salt_hex).expect("Failed to decode hex")),
    )
    .expect("Failed to parse salt");

    // TODO: Parse parameters from JSON
    let n = 15;
    let r = 8;
    let p = 1;

    let scrypt_params = scrypt::Params::new(n, r, p, 32).expect("Failed to set scrypt params");
    let derived_key = Scrypt
        .hash_password_customized(password, None, None, scrypt_params, &salt)
        .expect("Failed to derive key");

    derived_key.hash.expect("Failed to get hash of derived key")
}

fn generate_totp(secret: &str) -> Result<String> {
    let code = TOTPBuilder::new().base32_key(secret).finalize()?.generate();
    assert_eq!(code.len(), 6);
    Ok(code)
}

fn get_time_left(period: i32) -> i32 {
    let current_time = SystemTime::now();
    let seconds_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let seconds = seconds_since_epoch.as_secs() as i32;
    let remaining_time = period - (seconds % period);

    remaining_time
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args: Vec<String> = env::args().collect();
    let aegis = parse_aegis_json(args.get(1).expect("No filepath argument"));

    // TODO: Remove
    //let password = aegis_json["pw"].as_str().expect("No pw");
    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Insert Aegis Password")
        .interact()?;
    // TODO: Support password file

    // TODO: Try different slots.
    //       Find the ones with type == 1
    //       Iterate over them and decrypt the master key
    let slot_index = 1;
    let slot = aegis.header.slots.get(slot_index).unwrap();

    // Derive a key from the provided password and the salt from the file
    let derived_key = derive_key(
        password.as_bytes(),
        slot.salt.as_ref().expect("Failed to parse salt string"),
    );
    let key_nonce = Vec::from_hex(&slot.key_params.nonce)?;
    let mut master_key_enc: Vec<u8> = Vec::from_hex(&slot.key)?.to_vec();
    master_key_enc.extend_from_slice(&Vec::from_hex(&slot.key_params.tag)?);

    // Decrypt master key
    let mut cipher = Aes256Gcm::new(derived_key.as_bytes().into());
    let master_key = cipher
        .decrypt(Nonce::from_slice(&key_nonce), master_key_enc.as_ref())
        .expect("Failed to decrypt master key");

    // Get database encryption parameters
    let db_tag = Vec::from_hex(aegis.header.params.tag)?;
    let db_nonce = Vec::from_hex(aegis.header.params.nonce)?;
    let db_contents_enc = general_purpose::STANDARD_NO_PAD.decode(aegis.db)?;

    // Decrypt database
    let mut cipher_db = Aes256Gcm::new(master_key.as_slice().into());
    let mut db_enc: Vec<u8> = db_contents_enc;
    db_enc.extend_from_slice(&db_tag);
    let db_contents = cipher_db
        .decrypt(Nonce::from_slice(&db_nonce), db_enc.as_ref())
        .expect("Failed to decrypt database");

    let db_contents_str = String::from_utf8(db_contents).expect("UTF8");
    let db: Database = serde_json::from_str(&db_contents_str).expect("Failed to parse JSON");

    // TOTP Picker
    let items: Vec<&str> = db
        .entries
        .iter()
        .map(|entry| entry.issuer.as_str()) // TODO: Insert padded account name
        .collect();

    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .items(&items)
        .default(0)
        .interact_on_opt(&Term::stderr())?;
    match selection {
        Some(index) => {
            let totp_info = &db.entries.get(index).unwrap().info;
            println!(
                "{}, ({}s left)",
                generate_totp(&totp_info.secret.as_str())?,
                get_time_left(30)
            );
        }
        None => println!("No selection"),
    }
    // TODO: Reset terminal on exit

    Ok(())
}
