extern crate serde_json;

use aes_gcm::{aead::AeadMut, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use hex::FromHex;
use libreauth::oath::TOTPBuilder;
use password_hash::Output;
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::Read;

fn parse_aegis_json(path: &str) -> Value {
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
    let scrypt_params = scrypt::Params::new(15, 8, 1, 32).expect("Failed to set scrypt params");
    let derived_key = Scrypt
        .hash_password_customized(password, None, None, scrypt_params, &salt)
        .expect("Failed to derive key");

    return derived_key.hash.expect("Failed to get hash of derived key");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let aegis_json = parse_aegis_json(args.get(1).expect("No filepath argument"));

    // TODO: Read password from stdin
    let password = aegis_json["pw"].as_str().expect("No pw").as_bytes(); // TODO: Remove

    // TODO: Try different slots
    let slot = 1;
    // Derive a key from the provided password and the salt from the file
    let salt_hex_str = aegis_json["header"]["slots"][slot]["salt"]
        .as_str()
        .expect("Failed to parse salt string");
    let derived_key = derive_key(password, salt_hex_str);
    // println!(
    //     "Derived key: {:?}, len={:?}",
    //     derived_key,
    //     derived_key.len()
    // );

    let mut cipher = Aes256Gcm::new(derived_key.as_bytes().into());

    // Decrypt master key
    let tag_hex = aegis_json["header"]["slots"][slot]["key_params"]["tag"]
        .as_str()
        .expect("Failed to find the tag");
    let nonce_hex = aegis_json["header"]["slots"][slot]["key_params"]["nonce"]
        .as_str()
        .expect("Failed to find the nonce");
    let master_key_enc_hex = aegis_json["header"]["slots"][slot]["key"]
        .as_str()
        .expect("Failed to find the key");

    let mut master_key_enc: Vec<u8> = Vec::from_hex(master_key_enc_hex).unwrap().to_vec();
    master_key_enc.extend_from_slice(Vec::from_hex(tag_hex).unwrap().as_slice());
    let master_key = cipher
        .decrypt(
            Nonce::from_slice(&Vec::from_hex(nonce_hex).unwrap()),
            master_key_enc.as_ref(),
        )
        .expect("Failed to decrypt master key");

    // Load and base64-decode database
    let db_contents_enc_b64 = aegis_json["db"]
        .as_str()
        .expect("Failed to find the database");
    let db_contents_enc = general_purpose::STANDARD_NO_PAD
        .decode(db_contents_enc_b64)
        .expect("Failed to decode the database");

    // Decrypt database
    let mut cipher_db = Aes256Gcm::new(master_key.as_slice().into());
    let mut ciphertext_db: Vec<u8> = db_contents_enc;
    ciphertext_db.extend_from_slice(Vec::from_hex(tag_hex).unwrap().as_slice());
    let db_contents_str = cipher_db
        .decrypt(
            Nonce::from_slice(&Vec::from_hex(nonce_hex).unwrap()),
            ciphertext_db.as_ref(),
        )
        .expect("Failed to decrypt database");

    println!("{:?}", db_contents_str);

    //
    //
    //
    //
    //
    //
    // TODO: Parse out TOTP entry

    // TOTP Generation
    let key = "ABCABCABCABC".to_string();
    let code = TOTPBuilder::new()
        .base32_key(&key)
        .finalize()
        .unwrap()
        .generate();
    assert_eq!(code.len(), 6);
    println!("{}", code);
}
