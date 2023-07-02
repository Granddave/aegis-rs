extern crate serde_json;

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
    derived_key.hash.expect("Failed to get hash of derived key")
}

fn main() {
    let filepath: Vec<String> = env::args().collect();
    let aegis_json = parse_aegis_json(&filepath.get(1).expect("Found to filepath argument"));

    let password = b"hunter42";

    let salt_string = aegis_json["header"]["slots"][1]["salt"]
        .as_str()
        .expect("Failed to parse salt_string");

    let derived_key = derive_key(password, salt_string);
    println!("{:?}", derived_key);

    // TODO: Set up AESGCM
    // TODO: Decrypt master key
    // TODO: Base64-decode database
    // TODO: Decrypt database
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
