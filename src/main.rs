use base64::{engine::general_purpose, Engine as _};
use hex::FromHex;
use libreauth::oath::TOTPBuilder;
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};

fn main() {
    let password = b"hunter42";
    let salt_string = "ABCABCABCABC";

    let salt = SaltString::from_b64(
        &general_purpose::STANDARD_NO_PAD
            .encode(Vec::from_hex(salt_string).expect("Failed to decode hex")),
    )
    .expect("Failed to parse salt");

    let scrypt_params = scrypt::Params::new(15, 8, 1, 32).expect("Failed to set scrypt params");
    let derived_key = Scrypt
        .hash_password_customized(password, None, None, scrypt_params, &salt)
        .unwrap();
    println!("{:?}", derived_key.hash.unwrap());

    let key = "ABCABCABCABC".to_string();
    let code = TOTPBuilder::new()
        .base32_key(&key)
        .finalize()
        .unwrap()
        .generate();
    assert_eq!(code.len(), 6);
    println!("{}", code);
}
