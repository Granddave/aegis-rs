use color_eyre::eyre::Result;
use libreauth::{hash::HashFunction, oath::TOTPBuilder};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hash algorithms for HOTP and TOTP
#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Deserialize)]
pub struct EntryInfo {
    pub secret: String,
    pub algo: HashAlgorithm,
    pub digits: i32,
    pub period: Option<i32>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    /// Not implemented.
    ///
    /// [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)
    Hotp,

    /// [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
    Totp,

    /// Not implemented.
    Steam,

    /// Not implemented.
    Yandex,
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
        .period(info.period.unwrap().try_into()?)
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
