use color_eyre::eyre::{eyre, Result};
use libreauth::{hash::HashFunction, oath::TOTPBuilder};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<HashAlgorithm> for HashFunction {
    fn from(algo: HashAlgorithm) -> Self {
        match algo {
            HashAlgorithm::Sha1 => HashFunction::Sha1,
            HashAlgorithm::Sha256 => HashFunction::Sha256,
            HashAlgorithm::Sha512 => HashFunction::Sha512,
        }
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct EntryInfoHotp {
    pub secret: String,
    pub algo: HashAlgorithm,
    pub digits: i32,
    pub counter: u64,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct EntryInfoTotp {
    pub secret: String,
    pub algo: HashAlgorithm,
    pub digits: i32,
    pub period: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct EntryInfoSteam {
    pub secret: String,
    /// Only Sha1 is supported
    pub digits: i32,
    pub period: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct EntryInfoYandex {}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type", content = "info")]
pub enum EntryInfo {
    /// Not implemented.
    ///
    /// [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)
    Hotp(EntryInfoHotp),

    /// [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
    Totp(EntryInfoTotp),

    /// Not implemented.
    Steam(EntryInfoSteam),

    /// Not implemented.
    Yandex(EntryInfoYandex),
}

pub fn generate_totp(entry_info: &EntryInfo) -> Result<String> {
    let code = match entry_info {
        // TODO: Add full support for HOTP
        /*
        EntryType::Hotp(info) => HOTPBuilder::new()
            .base32_key(&info.secret.to_string())
            .hash_function(info.algo.into())
            .output_len(info.digits.try_into()?)
            .counter(info.counter)
            .finalize()?
            .generate(),
        */
        EntryInfo::Totp(info) => TOTPBuilder::new()
            .base32_key(&info.secret.to_string())
            .hash_function(info.algo.into())
            .output_len(info.digits.try_into()?)
            .period(info.period.try_into()?)
            .finalize()?
            .generate(),
        _ => return Err(eyre!("Not implemented")),
    };

    Ok(code)
}

pub fn calculate_remaining_time(entry_info: &EntryInfo) -> Result<i32> {
    let period_length_s = match entry_info {
        EntryInfo::Totp(info) => info.period,
        _ => return Err(eyre!("Not implemented")),
    } as i32;
    let current_time = SystemTime::now();
    let seconds_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let seconds = seconds_since_epoch.as_secs() as i32;

    Ok(period_length_s - (seconds % period_length_s))
}
