use color_eyre::eyre::{eyre, Result};
use libreauth::{hash::HashFunction, oath::TOTPBuilder};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hashing algorithm to use when generating the OTP
#[derive(Debug, Deserialize, Eq, PartialEq, Clone, Copy)]
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

/// HOTP (HMAC-based One Time Pad)
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct EntryInfoHotp {
    /// Base32 encoded secret
    pub secret: String,
    /// Hashing algorithm to use
    pub algo: HashAlgorithm,
    /// Number of digits in the OTP
    pub digits: i32,
    /// The counter value to use when generating the OTP
    pub counter: u64,
}

/// Time-based One Time Pads (TOTP)
///
/// [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct EntryInfoTotp {
    /// Base32 encoded secret
    pub secret: String,
    /// Hashing algorithm to use
    pub algo: HashAlgorithm,
    /// Number of digits in the OTP
    pub digits: i32,
    /// The time step in seconds since the UNIX epoch
    pub period: i32,
}

/// Steam Guard OTP
///
/// Essentially a TOTP with a 5 digit code and 30 second period using the SHA1 hashing algorithm
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct EntryInfoSteam {
    /// Base32 encoded secret
    pub secret: String,
    /// Number of digits in the OTP (default: 5)
    pub digits: i32,
    /// The time step in seconds since the UNIX epoch (default: 30)
    pub period: i32,
    // TODO: Remove digits and period from this struct since the values are fixed?
}

/// Yandex OTP
///
/// Not implemented.
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct EntryInfoYandex {}

/// Information used to generate one time codes
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
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

/// Entry with metadata and information used to generate one time codes
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct Entry {
    /// Information used to generate the OTP such as the secret and algorithm
    #[serde(flatten)]
    pub info: EntryInfo,
    // /// A UUID (version 4)
    // pub uuid: String,
    /// The account name
    pub name: String,
    /// The service that the token is for
    pub issuer: String,
    // /// A personal note about the entry
    // pub note: String,
    // /// Whether the entry is a favorite or not
    // pub favorite: bool,
    // /// JPEGa's encoded in Base64 with padding
    // pub icon: String,
}

/// Current time since the UNIX epoch in seconds
fn time_since_epoch() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i32
}

/// Generates a one time password based on the entry information and the current time
///
/// # Arguments
/// * `entry_info` - The information used to generate the OTP
/// * `time_since_epoch` - The time since the UNIX epoch in seconds
///
/// # Returns
/// The generated one time password
///
/// # Errors
/// Returns an error if the entry type is not implemented or if the entry information is invalid
pub fn generate_otp(entry_info: &EntryInfo) -> Result<String> {
    generate_otp_impl(entry_info, time_since_epoch())
}

fn generate_otp_impl(entry_info: &EntryInfo, time_since_epoch: i32) -> Result<String> {
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
            .timestamp(time_since_epoch as i64)
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

/// Calculates the remaining time until the next period starts
pub fn calculate_remaining_time(entry_info: &EntryInfo) -> Result<i32> {
    calculate_remaining_time_impl(entry_info, time_since_epoch())
}

fn calculate_remaining_time_impl(entry_info: &EntryInfo, seconds_since_epoch: i32) -> Result<i32> {
    let period_length_s = match entry_info {
        EntryInfo::Totp(info) => info.period,
        _ => return Err(eyre!("Not implemented")),
    } as i32;

    Ok(period_length_s - (seconds_since_epoch % period_length_s))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::otp::{
        Entry, EntryInfo, EntryInfoHotp, EntryInfoSteam, EntryInfoTotp, HashAlgorithm,
    };

    fn totp_entry() -> Entry {
        Entry {
            info: EntryInfo::Totp(EntryInfoTotp {
                secret: "4SJHB4GSD43FZBAI7C2HLRJGPQ".to_string(),
                algo: HashAlgorithm::Sha1,
                digits: 6,
                period: 30,
            }),
            name: "Mason".to_string(),
            issuer: "Deno".to_string(),
        }
    }

    #[test]
    fn test_totp_generate() {
        let entry = totp_entry();
        let otp_0 = generate_otp_impl(&entry.info, 0).unwrap();
        let otp_10 = generate_otp_impl(&entry.info, 10).unwrap();
        let otp_50 = generate_otp_impl(&entry.info, 50).unwrap();
        assert_eq!(otp_0, "591295");
        assert_eq!(otp_10, "591295");
        assert_eq!(otp_50, "526156");
    }

    #[test]
    fn test_totp_time_remaining() {
        let entry = totp_entry();
        let remaining_time = calculate_remaining_time_impl(&entry.info, 0).unwrap();
        assert_eq!(remaining_time, 30);

        let remaining_time = calculate_remaining_time_impl(&entry.info, 10).unwrap();
        assert_eq!(remaining_time, 20);

        let remaining_time = calculate_remaining_time_impl(&entry.info, 50).unwrap();
        assert_eq!(remaining_time, 10);
    }

    #[test]
    fn parse_hotp() {
        let json = r#"
            {
              "type": "hotp",
              "uuid": "b25f8815-007f-40f7-a700-ce058ac05435",
              "name": "Mason",
              "issuer": "WWE",
              "icon": null,
              "info": {
                "secret": "5VAML3X35THCEBVRLV24CGBKOY",
                "algo": "SHA512",
                "digits": 8,
                "counter": 10300
              }
            }"#;
        let hotp_entry = Entry {
            info: EntryInfo::Hotp(EntryInfoHotp {
                secret: "5VAML3X35THCEBVRLV24CGBKOY".to_string(),
                algo: HashAlgorithm::Sha512,
                digits: 8,
                counter: 10300,
            }),
            name: "Mason".to_string(),
            issuer: "WWE".to_string(),
        };

        let deserialized = serde_json::from_str::<Entry>(json).unwrap();
        assert_eq!(deserialized, hotp_entry);
    }

    #[test]
    fn parse_totp() {
        let json = r#"
            {
              "type": "totp",
              "uuid": "3ae6f1ad-2e65-4ed2-a953-1ec0dff2386d",
              "name": "Mason",
              "issuer": "Deno",
              "icon": null,
              "info": {
                "secret": "4SJHB4GSD43FZBAI7C2HLRJGPQ",
                "algo": "SHA1",
                "digits": 6,
                "period": 30
              }
            }"#;
        let totp_entry = Entry {
            info: EntryInfo::Totp(EntryInfoTotp {
                secret: "4SJHB4GSD43FZBAI7C2HLRJGPQ".to_string(),
                algo: HashAlgorithm::Sha1,
                digits: 6,
                period: 30,
            }),
            name: "Mason".to_string(),
            issuer: "Deno".to_string(),
        };

        let deserialized = serde_json::from_str::<Entry>(json).unwrap();
        assert_eq!(deserialized, totp_entry);
    }

    #[test]
    fn parse_steam() {
        let json = r#"
            {
              "type": "steam",
              "uuid": "5b11ae3b-6fc3-4d46-8ca7-cf0aea7de920",
              "name": "Sophia",
              "issuer": "Boeing",
              "icon": null,
              "info": {
                "secret": "JRZCL47CMXVOQMNPZR2F7J4RGI",
                "algo": "SHA1",
                "digits": 5,
                "period": 30
              }
            }"#;
        let steam_entry = Entry {
            info: EntryInfo::Steam(EntryInfoSteam {
                secret: "JRZCL47CMXVOQMNPZR2F7J4RGI".to_string(),
                digits: 5,
                period: 30,
            }),
            name: "Sophia".to_string(),
            issuer: "Boeing".to_string(),
        };

        let deserialized = serde_json::from_str::<Entry>(json).unwrap();
        assert_eq!(deserialized, steam_entry);
    }
}
