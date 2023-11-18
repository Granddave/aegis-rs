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

/// Entry with metadata and information used to generate one time codes
#[derive(Debug, Deserialize, PartialEq)]
pub struct Entry {
    #[serde(flatten)]
    pub info: EntryInfo,
    // pub uuid: String,
    pub name: String,
    pub issuer: String,
    // pub note: String,
    // pub favorite: bool,
    // pub icon: String,
}

pub fn generate_otp(entry_info: &EntryInfo) -> Result<String> {
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

#[cfg(test)]
mod test {
    use crate::otp::{
        Entry, EntryInfo, EntryInfoHotp, EntryInfoSteam, EntryInfoTotp, HashAlgorithm,
    };

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
