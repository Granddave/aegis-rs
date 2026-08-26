[![ci](https://github.com/Granddave/aegis-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Granddave/aegis-rs/actions)
[![dependency status](https://deps.rs/repo/github/granddave/aegis-rs/status.svg)](https://deps.rs/repo/github/granddave/aegis-rs)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# Aegis 2FA Authenticator CLI

This project provides a Rust library and CLI for decrypting backup vaults from the Android app [Aegis Authenticator](https://github.com/beemdevelopment/Aegis) and generating OTP codes.


## Features

- Decryption of the 256 bit AES-GCM encrypted vault 🔓
- Fuzzy selection 🔍
- TOTP generation 🕒
- Time left indication ⏳
- Clipboard support 📋
- JSON output to stdout 📜


## Getting Started with Aegis-rs

### Installation

The easiest way to install Aegis-rs is by downloading a pre-compiled binary from the [latest release](https://github.com/Granddave/aegis-rs/releases).

You can also download and compile yourself by using cargo-install:

```sh
cargo install aegis-rs
```

### Launching Aegis-rs with a Backup File

To start Aegis-rs, simply pass the path to your backup file as an argument and enter password. For example:

```sh
$ aegis-rs ~/Documents/aegis-backup-20230512-193110.json
? Insert Aegis Password › ********
```

### Unlocking the Vault

Aegis-rs will prompt you to enter the password, type the password then enter to unlock the vault.

> For other ways to unlock the vault, check the Usage section.


### Searching for an Entry

Aegis-rs supports fuzzy finding for quickly locating entries. Type a part of the entry's name to filter the list. For instance:

```sh
› tw
❯ Twitter (@johndoe)
  Twitch (johndoe)
  TeamViewer (johndoe@protonmail.com)
  Bitwarden (johndoe@protonmail.com)
```

### Generating an OTP

Aegis-rs allows you to read the OTP directly in the terminal or paste it using the integrated clipboard support. OTPs are regenerated automatically upon expiration. Here the OTP is displayed, including its remaining validity:

```sh
· Twitter (@johndoe)
121 921 (28s left)
```

## Usage

The following table show all options and arguments available.

> You can check the options and arguments with `aegis-rs -h`.

### Extra flags

| Description | Option or Argument | Environment variable | Note |
|---|---|---|---|
| Path to the vault file | `<VAULT_FILE_PATH>` | `AEGIS_VAULT_FILE` | Mandatory argument (no option flag) |
| Password to unlock vault | `--password <PASSWORD>` | `AEGIS_PASSWORD` | Exclusive with the `--password-file` option |
| Path to the password file | `-p <PASSWORD_FILE>`, `--password-file <PASSWORD_FILE>` | `AEGIS_PASSWORD_FILE` | Exclusive with the `--password` option |
| Group OTP digits | `--digit-group-size <SIZE>`| `AEGIS_DIGIT_GROUP_SIZE` | Only affects interactive display |
| Filter by entry issuer | `--issuer` | | |
| Filter by entry name | `--name` | | |
| Print to stdout in JSON | `--json` | | |
| Print help | `-h`, `--help` | | |
| Print version | `-V`, `--version` | | |


## Library

Add the crate to a Rust project:

```sh
cargo add aegis-rs color-eyre
```

The library exposes vault parsing and OTP generation:

```rust,no_run
use aegis_rs::{
    otp::generate_otp,
    vault::{parse_vault, PasswordGetter},
};
use color_eyre::eyre::Result;

struct Password;

impl PasswordGetter for Password {
    fn get_password(&self) -> Result<String> {
        Ok("password".to_string())
    }
}

fn main() -> Result<()> {
    let contents = std::fs::read_to_string("aegis-backup.json")?;
    let database = parse_vault(&contents, &Password)?;
    let otp = generate_otp(&database.entries[0].info)?;
    println!("{otp}");
    Ok(())
}
```


## Project history

The library was previously published separately as
[`aegis-vault-utils`](https://github.com/Granddave/aegis-vault-utils). Starting
with version 0.6.0, the library and CLI are published together as `aegis-rs`.


# License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
