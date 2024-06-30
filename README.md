[![ci](https://github.com/Granddave/aegis-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Granddave/aegis-rs/actions)
[![dependency status](https://deps.rs/repo/github/granddave/aegis-rs/status.svg)](https://deps.rs/repo/github/granddave/aegis-rs)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# Aegis 2FA Authenticator CLI

This is a CLI tool for generating OTP codes from a backup vault from the Android app [Aegis Authenticator](https://github.com/beemdevelopment/Aegis).


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
$ cargo install --git https://github.com/Granddave/aegis-rs --tag latest
```

### Launching Aegis-rs with a Backup File

To start Aegis-rs, simply pass the path to your backup file as an argument and enter password. For example:

```sh
$ aegis-rs ~/Documents/aegis-backup-20230512-193110.json
? Insert Aegis Password › ********
```

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
121921 (28s left)
```


### Ways to unlock the Vault

To unlock the Aegis vault Aegis-rs supports the following methods:

1. Password: The password can be passed as an argument or set as an environment variable.
    - Environment variable: `AEGIS_PASSWORD`
    - Argument: `--password <PASSWORD>`
    - Example: `aegis-rs --password hunter2 vault.json`
2. Password file: A file containing the password to unlock the vault.
    - Environment variable: `AEGIS_PASSWORD_FILE`
    - Argument: `--password-file <PASSWORD_FILE>`
    - Example: `aegis-rs --password-file /path/to/password-file vault.json`
3. Password prompt: If no password is provided, Aegis-rs will prompt you to enter the password.


### Extra flags

- `--issuer <ISSUER>`: Filter entries by entry issuer.
- `--name <NAME>`: Filter entries by entry name.
- `--json`: Output the calculated OTPs as JSON.


## TODO

- [x] Add password file feature
- [x] Add countdown timer and refresh TOTP code after timeout
- [ ] Display digits in groups
- [x] Add TOTP to clipboard
- [x] Add CI

## Project history

This project has been divided into a binary (this repo) and a [vault
utility](https://github.com/Granddave/aegis-vault-utils) crate so that other
projects can utilize the parsing and OTP generation functionalities as well.


# License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
