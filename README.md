![ci](https://github.com/Granddave/aegis-rs/actions/workflows/ci.yml/badge.svg)

# Aegis CLI tool

This is a CLI tool for generating TOTP codes from a backup vault from [Aegis Authenticator](https://github.com/beemdevelopment/Aegis).

## Getting Started with Aegis-rs

### Launching Aegis-rs with a Backup File

To start Aegis-rs, simply pass the path to your backup file as an argument. For example:

```sh
aegis-rs ~/Documents/aegis-backup-20230512-193110.json
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

### Retrieving One-Time Passwords (OTPs)

Aegis-rs allows you to read the OTP directly in the terminal or paste it using the integrated clipboard support. OTPs are regenerated automatically upon expiration. Here the OTP is displayed, including its remaining validity:

```sh
· Twitter (@johndoe)
121921 (28s left)
```


## Features

- Decryption of the 256 bit AES-GSM encrypted vault
- Fuzzy selection
- TOTP generation (Currently just SHA1)
- Time left indication
- Clipboard support


## Resources

- [Vault documentation](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)
- [Vault decryption example](https://github.com/beemdevelopment/Aegis/blob/master/docs/decrypt.py)
- [Plain text vault example](https://github.com/beemdevelopment/Aegis/blob/master/app/src/test/resources/com/beemdevelopment/aegis/importers/aegis_plain.json)
- [Encrypted vault example](https://github.com/beemdevelopment/Aegis/blob/master/app/src/test/resources/com/beemdevelopment/aegis/importers/aegis_encrypted.json)


## TODO

- [x] Add password file feature
- [x] Add countdown timer and refresh TOTP code after timeout
- [x] Improve on error handling
- [ ] Support different TOTP algorithms
    - [x] TOTP
    - [ ] HOTP
    - [ ] Steam
    - [ ] Yandex
- [ ] Support unencrypted vaults
- [ ] Display digits in groups
- [x] Add TOTP to clipboard
- [x] Add CI

# License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
