![ci](https://github.com/Granddave/aegis-rs/actions/workflows/ci.yml/badge.svg)

# Aegis CLI tool

This is a CLI tool for generating TOTP codes from a backup vault from [Aegis Authenticator](https://github.com/beemdevelopment/Aegis).


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
