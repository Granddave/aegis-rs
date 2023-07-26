# Aegis CLI tool

This is a CLI tool for generating TOTP codes from a backup vault from [Aegis Authenticator](https://github.com/beemdevelopment/Aegis).

## Features

- Decryption of the 256 bit AES-GSM encrypted vault
- Fuzzy selection
- TOTP generation (Currently just SHA1)
- Time left indication


## Resources


- [Vault documentation](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)
- [Vault decryption example](https://github.com/beemdevelopment/Aegis/blob/master/docs/decrypt.py)
- [Plain text vault example](https://github.com/beemdevelopment/Aegis/blob/master/app/src/test/resources/com/beemdevelopment/aegis/importers/aegis_plain.json)
- [Encrypted vault example](https://github.com/beemdevelopment/Aegis/blob/master/app/src/test/resources/com/beemdevelopment/aegis/importers/aegis_encrypted.json)


## TODO

- Add password file feature
- Add countdown timer and refresh TOTP code after timeout
- Improve on error handling
- Support different TOTP algorithms
    - [x] TOTP
    - [ ] HOTP
    - [ ] Steam
    - [ ] Yandex
- Support unencrypted vaults
- Display digits in groups
