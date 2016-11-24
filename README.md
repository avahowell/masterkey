# masterkey

masterkey is a simple, secure password manager written in Go using `nacl/secretbox.` It stores credentials given a `location`, where each credential is represented by a `Username` and a `Password`. Locations, Usernames, and Passwords are always encrypted using a scrypt key derived from the input passphrase and never stored on disk or in memory. Unlike `password-store` and a few other password managers, an attacker with access to the encrypted database can not discern how many passwords are stored, the labels (`locations`) for the passwords, or the usernames associated with the passwords.

## Usage

Install `masterkey` either by downloading a release or using `go install`:

`go install github.com/johnathanhowell/masterkey`

Create your vault, in this example we'll create it at `./vault.db`

```
masterkey -new vault.db
... enter strong passphrase twice
```

Note that as with all password managers, your vault is only as secure as your master password. Use a strong, high entropy master password to protect your credentials.

`masterkey` will launch you into an interactive shell where you can interact with your vault. `help` lists the available commands. The vault will automatically be (safely, that is, atomically), saved on ctrl-c or `exit`.

## Planned Features

- Migration from 1Password, KeePass, and `password-store`
- Secure cross-platform clipboard interaction (with automatic clearing)
- Web interface


