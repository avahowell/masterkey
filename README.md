# masterkey

[![Go Report Card](https://goreportcard.com/badge/github.com/avahowell/masterkey)](https://goreportcard.com/report/github.com/avahowell/masterkey)
[![Build Status](https://travis-ci.org/avahowell/masterkey.svg?branch=master)](https://travis-ci.org/avahowell/masterkey)

![masterkey](img/screen.png?raw=True "screenshot")

masterkey is a simple, secure password manager written in Go. It uses `xchacha20poly1305` for authenticated encryption and `argon2id` for key derivation. It stores credentials given a `location`, where each credential is represented by a `Username` and a `Password`. Locations, Usernames, and Passwords are always encrypted using a argon2id key derived from the input passphrase. Unlike `password-store` and a few other password managers, an attacker with access to the encrypted database can not discern exactly how many passwords are stored, the labels (`locations`) for the passwords, or the usernames associated with the passwords.

## Example Usage

Install `masterkey` either by downloading a release or using `go get`:

`go get github.com/avahowell/masterkey`

Now create your vault, in this example we'll create it at `./vault.db`. New vaults are created using the `-new` flag, existing vaults can be opened by simplly omitting the `-new` flag.

Next, launch the terminal UI using `masterkey vault.db`, or use `masterkey -repl vault.db` to use the developer shell which has a bit more functionality.

Note that as with all password managers, your vault is only as secure as your master password. Use a strong, high entropy master password to protect your credentials.

