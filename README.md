# masterkey
[![Go Report Card](https://goreportcard.com/badge/github.com/johnathanhowell/masterkey)](https://goreportcard.com/report/github.com/johnathanhowell/masterkey)
[![Build Status](https://travis-ci.org/johnathanhowell/masterkey.svg?branch=master)](https://travis-ci.org/johnathanhowell/masterkey)

masterkey is a simple, secure password manager written in Go using `nacl/secretbox.` It stores credentials given a `location`, where each credential is represented by a `Username` and a `Password`. Locations, Usernames, and Passwords are always encrypted using a scrypt key derived from the input passphrase and never stored on disk or in memory. Unlike `password-store` and a few other password managers, an attacker with access to the encrypted database can not discern how many passwords are stored, the labels (`locations`) for the passwords, or the usernames associated with the passwords.

## Example Usage

Install `masterkey` either by downloading a release or using `go get`:

`go get github.com/johnathanhowell/masterkey`

Now create your vault, in this example we'll create it at `./vault.db`. New vaults are created using the `-new` flag, existing vaults can be opened by simplly omitting the `-new` flag.

```
masterkey -new vault.db
Enter a passphrase for vault.db:
Enter the same passphrase again:
masterkey [vault.db] >
masterkey [vault.db] > help
gen [location] [username]: generate a password and add it to the vault
edit [location] [username] [password]: change the credentials at location to username, password
clip [location]: copy the password at location to the clipboard.
search [searchtext]: search the vault for locations containing searchtext
list: list the credentials stored inside this vault
save: save the changes in this vault to disk
get [location]: get the credential at [location]
add [location] [username] [password]: add a credential to the vaul
masterkey [vault.db] > gen github.com johnathanhowell
github.com generated successfully
masterkey [vault.db] > get github.com
Username: johnathanhowell
Password: speedy dwindling bicycle cedar putty urgent myriad ensign jaws gambit digit usual
masterkey [vault.db] > clip github.com
github.com copied to clipboard, will clear in 30 seconds
masterkey [vault.db] > exit
clearing clipboard and saving vault

... end of session.
```

Note that as with all password managers, your vault is only as secure as your master password. Use a strong, high entropy master password to protect your credentials.

`masterkey` will launch you into an interactive shell where you can interact with your vault. `help` lists the available commands. The vault will automatically be (safely, that is, atomically), saved on ctrl-c or `exit`.

## Planned Features

- Migration from 1Password, KeePass, and `password-store`
- Web interface


