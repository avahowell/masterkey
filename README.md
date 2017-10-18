# masterkey
[![Go Report Card](https://goreportcard.com/badge/github.com/avahowell/masterkey)](https://goreportcard.com/report/github.com/avahowell/masterkey)
[![Build Status](https://travis-ci.org/avahowell/masterkey.svg?branch=master)](https://travis-ci.org/avahowell/masterkey)

masterkey is a simple, secure password manager written in Go using `nacl/secretbox.` It stores credentials given a `location`, where each credential is represented by a `Username` and a `Password`. Locations, Usernames, and Passwords are always encrypted using a scrypt key derived from the input passphrase and never stored on disk or in memory. Unlike `password-store` and a few other password managers, an attacker with access to the encrypted database can not discern how many passwords are stored, the labels (`locations`) for the passwords, or the usernames associated with the passwords.

## Example Usage

Install `masterkey` either by downloading a release or using `go get`:

`go get github.com/avahowell/masterkey`

Now create your vault, in this example we'll create it at `./vault.db`. New vaults are created using the `-new` flag, existing vaults can be opened by simplly omitting the `-new` flag.

```
masterkey -new vault.db
Enter a passphrase for vault.db:
Enter the same passphrase again:
masterkey [vault.db] >
masterkey [vault.db] > help
save: save the changes in this vault to disk
clip [location]: copy the password at location to the clipboard.
addmeta [location] [meta name] [meta value]: add a metadata tag to the credential at [location]
edit [location] [username] [password]: change the credentials at location to username, password
search [searchtext]: search the vault for locations containing searchtext
editmeta [location] [meta name] [new meta value]: edit an existing metadata tag at [location].
deletemeta [location] [meta name]: delete an existing metadata tag at [location].
list: list the credentials stored inside this vault
get [location]: get the credential at [location]
add [location] [username] [password]: add a credential to the vault
gen [location] [username]: generate a password and add it to the vault
delete [location]: remove [location] from the vault.
masterkey [vault.db] > gen github.com avahowell
github.com generated successfully
masterkey [vault.db] > get github.com
Username: avahowell
Password: speedy dwindling bicycle cedar putty urgent myriad ensign jaws gambit digit usual
masterkey [vault.db] > addmeta github.com 2fa "pretty secure 2fa token"
2fa added to github.com successfully.
masterkey [vault.db] > get github.com
Username: avahowell
Password: speedy dwindling bicycle cedar putty urgent myriad ensign jaws gambit digit usual
2fa: pretty secure token
masterkey [vault.db] > clip github.com
github.com copied to clipboard, will clear in 30 seconds
masterkey [vault.db] > exit
clearing clipboard and saving vault

... end of session.
```

Note that as with all password managers, your vault is only as secure as your master password. Use a strong, high entropy master password to protect your credentials.

`masterkey` will launch you into an interactive shell where you can interact with your vault. `help` lists the available commands. The vault will automatically be (safely, that is, atomically), saved on ctrl-c or `exit`.


## Migration

`masterkey` has a command, `importcsv`, that can be used to import arbitrary password data from a CSV file. This command takes 4 arguments. The first is the path to the CSV file, the second is the name of the CSV key to use for Locations, the third is the name of the CSV key to use for Usernames, and the fourth is the name of CSV key to use for Passwords. All other CSV fields will be added as Meta tags.

For example, the following CSV password file:
```csv
"Group","Title","Username","Password","URL","Notes"

"TestGroup0","testtitle0","testusername0","testpassword0","testurl0",""
"TestGroup1","testtitle1","testusername1","testpassword1","testurl1",""
"TestGroup2","testtitle2","testusername2","testpassword2","testurl2",""
"TestGroup2","testtitle2","testusername2","testpassword2","testurl2",""
"TestGroup3","testtitle3","testusername3","testpassword3","testurl3",""
"TestGroup4","testtitle4","testusername4","testpassword4","testurl4",""
"TestGroup3","testtitle3","testusername3","testpassword3","testurl3",""
```

Can be successfully imported by using the following command:

```
masterkey [vault.db] > importcsv test.csv Title Username Password
```

This will use the "Title" field to determine the Location, "Username" for usernames, and "Password" for passwords.

## Planned Features

- Web interface

## Donate

If you find masterkey useful, you can send some bitcoin to 39xGq6Y1ANxmDUTvWz75mscruYiDGYmGNe.

