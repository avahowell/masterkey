package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/howeyc/gopass"
	"github.com/johnathanhowell/masterkey/repl"
	"github.com/johnathanhowell/masterkey/secureclip"
	"github.com/johnathanhowell/masterkey/vault"
	"github.com/johnathanhowell/masterkey/vault/filelock"
)

const usage = `Usage: masterkey [-new] vault`

func die(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func setupRepl(v *vault.Vault, vaultPath string) *repl.REPL {
	r := repl.New(fmt.Sprintf("masterkey [%v] > ", vaultPath))

	r.AddCommand(addFileCmd(v))
	r.AddCommand(getFileCmd(v))
	r.AddCommand(importCmd(v))
	r.AddCommand(listCmd(v))
	r.AddCommand(saveCmd(v, vaultPath))
	r.AddCommand(getCmd(v))
	r.AddCommand(addCmd(v))
	r.AddCommand(genCmd(v))
	r.AddCommand(editCmd(v))
	r.AddCommand(clipCmd(v))
	r.AddCommand(searchCmd(v))
	r.AddCommand(addmetaCmd(v))
	r.AddCommand(editmetaCmd(v))
	r.AddCommand(deletemetaCmd(v))
	r.AddCommand(deleteCmd(v))
	r.AddCommand(changePasswordCmd(v))

	r.OnStop(func() {
		fmt.Println("clearing clipboard and saving vault")
		secureclip.Clear()
		v.Save(vaultPath)
	})

	return r
}

func main() {
	createVault := flag.Bool("new", false, "whether to create a new vault at the specified location")

	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Println(usage)
		flag.PrintDefaults()
		os.Exit(1)
	}

	vaultPath := flag.Args()[0]
	var v *vault.Vault

	if !*createVault {
		fmt.Print("Password for " + vaultPath + ": ")
		passphrase, err := gopass.GetPasswd()
		if err != nil {
			die(err)
		}
		fmt.Printf("Opening %v...\n", vaultPath)

		v, err = vault.Open(vaultPath, string(passphrase))
		if err != nil {
			if err == filelock.ErrLocked {
				die(fmt.Errorf("%v is open by another masterkey instance! exit that instance first, or remove %v before opening this vault.", vaultPath, vaultPath+".lck"))
			}
			die(err)
		}
		defer v.Close()
	} else {
		fmt.Print("Enter a passphrase for " + vaultPath + ": ")
		passphrase1, err := gopass.GetPasswd()
		if err != nil {
			die(err)
		}
		fmt.Print("Enter the same passphrase again: ")
		passphrase2, err := gopass.GetPasswd()
		if err != nil {
			die(err)
		}
		if string(passphrase1) != string(passphrase2) {
			die(fmt.Errorf("passphrases do not match"))
		}
		v, err = vault.New(string(passphrase1))
		if err != nil {
			die(err)
		}
		err = v.Save(vaultPath)
		if err != nil {
			die(err)
		}
	}

	r := setupRepl(v, vaultPath)
	r.Loop()
}
