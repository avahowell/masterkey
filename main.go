package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/avahowell/masterkey/filelock"
	"github.com/avahowell/masterkey/repl"
	"github.com/avahowell/masterkey/secureclip"
	"github.com/avahowell/masterkey/vault"

	"golang.org/x/crypto/ssh/terminal"
)

const usage = `Usage: masterkey [-new] vault`

func die(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func askPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	pw, err := terminal.ReadPassword(0)
	fmt.Println()
	return string(pw), err
}

func setupRepl(v *vault.Vault, vaultPath string, timeout time.Duration) *repl.REPL {
	r := repl.New(fmt.Sprintf("masterkey [%v] > ", vaultPath), timeout)

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
	r.AddCommand(mergeCmd(v))

	r.OnStop(func() {
		fmt.Println("clearing clipboard and saving vault")
		secureclip.Clear()
		v.Save(vaultPath)
	})

	return r
}

func main() {
	createVault := flag.Bool("new", false, "whether to create a new vault at the specified location")
	timeout := flag.Duration("timeout", time.Minute*5, "how long to wait with no vault activity before exiting")

	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Println(usage)
		flag.PrintDefaults()
		os.Exit(1)
	}

	vaultPath := flag.Args()[0]
	var v *vault.Vault

	if !*createVault {
		passphrase, err := askPassword("Password for " + vaultPath + ": ")
		if err != nil {
			die(err)
		}
		fmt.Printf("Opening %v...\n", vaultPath)

		v, err = vault.Open(vaultPath, passphrase)
		if err != nil {
			if err == filelock.ErrLocked {
				die(fmt.Errorf("%v is open by another masterkey instance! exit that instance first, or remove %v before opening this vault.", vaultPath, vaultPath+".lck"))
			}
			die(err)
		}
		defer v.Close()
	} else {
		passphrase1, err := askPassword("Enter a passphrase for " + vaultPath + ": ")
		if err != nil {
			die(err)
		}
		passphrase2, err := askPassword("Enter the same passphrase again: ")
		if err != nil {
			die(err)
		}
		if passphrase1 != passphrase2 {
			die(fmt.Errorf("passphrases do not match"))
		}
		v, err = vault.New(passphrase1)
		if err != nil {
			die(err)
		}
		err = v.Save(vaultPath)
		if err != nil {
			die(err)
		}
	}

	r := setupRepl(v, vaultPath, *timeout)
	r.Loop()
}
