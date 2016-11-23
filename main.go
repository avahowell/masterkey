package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/howeyc/gopass"
	"github.com/johnathanhowell/masterkey/repl"
	"github.com/johnathanhowell/masterkey/vault"
)

const (
	genEntropySize = 16
	usage          = `Usage: masterkey [-new] vault`
)

func die(err error) {
	fmt.Println(err)
	os.Exit(1)
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
			die(err)
		}
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

	r := repl.New("masterkey > ")

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, os.Kill)
	go func() {
		<-sigchan
		fmt.Println("\nCaught quit signal, saving vault")
		err := v.Save(vaultPath)
		if err != nil {
			fmt.Printf("error saving vault: %v\n", err)
		}
		r.Stop()
	}()

	r.AddCommand(listCmd(v))
	r.AddCommand(saveCmd(v, vaultPath))
	r.AddCommand(getCmd(v))
	r.AddCommand(addCmd(v))
	r.AddCommand(genCmd(v))

	r.Loop()
}
