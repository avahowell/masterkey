package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/howeyc/gopass"
	"github.com/johnathanhowell/passio/repl"
	"github.com/johnathanhowell/passio/vault"
)

const usage = `Usage: passio [-new] vault`
const REPLhelp = `Available Commands:
get [location]: decrypt and print the credential at location
`

func die(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func startRepl(v *vault.Vault) {
	r := repl.New("passio > ")
	r.SetUsage(REPLhelp)
	r.AddCommand("list", func(args []string) (string, error) {
		locations, err := v.Locations()
		if err != nil {
			return "", err
		}
		printstring := "Locations stored in this vault: "
		for _, loc := range locations {
			printstring += "\n" + loc
		}
		return printstring, nil
	})
	r.AddCommand("save", func(args []string) (string, error) {
		if err := v.Save("pass.db"); err != nil {
			return "", err
		}
		return "saved successfully.", nil
	})
	r.AddCommand("get", func(args []string) (string, error) {
		if len(args) == 0 {
			return "", fmt.Errorf("get requires at least one argument. See help for usage.")
		}
		location := args[0]
		cred, err := v.Get(location)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Username: %v\nPassword: %v", cred.Username, cred.Password), nil
	})
	r.AddCommand("add", func(args []string) (string, error) {
		if len(args) != 3 {
			return "", fmt.Errorf("add requires at least three arguments. See help for usage.")
		}
		location := args[0]
		username := args[1]
		password := args[2]
		cred := vault.Credential{
			Username: username,
			Password: password,
		}
		err := v.Add(location, cred)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%v added successfully", location), nil
	})
	r.Loop()
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

	if *createVault {
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
		v, err := vault.New(string(passphrase1))
		if err != nil {
			die(err)
		}
		err = v.Save(vaultPath)
		if err != nil {
			die(err)
		}
		return
	}

	fmt.Print("Password for " + vaultPath + ": ")
	passphrase, err := gopass.GetPasswd()
	if err != nil {
		die(err)
	}
	fmt.Printf("Opening %v...\n", vaultPath)

	v, err := vault.Open(vaultPath, string(passphrase))
	if err != nil {
		die(err)
	}

	startRepl(v)
}
