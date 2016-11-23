package main

import (
	"fmt"

	"github.com/johnathanhowell/masterkey/repl"
	"github.com/johnathanhowell/masterkey/vault"
)

var (
	listCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name:   "list",
			Action: list(v),
			Usage:  "list: list the credentials stored inside this vault",
		}
	}

	saveCmd = func(v *vault.Vault, vaultPath string) repl.Command {
		return repl.Command{
			Name:   "save",
			Action: save(v, vaultPath),
			Usage:  "save: save the changes in this vault to disk",
		}
	}

	getCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name:   "get",
			Action: get(v),
			Usage:  "get [location]: get the credential at [location]",
		}
	}

	addCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name:   "add",
			Action: add(v),
			Usage:  "add [location] [username] [password]: add a credential to the vault",
		}
	}

	genCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name:   "gen",
			Action: gen(v),
			Usage:  "gen [location] [username]: generate a password and add it to the vault",
		}
	}
)

func list(v *vault.Vault) repl.ActionFunc {
	return func(args []string) (string, error) {
		locations, err := v.Locations()
		if err != nil {
			return "", err
		}
		printstring := "Locations stored in this vault: "
		for _, loc := range locations {
			printstring += "\n" + loc
		}
		return printstring, nil
	}
}

func save(v *vault.Vault, savePath string) repl.ActionFunc {
	return func(args []string) (string, error) {
		if err := v.Save(savePath); err != nil {
			return "", err
		}
		return "saved successfully", nil
	}
}

func get(v *vault.Vault) repl.ActionFunc {
	return func(args []string) (string, error) {
		if len(args) == 0 {
			return "", fmt.Errorf("get requires at least one argument. See help for usage.")
		}
		location := args[0]
		cred, err := v.Get(location)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("Username: %v\nPassword: %v", cred.Username, cred.Password), nil
	}
}

func add(v *vault.Vault) repl.ActionFunc {
	return func(args []string) (string, error) {
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
	}
}

func gen(v *vault.Vault) repl.ActionFunc {
	return func(args []string) (string, error) {
		if len(args) != 2 {
			return "", fmt.Errorf("gen requires two arguments. See help for usage.")
		}

		location := args[0]
		username := args[1]

		if err := v.Generate(location, username); err != nil {
			return "", err
		}

		return fmt.Sprintf("%v generated successfully", location), nil
	}
}
