package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/NebulousLabs/entropy-mnemonics"
	"github.com/johnathanhowell/passio/repl"
	"github.com/johnathanhowell/passio/vault"
)

var (
	listCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name: "list",
			Action: func(args []string) (string, error) {
				locations, err := v.Locations()
				if err != nil {
					return "", err
				}
				printstring := "Locations stored in this vault: "
				for _, loc := range locations {
					printstring += "\n" + loc
				}
				return printstring, nil
			},
			Usage: "list: list the credentials stored inside this vault",
		}
	}

	saveCmd = func(v *vault.Vault, vaultPath string) repl.Command {
		return repl.Command{
			Name: "save",
			Action: func(args []string) (string, error) {
				if err := v.Save(vaultPath); err != nil {
					return "", err
				}
				return "saved successfully.", nil
			},
			Usage: "save: save the changes in this vault to disk",
		}
	}

	getCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name: "get",
			Action: func(args []string) (string, error) {
				if len(args) == 0 {
					return "", fmt.Errorf("get requires at least one argument. See help for usage.")
				}
				location := args[0]
				cred, err := v.Get(location)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("Username: %v\nPassword: %v", cred.Username, cred.Password), nil
			},
			Usage: "get [location]: get the credential at [location]",
		}
	}

	addCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name: "add",
			Action: func(args []string) (string, error) {
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
			},
			Usage: "add [location] [username] [password]: add a credential to the vault",
		}
	}

	genCmd = func(v *vault.Vault) repl.Command {
		return repl.Command{
			Name: "gen",
			Action: func(args []string) (string, error) {
				if len(args) != 2 {
					return "", fmt.Errorf("gen requires two arguments. See help for usage.")
				}
				location := args[0]
				username := args[1]

				var buf bytes.Buffer
				if _, err := io.CopyN(&buf, rand.Reader, genEntropySize); err != nil {
					return "", err
				}
				phrase, err := mnemonics.ToPhrase(buf.Bytes(), mnemonics.English)
				if err != nil {
					return "", err
				}

				cred := vault.Credential{
					Username: username,
					Password: phrase.String(),
				}

				err = v.Add(location, cred)
				if err != nil {
					return "", err
				}

				return fmt.Sprintf("%v generated successfully", location), nil
			},
			Usage: "gen [location] [username]: generate a password and add it to the vault",
		}
	}
)
