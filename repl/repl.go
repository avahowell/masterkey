package repl

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type ActionFunc func([]string) (string, error)

type REPL struct {
	usage    string
	prompt   string
	commands map[string]ActionFunc
}

func New(prompt string) *REPL {
	return &REPL{
		commands: make(map[string]ActionFunc),
		prompt:   prompt,
	}
}

func (r *REPL) SetUsage(usage string) {
	r.usage = usage
}

func (r *REPL) AddCommand(command string, action ActionFunc) {
	r.commands[command] = action
}

func (r *REPL) eval(line string) (string, error) {
	args := strings.Split(line, " ")
	command := args[0]

	action, exists := r.commands[command]
	if !exists {
		return "", fmt.Errorf("command not recognized. Type `help` for a list of commands.")
	}

	res, err := action(args[1:])
	if err != nil {
		return "", err
	}

	return res, nil
}

func (r *REPL) Loop() error {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(r.prompt)
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.Replace(line, "\n", "", -1)
		if line != "\n" {
			res, err := r.eval(line)
			if err != nil {
				fmt.Println("error: ", err.Error())
				continue
			}
			fmt.Println(res)
		}
	}
}
