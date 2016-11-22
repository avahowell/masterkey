package repl

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Command struct {
	Name   string
	Action ActionFunc
	Usage  string
}

type ActionFunc func([]string) (string, error)

type REPL struct {
	usage    string
	prompt   string
	commands map[string]ActionFunc

	stopchan chan struct{}
}

func New(prompt string) *REPL {
	return &REPL{
		commands: make(map[string]ActionFunc),
		prompt:   prompt,
		stopchan: make(chan struct{}),
	}
}

func (r *REPL) Stop() {
	close(r.stopchan)
}

func (r *REPL) AddCommand(cmd Command) {
	r.commands[cmd.Name] = cmd.Action
	r.usage = r.usage + cmd.Usage + "\n"
}

func (r *REPL) eval(line string) (string, error) {
	args := strings.Split(line, " ")
	command := args[0]

	if command == "help" {
		return r.usage, nil
	}

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
	msgchan := make(chan string)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			line, _ := reader.ReadString('\n')
			msgchan <- line
		}
	}()

	for {
		fmt.Print(r.prompt)
		select {
		case <-r.stopchan:
			return nil
		case line := <-msgchan:
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
}
