package repl

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

type (
	// REPL is a read-eval-print loop used to create a simple, minimalistic,
	// easy-to-use command line interface for masterkey.
	REPL struct {
		prompt   string
		commands map[string]Command
		input    io.Reader
		output   io.Writer
		stopfunc func()

		stopchan chan struct{}
	}

	// Command is a command that can be registered with the REPL. It consists
	// of a name, an action that is run when the name is input to the REPL, and
	// a usage string.
	Command struct {
		Name   string
		Action ActionFunc
		Usage  string
	}

	// ActionFunc defines the signature of an action associated with a command.
	// Actions take on parameter, a slice of strings, representing the arguments
	// passed to the command. Actions should return a string representing the
	// result of the action, or an error if the action fails.
	ActionFunc func([]string) (string, error)
)

// New instantiates a new REPL using the provided `prompt`.
func New(prompt string) *REPL {
	return &REPL{
		commands: make(map[string]Command),
		prompt:   prompt,
		stopchan: make(chan struct{}),
		input:    os.Stdin,
		output:   os.Stdout,
	}
}

// OnStop registers a function to be called when the REPL stops.
func (r *REPL) OnStop(sf func()) {
	r.stopfunc = sf
}

// Usage returns the usage for every command in the REPL.
func (r *REPL) Usage() string {
	buf := new(bytes.Buffer)
	for _, command := range r.commands {
		fmt.Fprintln(buf, command.Usage)
	}
	return buf.String()
}

// Stop terminates the REPL.
func (r *REPL) Stop() {
	if r.stopfunc != nil {
		r.stopfunc()
	}
	close(r.stopchan)
}

// AddCommand registers the command provided in `cmd` with the REPL.
func (r *REPL) AddCommand(cmd Command) {
	r.commands[cmd.Name] = cmd
}

// eval evaluates a line that was input to the REPL.
func (r *REPL) eval(line string) (string, error) {
	args := strings.Split(line, " ")
	command := args[0]

	if command == "help" {
		return r.Usage(), nil
	}

	if command == "exit" {
		r.Stop()
		return "", nil
	}

	cmd, exists := r.commands[command]
	if !exists {
		return "", fmt.Errorf("command not recognized. Type `help` for a list of commands.")
	}

	res, err := cmd.Action(args[1:])
	if err != nil {
		return "", err
	}

	return res, nil
}

// Loop starts the Read-Eval-Print loop.
func (r *REPL) Loop() error {
	msgchan := make(chan string)

	go func() {
		scanner := bufio.NewScanner(r.input)
		for scanner.Scan() {
			msgchan <- scanner.Text()
		}
	}()

	for {
		fmt.Fprint(r.output, r.prompt)
		select {
		case <-r.stopchan:
			return nil
		case line := <-msgchan:
			if line != "" {
				res, err := r.eval(line)
				if err != nil {
					fmt.Fprintln(r.output, err.Error())
					continue
				}
				fmt.Fprintln(r.output, res)
			}
		}
	}
}
