package repl

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/chzyer/readline"
	"github.com/mattn/go-shellwords"
)

const defaultTimeout = time.Hour

type (
	// REPL is a read-eval-print loop used to create a simple, minimalistic,
	// easy-to-use command line interface for masterkey, with an automatic
	// timeout that exits the program after a specified duration.
	REPL struct {
		prompt          string
		stopChan        chan struct{}
		commands        map[string]Command
		prefixCompleter *readline.PrefixCompleter
		input           io.Reader
		output          io.Writer
		rl              *readline.Instance
		stopfunc        func()
		lastCommandTime int64
		timeout         time.Duration
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

// New instantiates a new REPL using the provided `prompt` and `timeout`.
func New(prompt string, timeout time.Duration) *REPL {
	r := &REPL{
		commands:        make(map[string]Command),
		prompt:          prompt,
		input:           os.Stdin,
		output:          os.Stdout,
		timeout:         timeout,
		lastCommandTime: time.Now().Unix(),
		stopChan:        make(chan struct{}),
	}

	// Add default commands clear, exit, and help
	r.AddCommand(Command{
		Name:  "help",
		Usage: "help: displays available commands and their usage",
		Action: func(args []string) (string, error) {
			return r.Usage(), nil
		},
	})

	r.AddCommand(Command{
		Name:  "exit",
		Usage: "exit: exit the interactive prompt",
		Action: func(args []string) (string, error) {
			return "", r.Stop()
		},
	})

	r.AddCommand(Command{
		Name:  "clear",
		Usage: "clear: clear the terminal",
		Action: func(args []string) (string, error) {
			readline.ClearScreen(r.output)
			return "cleared terminal", nil
		},
	})

	return r
}

// Stop exits the REPL and runs the configured `OnStop` func, if one exists.
func (r *REPL) Stop() error {
	close(r.stopChan)
	if r.stopfunc != nil {
		r.stopfunc()
	}
	return nil
}

// OnStop registers a function to be called when the REPL stops.
func (r *REPL) OnStop(sf func()) {
	r.stopfunc = sf
}

// Usage returns the usage for every command in the REPL.
func (r *REPL) Usage() string {
	printstring := ""
	for _, command := range r.commands {
		printstring += command.Usage + "\n"
	}
	return printstring
}

// AddCommand registers the command provided in `cmd` with the REPL.
func (r *REPL) AddCommand(cmd Command) {
	r.commands[cmd.Name] = cmd

	var completers []readline.PrefixCompleterInterface
	for name := range r.commands {
		completers = append(completers, readline.PcItem(name))
	}

	r.prefixCompleter = readline.NewPrefixCompleter(completers...)
}

// eval evaluates a line that was input to the REPL.
func (r *REPL) eval(line string) (string, error) {
	atomic.StoreInt64(&r.lastCommandTime, time.Now().Unix())
	if line == "" {
		return "", nil
	}
	args, err := shellwords.Parse(line)
	if err != nil {
		return "", err
	}
	command := args[0]

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
	rl, err := readline.NewEx(&readline.Config{
		Prompt:       r.prompt,
		AutoComplete: r.prefixCompleter,
	})
	if err != nil {
		return err
	}
	r.rl = rl

	type result struct {
		line string
		err  error
	}

	for {
		lineresult := make(chan result)
		go func() {
			line, err := r.rl.Readline()
			lineresult <- result{line, err}
		}()
		select {
		case <-r.stopChan:
			return nil
		case <-time.After(r.timeout):
			r.Stop()
		case input := <-lineresult:
			if input.err != nil {
				if input.err == readline.ErrInterrupt {
					r.Stop()
				}
				break
			}
			res, err := r.eval(input.line)
			if err != nil {
				fmt.Fprintln(r.output, err.Error())
				continue
			}
			fmt.Fprint(r.output, res)
		}
	}
	return nil
}
