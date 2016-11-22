package repl

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestREPLLoop(t *testing.T) {
	r := New("test >")

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	r.input = stdin
	r.output = stdout

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		r.Loop()
	}()

	time.Sleep(100 * time.Millisecond)
	if stdout.String() != "test >" {
		t.Fatal("repl loop did not print the expected prompt")
	}

	stdout.Reset()
	r.Stop()

	<-stopped
}

func TestREPLCmd(t *testing.T) {
	r := New("test >")

	called := false
	var callArgs []string
	r.AddCommand(Command{
		Name: "testcmd",
		Action: func(args []string) (string, error) {
			callArgs = args
			called = true
			return "success", nil
		},
		Usage: "test usage",
	})

	res, err := r.eval("testcmd arg1 arg2")
	if err != nil {
		t.Fatal(err)
	}
	if res != "success" {
		t.Fatal("eval returned the wrong result")
	}
	if !called {
		t.Fatal("testcmd did not set called")
	}
	if callArgs[1] != "arg2" || callArgs[0] != "arg1" {
		t.Fatal("testcmd did not have the correct args")
	}
}

func TestREPLCmdError(t *testing.T) {
	r := New("test >")
	testerr := errors.New("testerr")

	r.AddCommand(Command{
		Name: "testcmd",
		Action: func(args []string) (string, error) {
			return "", testerr
		},
		Usage: "testusage",
	})

	res, err := r.eval("testcmd")
	if err != testerr {
		t.Fatal("testcmd did not return testerr")
	}
	if res != "" {
		t.Fatal("result string was not empty")
	}

}
