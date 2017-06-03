package repl

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestREPLArgQuotes(t *testing.T) {
	r := New("test >", defaultTimeout)

	var callArgs []string
	r.AddCommand(Command{
		Name: "testcmd",
		Action: func(args []string) (string, error) {
			callArgs = args
			return "success", nil
		},
		Usage: "",
	})

	_, err := r.eval("testcmd \"test arg with quotes and spaces\" testarg2")
	if err != nil {
		t.Fatal(err)
	}

	expectedArgs := []string{"test arg with quotes and spaces", "testarg2"}
	if !reflect.DeepEqual(callArgs, expectedArgs) {
		t.Fatalf("args incorrectly passed to repl command, got %v wanted %v\n", callArgs, expectedArgs)
	}

	_, err = r.eval("testcmd test1 test2 \"test with spaces\"")
	if err != nil {
		t.Fatal(err)
	}
	expectedArgs = []string{"test1", "test2", "test with spaces"}
	if !reflect.DeepEqual(callArgs, expectedArgs) {
		t.Fatalf("args incorrectly passed to repl command, got %v wanted %v\n", callArgs, expectedArgs)
	}
}

// TestREPLTimeout verifies that the REPL exits after its configured timeout
// elapses.
func TestREPLTimeout(t *testing.T) {
	r := New("test >", time.Second*5)
	time.Sleep(time.Second * 6)
	select {
	case <-r.stopChan:
	default:
		t.Fatal("repl was still running after timeout elapsed")
	}

	r = New("test >", time.Second*5)
	r.AddCommand(Command{
		Name: "testcmd",
		Action: func(args []string) (string, error) {
			return "success", nil
		},
		Usage: "",
	})

	time.Sleep(time.Second * 4)
	_, err := r.eval("testcmd")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second * 4)
	select {
	case <-r.stopChan:
		t.Fatal("repl stopped prematurely")
	default:
	}

	r = New("test >", time.Second*5)
	time.Sleep(time.Second * 4)
	_, err = r.eval("")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second * 4)
	select {
	case <-r.stopChan:
		t.Fatal("repl stopped prematurely")
	default:
	}
}

func TestREPLCmd(t *testing.T) {
	r := New("test >", defaultTimeout)

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
	r := New("test >", defaultTimeout)
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
