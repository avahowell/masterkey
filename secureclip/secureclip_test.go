package secureclip

import (
	"testing"
	"time"

	"github.com/atotto/clipboard"
)

func TestSecureClip(t *testing.T) {
	clipTimeout = time.Second * 3
	err := Clip("test")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(clipTimeout + time.Second)
	contents, err := clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if contents != "" {
		t.Fatal("did not clear clipboard contents after timeout")
	}
}

func TestSecureClipStaggeredCalls(t *testing.T) {
	clipTimeout = time.Second * 2
	if err := Clip("test1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if err := Clip("test2"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	contents, err := clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if contents != "test2" {
		t.Fatal("clipboard prematurely cleared")
	}
	time.Sleep(time.Second * 2)
	contents, err = clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if contents != "" {
		t.Fatal("clipboard was not cleared")
	}
}
