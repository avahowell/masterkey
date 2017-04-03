package filelock

import (
	"testing"
)

func TestFilelockContention(t *testing.T) {
	lock, err := Lock("test.lck")
	if err != nil {
		t.Fatal(err)
	}

	_, err = Lock("test.lck")
	if err != ErrLocked {
		t.Fatal("expected Lock call on existing lockfile to fail")
	}

	err = lock.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	lock, err = Lock("test.lck")
	if err != nil {
		t.Fatal(err)
	}

	err = lock.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}
