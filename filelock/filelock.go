package filelock

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrLocked is returned from Lock if a Lock is called on an existing LockFile
var ErrLocked = errors.New("specified lockfile is locked")

// FileLock is a handle to an on-disk file lock.
type FileLock struct {
	path string
}

// Lock attempts to acquire a lock on the file at `filename`. Returns an error
// if a lock has already been created.
func Lock(filename string) (*FileLock, error) {
	absolutePath, err := filepath.Abs(filename + ".lck")
	if err != nil {
		return nil, err
	}

	if _, err = os.Stat(absolutePath); err == nil {
		return nil, ErrLocked
	}

	_, err = os.Create(absolutePath)
	if err != nil {
		return nil, err
	}

	return &FileLock{
		path: absolutePath,
	}, nil
}

// Unlock unlocks the FileLock.
func (fl *FileLock) Unlock() error {
	return os.Remove(fl.path)
}
