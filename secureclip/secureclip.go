package secureclip

import (
	"sync"
	"time"

	"github.com/atotto/clipboard"
)

var (
	lastClip     = time.Now()
	lastClipLock sync.Mutex
	clipTimeout  = time.Second * 30
)

func getLastClip() time.Time {
	lastClipLock.Lock()
	t := lastClip
	lastClipLock.Unlock()
	return t
}

func setLastClip(t time.Time) {
	lastClipLock.Lock()
	lastClip = t
	lastClipLock.Unlock()
}

// Clip copies the passphrase given by `passphrase` to the clipboard. The
// clipboard will be cleared 30 seconds after the last `Clip` call.
func Clip(passphrase string) error {
	err := clipboard.WriteAll(passphrase)
	if err != nil {
		return err
	}
	setLastClip(time.Now())
	go func() {
		time.Sleep(clipTimeout)
		if time.Since(getLastClip()) > clipTimeout {
			clipboard.WriteAll("")
		}
	}()
	return nil
}

// Clear clears the clipboard.
func Clear() error {
	return clipboard.WriteAll("")
}
