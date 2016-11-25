package secureclip

import (
	"time"

	"github.com/atotto/clipboard"
)

var (
	lastClip    = time.Now()
	clipTimeout = time.Second * 30
)

// Clip copies the passphrase given by `passphrase` to the clipboard. The
// clipboard will be cleared 30 seconds after the last `Clip` call.
func Clip(passphrase string) error {
	err := clipboard.WriteAll(passphrase)
	if err != nil {
		return err
	}
	lastClip = time.Now()
	go func() {
		time.Sleep(clipTimeout)
		if time.Since(lastClip) > clipTimeout {
			clipboard.WriteAll("")
		}
	}()
	return nil
}
