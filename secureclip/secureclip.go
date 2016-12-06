package secureclip

import (
	"sync/atomic"
	"time"

	"github.com/atotto/clipboard"
)

var (
	lastClip    = time.Now().Unix()
	clipTimeout = time.Second * 30
)

// Clip copies the passphrase given by `passphrase` to the clipboard. The
// clipboard will be cleared 30 seconds after the last `Clip` call.
func Clip(passphrase string) error {
	err := clipboard.WriteAll(passphrase)
	if err != nil {
		return err
	}
	atomic.StoreInt64(&lastClip, time.Now().Unix())
	go func() {
		time.Sleep(clipTimeout)
		lc := atomic.LoadInt64(&lastClip)
		if time.Since(time.Unix(lc, 0)) > clipTimeout {
			clipboard.WriteAll("")
		}
	}()
	return nil
}

// Clear clears the clipboard.
func Clear() error {
	return clipboard.WriteAll("")
}
