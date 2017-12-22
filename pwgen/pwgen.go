package pwgen

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	// CharsetAlpha defines a character set containing only letters.
	CharsetAlpha = []byte("abcdefghijklmnopqrstuvwxyz")
	// CharsetAlphaNum defines a character set containing letters and numbers.
	CharsetAlphaNum = []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	// CharsetAlphaNumSpecial defines a character set containing letters,
	// numbers, and special characters.
	CharsetAlphaNumSpecial = []byte("abcdefghijklmnopqrstuvwxyz0123456789{}_*()&^%$@!\\<>;'|[]=+-`~,.?")

	errBadLength           = errors.New("length argument must be greater than zero")
	errInsufficientEntropy = errors.New("charset has insufficient entropy")
)

// GeneratePassphrase creates a new random passphrase with the length defined
// by `length` using the characters defined by charset.
func GeneratePassphrase(charset []byte, length uint) (string, error) {
	if length == 0 {
		return "", errBadLength
	}
	var res string
	for i := uint(0); i < length; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		res += string(charset[randIndex.Uint64()])
	}
	return res, nil
}
