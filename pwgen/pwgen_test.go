package pwgen

import (
	"testing"
)

func TestGeneratePassphrase(t *testing.T) {
	tests := []struct {
		length      uint
		charset     []byte
		expectedErr error
	}{
		{0, CharsetAlpha, errBadLength},
		{32, CharsetAlphaNum, nil},
	}
	for _, test := range tests {
		if _, err := GeneratePassphrase(test.charset, test.length); err != test.expectedErr {
			t.Fatal("unexpected result, got", err, "wanted", test.expectedErr)
		}
	}
}
