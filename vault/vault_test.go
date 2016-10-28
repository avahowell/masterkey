package vault

import (
	"reflect"
	"testing"
)

func TestNewSaveOpen(t *testing.T) {
	testCredential := Credential{"testuser", "testpass"}

	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	v.Add("testlocation", testCredential)
	err = v.Save("pass.db")
	if err != nil {
		t.Fatal(err)
	}
	vopen, err := Open("pass.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := vopen.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&testCredential, credential) {
		t.Fatalf("vault did not store credential correctly. wanted %v got %v", testCredential, credential)
	}

	_, err = Open("pass.db", "wrongpass")
	if err != ErrCouldNotDecrypt {
		t.Fatal("Open decrypted given an incorrect passphrase")
	}
}

func TestNonceRotation(t *testing.T) {
	testCredential := Credential{"testuser", "testpass"}

	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	oldnonce := v.nonce
	oldsecret := v.secret

	v.Add("testlocation", testCredential)
	err = v.Save("pass.db")
	if err != nil {
		t.Fatal(err)
	}
	vopen, err := Open("pass.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	if vopen.secret == oldsecret {
		t.Fatal("opened vault had the same secret as the previous vault")
	}
	if vopen.nonce == oldnonce {
		t.Fatal("opened vault had the same nonce as the previous vault")
	}
}
