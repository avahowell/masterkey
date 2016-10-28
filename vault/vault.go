package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"

	"encoding/gob"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	scryptN = 16384
	scryptR = 8
	scryptP = 1
	keyLen  = 32
)

var (
	ErrNoSuchCredential = errors.New("credential at specified location does not exist in vault")
	ErrCouldNotDecrypt  = errors.New("provided decryption key is incorrect or the provided vault is corrupt")
)

// Vault is an atomic, consistent, and durable password database, using NACL
// secretbox.
type Vault struct {
	credentials map[string]*Credential
	secret      [32]byte
	nonce       [24]byte
}

type Credential struct {
	Username string
	Password string
}

func New(passphrase string) (*Vault, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	var secret [32]byte
	key, err := scrypt.Key([]byte(passphrase), nonce[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}
	copy(secret[:], key)

	return &Vault{
		credentials: make(map[string]*Credential),
		nonce:       nonce,
		secret:      secret,
	}, nil
}

func (v *Vault) Add(location string, credential Credential) {
	v.credentials[location] = &credential
}

func (v *Vault) Get(location string) (*Credential, error) {
	cred, ok := v.credentials[location]
	if !ok {
		return nil, ErrNoSuchCredential
	}
	return cred, nil
}

func (v *Vault) Save(filename string) error {
	var credentialData bytes.Buffer
	err := gob.NewEncoder(&credentialData).Encode(v.credentials)
	if err != nil {
		return err
	}

	encrypted := secretbox.Seal(v.nonce[:], credentialData.Bytes(), &v.nonce, &v.secret)

	tempfile, err := ioutil.TempFile(path.Dir(filename), "passio-temp")
	if err != nil {
		return err
	}

	_, err = io.Copy(tempfile, bytes.NewBuffer(encrypted))
	if err != nil {
		return err
	}

	err = os.Rename(tempfile.Name(), filename)
	if err != nil {
		return err
	}

	return nil
}

func Open(filename string, passphrase string) (*Vault, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var encryptedData bytes.Buffer
	_, err = io.Copy(&encryptedData, f)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], encryptedData.Bytes()[:24])

	key, err := scrypt.Key([]byte(passphrase), nonce[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}

	var secret [32]byte
	copy(secret[:], key)

	decryptedData, success := secretbox.Open([]byte{}, encryptedData.Bytes()[24:], &nonce, &secret)
	if !success {
		return nil, ErrCouldNotDecrypt
	}

	credentials := make(map[string]*Credential)
	err = gob.NewDecoder(bytes.NewBuffer(decryptedData)).Decode(&credentials)
	if err != nil {
		return nil, err
	}

	var newnonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	var newsecret [32]byte
	key, err = scrypt.Key([]byte(passphrase), newnonce[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}
	copy(newsecret[:], key)

	return &Vault{
		credentials: credentials,
		nonce:       newnonce,
		secret:      newsecret,
	}, nil
}
