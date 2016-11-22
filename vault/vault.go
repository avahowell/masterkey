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
	ErrCredentialExists = errors.New("credential at specified location already exists")
)

// Vault is an atomic, consistent, and durable password database, using NACL
// secretbox.
type Vault struct {
	data   []byte
	nonce  [24]byte
	secret [32]byte
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

	v := &Vault{
		nonce:  nonce,
		secret: secret,
	}

	err = v.encrypt(make(map[string]*Credential))
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (v *Vault) decrypt() (map[string]*Credential, error) {
	decryptedData, success := secretbox.Open([]byte{}, v.data[len(v.nonce):], &v.nonce, &v.secret)
	if !success {
		return nil, ErrCouldNotDecrypt
	}

	credentials := make(map[string]*Credential)
	err := gob.NewDecoder(bytes.NewBuffer(decryptedData)).Decode(&credentials)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

func (v *Vault) encrypt(creds map[string]*Credential) error {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(creds)
	if err != nil {
		return err
	}

	v.data = secretbox.Seal(v.nonce[:], buf.Bytes(), &v.nonce, &v.secret)

	return nil
}

func (v *Vault) Add(location string, credential Credential) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	if _, exists := creds[location]; exists {
		return ErrCredentialExists
	}

	creds[location] = &credential

	err = v.encrypt(creds)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) Get(location string) (*Credential, error) {
	creds, err := v.decrypt()
	if err != nil {
		return nil, err
	}

	cred, ok := creds[location]
	if !ok {
		return nil, ErrNoSuchCredential
	}
	return cred, nil
}

func (v *Vault) Save(filename string) error {
	tempfile, err := ioutil.TempFile(path.Dir(filename), "passio-temp")
	if err != nil {
		return err
	}

	_, err = io.Copy(tempfile, bytes.NewBuffer(v.data))
	if err != nil {
		return err
	}

	err = os.Rename(tempfile.Name(), filename)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) Locations() ([]string, error) {
	var locations []string
	creds, err := v.decrypt()
	if err != nil {
		return locations, err
	}

	for location, _ := range creds {
		locations = append(locations, location)
	}
	return locations, nil
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

	vault := &Vault{
		data:   encryptedData.Bytes(),
		nonce:  nonce,
		secret: secret,
	}

	creds, err := vault.decrypt()
	if err != nil {
		return nil, err
	}

	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	key, err = scrypt.Key([]byte(passphrase), nonce[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}
	copy(secret[:], key)

	vault.secret = secret
	vault.nonce = nonce
	if err = vault.encrypt(creds); err != nil {
		return nil, err
	}

	return vault, nil
}
