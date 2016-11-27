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
	"github.com/NebulousLabs/entropy-mnemonics"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	scryptN        = 16384
	scryptR        = 8
	scryptP        = 1
	keyLen         = 32
	genEntropySize = 16
)

var (
	// ErrNoSuchCredential is returned from a Get call if the requested
	// credential does not exist
	ErrNoSuchCredential = errors.New("credential at specified location does not exist in vault")

	// ErrCouldNotDecrypt is returned if secretbox decryption fails.
	ErrCouldNotDecrypt = errors.New("provided decryption key is incorrect or the provided vault is corrupt")

	// ErrCredentialExists is returned from Add if a credential already exists
	// at the provided location.
	ErrCredentialExists = errors.New("credential at specified location already exists")
)

type (
	// Vault is a secure password vault. It can be created by calling New()
	// with a passphrase. Passwords, usernames, and locations are encrypted
	// using nacl/secretbox.
	Vault struct {
		data   []byte
		nonce  [24]byte
		secret [32]byte
	}

	// Credential defines a Username and Password, and a map of Metadata to store
	// inside the vault.
	Credential struct {
		Username string
		Password string

		Meta map[string]string
	}
)

// New creates a new, empty, vault using the passphrase provided to
// `passphrase`.
func New(passphrase string) (*Vault, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	var secret [32]byte
	key, err := scrypt.Key([]byte(passphrase), nonce[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		panic(err)
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

// Open reads a vault from the location provided to `filename` and decrypts
// it using `passphrase`. If decryption succeeds, new nonce is chosen and the
// vault is re-encrypted, ensuring nonces are unique and not reused across
// sessions.
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
		panic(err)
	}

	key, err = scrypt.Key([]byte(passphrase), nonce[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		panic(err)
	}
	copy(secret[:], key)

	vault.secret = secret
	vault.nonce = nonce
	if err = vault.encrypt(creds); err != nil {
		return nil, err
	}

	return vault, nil
}

// Generate generates a new strong mnemonic passphrase and Add()s it to the
// vault.
func (v *Vault) Generate(location string, username string) error {
	buf := new(bytes.Buffer)
	_, err := io.CopyN(buf, rand.Reader, genEntropySize)
	if err != nil {
		panic(err)
	}
	phrase, err := mnemonics.ToPhrase(buf.Bytes(), mnemonics.English)
	if err != nil {
		return err
	}

	cred := Credential{
		Username: username,
		Password: phrase.String(),
	}

	err = v.Add(location, cred)
	if err != nil {
		return err
	}
	return nil
}

// decrypt decrypts the vault and returns the credential data as a map of
// strings (locations) to Credentials.
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

// encrypt encrypts the supplied credential map and updates the vault's
// encrypted data.
func (v *Vault) encrypt(creds map[string]*Credential) error {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(creds)
	if err != nil {
		return err
	}

	v.data = secretbox.Seal(v.nonce[:], buf.Bytes(), &v.nonce, &v.secret)

	return nil
}

// Add adds the credential provided to `credential` at the location provided
// by `location` to the vault.
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

// Get retrieves a Credential at the provided `location`.
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

// Save safely (atomically) persists the vault to disk at the filename
// provided to `filename`.
func (v *Vault) Save(filename string) error {
	tempfile, err := ioutil.TempFile(path.Dir(filename), "masterkey-temp")
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

// Edit replaces the credential at location with the provided `credential`.
func (v *Vault) Edit(location string, credential Credential) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	if _, ok := creds[location]; !ok {
		return ErrNoSuchCredential
	}

	creds[location] = &credential

	err = v.encrypt(creds)
	if err != nil {
		return err
	}

	return nil
}

// Delete removes the credential at `location`.
func (v *Vault) Delete(location string) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	if _, exists := creds[location]; !exists {
		return ErrNoSuchCredential
	}

	delete(creds, location)

	err = v.encrypt(creds)
	if err != nil {
		return err
	}

	return nil
}

// AddMeta adds a meta tag to the credential in the vault at `location`. `name`
// is used for the name of the meta tag and `value` is used as its value.
func (v *Vault) AddMeta(location string, name string, value string) error {
	cred, err := v.Get(location)
	if err != nil {
		return err
	}
	cred.AddMeta(name, value)
	return v.Edit(location, *cred)
}

// Locations retrieves the locations in the vault and returns them as a
// slice of strings.
func (v *Vault) Locations() ([]string, error) {
	var locations []string
	creds, err := v.decrypt()
	if err != nil {
		return locations, err
	}

	for location := range creds {
		locations = append(locations, location)
	}
	return locations, nil
}

// AddMeta adds a meta tag to a Credential.
func (c *Credential) AddMeta(metaname, metavalue string) {
	if c.Meta == nil {
		c.Meta = make(map[string]string)
	}
	c.Meta[metaname] = metavalue
}
