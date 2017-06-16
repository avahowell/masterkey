package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/johnathanhowell/masterkey/filelock"

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

	// ErrMetaExists is returned from AddMeta if a meta tag already exists.
	ErrMetaExists = errors.New("meta tag already exists")

	// ErrMetaDoesNotExist is returned from Editmeta if a meta tag does not
	// exist.
	ErrMetaDoesNotExist = errors.New("meta tag does not exist")
)

type (
	// Vault is a secure password vault. It can be created by calling New()
	// with a passphrase. Passwords, usernames, and locations are encrypted
	// using nacl/secretbox.
	Vault struct {
		data   []byte
		nonce  [24]byte
		salt   [24]byte
		secret [32]byte
		lock   *filelock.FileLock
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
	var nonce, salt [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		panic(err)
	}

	var secret [32]byte
	key, err := scrypt.Key([]byte(passphrase), salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		panic(err)
	}
	copy(secret[:], key)

	v := &Vault{
		nonce:  nonce,
		salt:   salt,
		secret: secret,
	}

	err = v.encrypt(make(map[string]*Credential))
	if err != nil {
		return nil, err
	}

	return v, nil
}

func openVaultCompat(filename, passphrase string) (*Vault, error) {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], bs[:24])

	key, err := scrypt.Key([]byte(passphrase), nonce[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}

	var secret [32]byte
	copy(secret[:], key)

	vault := &Vault{
		data:   bs,
		nonce:  nonce,
		salt:   nonce,
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

func openVault(filename, passphrase string) (*Vault, error) {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var salt, nonce [24]byte
	copy(salt[:], bs[:24])
	copy(nonce[:], bs[24:48])

	key, err := scrypt.Key([]byte(passphrase), salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}

	var secret [32]byte
	copy(secret[:], key)

	vault := &Vault{
		data:   bs[len(salt):],
		nonce:  nonce,
		secret: secret,
		salt:   salt,
	}

	creds, err := vault.decrypt()
	if err != nil {
		return nil, err
	}

	_, err = io.ReadFull(rand.Reader, vault.salt[:])
	if err != nil {
		panic(err)
	}

	key, err = scrypt.Key([]byte(passphrase), vault.salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}
	copy(vault.secret[:], key)

	err = vault.encrypt(creds)
	if err != nil {
		return nil, err
	}

	return vault, nil
}

// Open reads a vault from the location provided to `filename` and decrypts
// it using `passphrase`. If decryption succeeds, new nonce is chosen and the
// vault is re-encrypted, ensuring nonces are unique and not reused across
// sessions.
func Open(filename string, passphrase string) (*Vault, error) {
	lock, err := filelock.Lock(filename)
	if err != nil {
		return nil, err
	}
	vault, err := openVault(filename, passphrase)
	if err != nil {
		vault, err = openVaultCompat(filename, passphrase)
		if err != nil {
			lock.Unlock()
			return nil, err
		}
	}
	vault.lock = lock

	return vault, nil
}

// Close releases the lock acquired by calling Open() on a vault.
func (v *Vault) Close() error {
	if v.lock != nil {
		return v.lock.Unlock()
	}
	return nil
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
	if _, err = io.ReadFull(rand.Reader, v.nonce[:]); err != nil {
		panic(err)
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

	return v.encrypt(creds)
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
	defer tempfile.Close()

	_, err = tempfile.Write(v.salt[:])
	if err != nil {
		return err
	}
	_, err = tempfile.Write(v.data)
	if err != nil {
		return err
	}

	err = tempfile.Sync()
	if err != nil {
		return err
	}

	err = tempfile.Close()
	if err != nil {
		return err
	}

	err = os.Rename(tempfile.Name(), filename)
	if err != nil {
		return err
	}

	return nil
}

// Edit replaces the credential at location with the provided `credential`. The
// metadata from the old credential is preserved.
func (v *Vault) Edit(location string, credential Credential) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	oldcred, ok := creds[location]
	if !ok {
		return ErrNoSuchCredential
	}

	credential.Meta = oldcred.Meta
	creds[location] = &credential

	return v.encrypt(creds)
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

	return v.encrypt(creds)
}

// AddMeta adds a meta tag to the credential in the vault at `location`. `name`
// is used for the name of the meta tag and `value` is used as its value.
func (v *Vault) AddMeta(location string, name string, value string) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	cred, exists := creds[location]
	if !exists {
		return ErrNoSuchCredential
	}

	if _, exists = cred.Meta[name]; exists {
		return ErrMetaExists
	}

	if cred.Meta == nil {
		cred.Meta = make(map[string]string)
	}
	cred.Meta[name] = value
	creds[location] = cred

	return v.encrypt(creds)
}

// EditMeta changes a meta tag at a given location and meta tag name to
// `newvalue`.
func (v *Vault) EditMeta(location string, name string, newvalue string) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	cred, exists := creds[location]
	if !exists {
		return ErrNoSuchCredential
	}

	if _, exists = cred.Meta[name]; !exists {
		return ErrMetaDoesNotExist
	}

	cred.Meta[name] = newvalue
	creds[location] = cred

	return v.encrypt(creds)
}

// DeleteMeta removes a meta tag from the credential at `location`.
func (v *Vault) DeleteMeta(location string, metaname string) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	cred, exists := creds[location]
	if !exists {
		return ErrNoSuchCredential
	}

	if _, exists = cred.Meta[metaname]; !exists {
		return ErrMetaDoesNotExist
	}

	delete(cred.Meta, metaname)
	creds[location] = cred

	return v.encrypt(creds)
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

// Find searches the vault for locations containing the `searchtext` and
// returns the matching credential name and credential if it is found.
// Otherwise, an error `ErrNoSuchCredential` will be returned.
func (v *Vault) Find(searchtext string) (string, *Credential, error) {
	creds, err := v.decrypt()
	if err != nil {
		return "", nil, err
	}

	// first try direct string comparison, we want the most exact match if
	// possible
	for location, cred := range creds {
		if location == searchtext {
			return location, cred, nil
		}
	}

	// that failed, so let's match using strings.Contains
	for location, cred := range creds {
		if strings.Contains(location, searchtext) {
			return location, cred, nil
		}
	}

	return "", nil, ErrNoSuchCredential
}

// FindMeta search the credential at location `location` for a meta value
// containing `serachtext` and returns the meta name and value if it is found.
// Otherwise, an error `ErrMetaDoesNotExist` will be returned.
func (v *Vault) FindMeta(location string, searchtext string) (string, string, error) {
	creds, err := v.decrypt()
	if err != nil {
		return "", "", err
	}

	cred, exists := creds[location]
	if !exists {
		return "", "", ErrNoSuchCredential
	}

	for metaname, metaval := range cred.Meta {
		if metaname == searchtext {
			return metaname, metaval, nil
		}
	}

	for metaname, metaval := range cred.Meta {
		if strings.Contains(metaname, searchtext) {
			return metaname, metaval, nil
		}
	}

	return "", "", ErrMetaDoesNotExist
}

// LoadCSV loads password data from a CSV file. The text provided by
// locationField is used as the key for Location data, usernameField and
// passwordField are used as the key for the Username and Password data.
func (v *Vault) LoadCSV(c io.Reader, locationField, usernameField, passwordField string) (int, error) {
	r := csv.NewReader(c)

	var header []string
	locationFieldIndex := 0
	usernameFieldIndex := 0
	passwordFieldIndex := 0

	nimported := 0

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nimported, err
		}
		if len(header) == 0 {
			header = record
			for idx, field := range record {
				if field == locationField {
					locationFieldIndex = idx
				}
				if field == usernameField {
					usernameFieldIndex = idx
				}
				if field == passwordField {
					passwordFieldIndex = idx
				}
			}
			continue
		}

		location := record[locationFieldIndex]
		cred := Credential{Username: record[usernameFieldIndex], Password: record[passwordFieldIndex]}

		err = v.Add(location, cred)
		if err != nil {
			fmt.Printf("error importing %v: %v. skipping.\n", location, err)
			continue
		}

		for idx, field := range record {
			if idx == locationFieldIndex || idx == usernameFieldIndex || idx == passwordFieldIndex {
				continue
			}

			metaname := header[idx]
			metaval := field

			err = v.AddMeta(location, metaname, metaval)
			if err != nil {
				return nimported, err
			}
		}

		nimported++
	}

	return nimported, nil
}

// ChangePassphrase re-encrypts the entire vault with a new master key derived
// from the provided `newpassphrase`.
func (v *Vault) ChangePassphrase(newpassphrase string) error {
	creds, err := v.decrypt()
	if err != nil {
		return err
	}

	var nonce, salt [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		panic(err)
	}

	var secret [32]byte
	key, err := scrypt.Key([]byte(newpassphrase), salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		panic(err)
	}
	copy(secret[:], key)

	v.nonce = nonce
	v.secret = secret
	v.salt = salt

	err = v.encrypt(creds)
	if err != nil {
		return err
	}

	return nil
}
