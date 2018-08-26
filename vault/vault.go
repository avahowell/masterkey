package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/avahowell/masterkey/filelock"
	"github.com/avahowell/masterkey/pwgen"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	scryptN          = 16384
	scryptR          = 8
	scryptP          = 1
	defaultArgonTime = 3
	keyLen           = 32
	genPasswordLen   = 32
)

var (
	defaultArgonMemory = func() uint32 {
		if flag.Lookup("test.v") != nil { // testing
			return 1e4
		}
		return 2e6
	}()
)

var (
	// ErrNoSuchCredential is returned from a Get call if the requested
	// credential does not exist
	ErrNoSuchCredential = errors.New("credential at specified location does not exist in vault")

	// ErrCouldNotDecrypt is returned if decryption fails.
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
	// using xchacha20 and authenticated with poly1305..
	Vault struct {
		data        []byte
		nonce       [24]byte
		salt        [24]byte
		secret      [32]byte
		argonTime   uint32
		argonMemory uint32
		argonLanes  uint8
		lock        *filelock.FileLock
	}

	// vaultFile defines the file format of the vault stored on disk, encoded using
	// json.
	vaultFile struct {
		ArgonTime   uint32
		ArgonMemory uint32
		ArgonLanes  uint8
		Nonce       [24]byte
		Salt        [24]byte
		Data        []byte
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
	skb := argon2.IDKey([]byte(passphrase), salt[:], defaultArgonTime, defaultArgonMemory, uint8(runtime.NumCPU()), keyLen)
	subtle.ConstantTimeCopy(1, secret[:], skb)

	v := &Vault{
		nonce:       nonce,
		salt:        salt,
		secret:      secret,
		argonTime:   defaultArgonTime,
		argonMemory: defaultArgonMemory,
		argonLanes:  uint8(runtime.NumCPU()),
	}

	err := v.encrypt(make(map[string]*Credential))
	if err != nil {
		return nil, err
	}

	return v, nil
}

// openVaultCompat opens an on-disk vault, using the legacy format
// (NACL/Secretbox, scrypt).
func openVaultCompat(filename, passphrase string) (*Vault, error) {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var salt, nonce [24]byte
	subtle.ConstantTimeCopy(1, salt[:], bs[:24])
	subtle.ConstantTimeCopy(1, nonce[:], bs[24:48])

	key, err := scrypt.Key([]byte(passphrase), salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}

	var secret [32]byte
	subtle.ConstantTimeCopy(1, secret[:], key)

	decryptedBytes, success := secretbox.Open(nil, bs[48:], &nonce, &secret)
	if !success {
		return nil, ErrCouldNotDecrypt
	}

	credentials := make(map[string]*Credential)
	err = gob.NewDecoder(bytes.NewBuffer(decryptedBytes)).Decode(&credentials)
	if err != nil {
		return nil, err
	}

	v := &Vault{
		salt:        salt,
		secret:      secret,
		argonLanes:  uint8(runtime.NumCPU()),
		argonTime:   defaultArgonTime,
		argonMemory: defaultArgonMemory,
	}

	skb := argon2.IDKey([]byte(passphrase), salt[:], v.argonTime, v.argonMemory, v.argonLanes, keyLen)
	subtle.ConstantTimeCopy(1, v.secret[:], skb)

	err = v.encrypt(credentials)
	if err != nil {
		return nil, err
	}

	return v, nil
}

// openVault opens an on-disk vault using the current format (salt:nonce:data).
func openVault(filename, passphrase string) (*Vault, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	vf := vaultFile{}
	err = json.NewDecoder(f).Decode(&vf)
	if err != nil {
		return nil, err
	}

	skb := argon2.IDKey([]byte(passphrase), vf.Salt[:], vf.ArgonTime, vf.ArgonMemory, vf.ArgonLanes, keyLen)
	var secret [32]byte
	subtle.ConstantTimeCopy(1, secret[:], skb)

	vault := &Vault{
		data:        vf.Data,
		nonce:       vf.Nonce,
		secret:      secret,
		salt:        vf.Salt,
		argonTime:   vf.ArgonTime,
		argonMemory: vf.ArgonMemory,
		argonLanes:  vf.ArgonLanes,
	}

	// rotate the salt on open
	creds, err := vault.decrypt()
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(rand.Reader, vault.salt[:])
	if err != nil {
		panic(err)
	}
	skb = argon2.IDKey([]byte(passphrase), vault.salt[:], vault.argonTime, vault.argonMemory, vault.argonLanes, keyLen)
	subtle.ConstantTimeCopy(1, vault.secret[:], skb)

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
	vaultPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	lock, err := filelock.Lock(vaultPath)
	if err != nil {
		return nil, err
	}
	vault, err := openVault(vaultPath, passphrase)
	if err != nil {
		vault, err = openVaultCompat(vaultPath, passphrase)
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
	for i := range v.secret {
		v.secret[i] = 0x00
	}
	if v.lock != nil {
		return v.lock.Unlock()
	}
	return nil
}

// Generate generates a new strong mnemonic passphrase and Add()s it to the
// vault.
func (v *Vault) Generate(location string, username string) error {
	phrase, err := pwgen.GeneratePassphrase(pwgen.CharsetAlphaNum, genPasswordLen)
	if err != nil {
		return err
	}
	cred := Credential{
		Username: username,
		Password: phrase,
	}
	return v.Add(location, cred)
}

// decrypt decrypts the vault and returns the credential data as a map of
// strings (locations) to Credentials.
func (v *Vault) decrypt() (map[string]*Credential, error) {
	aead, err := chacha20poly1305.NewX(v.secret[:])
	if err != nil {
		return nil, err
	}
	decryptedData, err := aead.Open(nil, v.nonce[:], v.data, nil)
	if err != nil {
		return nil, ErrCouldNotDecrypt
	}

	credentials := make(map[string]*Credential)
	err = gob.NewDecoder(bytes.NewBuffer(decryptedData)).Decode(&credentials)
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
	aead, err := chacha20poly1305.NewX(v.secret[:])
	if err != nil {
		return err
	}
	v.data = aead.Seal(nil, v.nonce[:], buf.Bytes(), nil)

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

	vf := vaultFile{
		Nonce:       v.nonce,
		Salt:        v.salt,
		ArgonTime:   v.argonTime,
		ArgonMemory: v.argonMemory,
		ArgonLanes:  v.argonLanes,
		Data:        v.data,
	}
	err = json.NewEncoder(tempfile).Encode(&vf)
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

	sort.Strings(locations)

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
	skb := argon2.IDKey([]byte(newpassphrase), salt[:], v.argonTime, v.argonMemory, v.argonLanes, keyLen)
	subtle.ConstantTimeCopy(1, secret[:], skb)

	v.nonce = nonce
	v.secret = secret
	v.salt = salt

	err = v.encrypt(creds)
	if err != nil {
		return err
	}

	return nil
}

// Merge adds every credential in otherVault to the vault. If a credential
// already exists with the same location in the vault, an error will be
// returned.
func (v *Vault) Merge(otherVault *Vault) error {
	otherLocations, err := otherVault.Locations()
	if err != nil {
		return err
	}
	for _, loc := range otherLocations {
		_, err := v.Get(loc)
		if err == nil {
			return fmt.Errorf("merge conflict: %v already exists in vault", loc)
		}
		otherCred, err := otherVault.Get(loc)
		if err != nil {
			return err
		}
		err = v.Add(loc, *otherCred)
		if err != nil {
			return err
		}
	}
	return nil
}
