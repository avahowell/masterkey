package vault

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/johnathanhowell/masterkey/vault/filelock"
)

func TestVaultLock(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("testlocation", Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.Save("testout.db")
	if err != nil {
		t.Fatal(err)
	}

	v, err = Open("testout.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}

	_, err = Open("testout.db", "testpass")
	if err != filelock.ErrLocked {
		t.Fatal("open on already opened vault should fail with ErrLocked")
	}

	err = v.Close()
	if err != nil {
		t.Fatal(err)
	}

	v2, err := Open("testout.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v2.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestChangePassphrase(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("testlocation", Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.Save("testout.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("testout.db")

	v, err = Open("testout.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.ChangePassphrase("newpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Save("testout.db")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Close()
	if err != nil {
		t.Fatal(err)
	}

	v2, err := Open("testout.db", "newpass")
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()

	_, err = v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFindMeta(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = v.FindMeta("testlocation", "test")
	if err != ErrNoSuchCredential {
		t.Fatal("expected no such credential")
	}

	err = v.Add("testlocation", Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = v.FindMeta("testlocation", "test")
	if err != ErrMetaDoesNotExist {
		t.Fatal("expected ErrMetaDoesNotExist")
	}

	err = v.AddMeta("testlocation", "testmeta", "testmetaval")
	if err != nil {
		t.Fatal(err)
	}

	metaname, metaval, err := v.FindMeta("testlocation", "testme")
	if err != nil {
		t.Fatal(err)
	}
	if metaname != "testmeta" {
		t.Fatalf("meta name returned did not match: got %v wanted testmeta\n", metaname)
	}
	if metaval != "testmetaval" {
		t.Fatalf("meta value returned did not match: got %v wanted testmetaval\n", metaval)
	}
}
func TestLoadCSV(t *testing.T) {
	const kpcsvData = `
"Group","Title","Username","Password","URL","Notes"

"TestGroup0","testtitle0","testusername0","testpassword0","testurl0",""
"TestGroup1","testtitle1","testusername1","testpassword1","testurl1",""
"TestGroup2","testtitle2","testusername2","testpassword2","testurl2",""
"TestGroup2","testtitle2","testusername2","testpassword2","testurl2",""
"TestGroup3","testtitle3","testusername3","testpassword3","testurl3",""
"TestGroup4","testtitle4","testusername4","testpassword4","testurl4",""
"TestGroup3","testtitle3","testusername3","testpassword3","testurl3",""
`
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	n, err := v.LoadCSV(strings.NewReader(kpcsvData), "Title", "Username", "Password")
	locations, err := v.Locations()
	if err != nil {
		t.Fatal(err)
	}
	if len(locations) != n {
		t.Fatalf("loadcsv misreported the number of imported credentials. wanted %v got %v\n", len(locations), n)
	}

	if len(locations) != 5 {
		t.Fatalf("wrong number of locations in vault, got %v wanted %v\n", len(locations), 5)
	}

	for i := 0; i < 5; i++ {
		expectedLocation := fmt.Sprintf("testtitle%v", i)
		expectedUsername := fmt.Sprintf("testusername%v", i)
		expectedPassword := fmt.Sprintf("testpassword%v", i)
		expectedMetaGroup := fmt.Sprintf("TestGroup%v", i)
		expectedMetaUrl := fmt.Sprintf("testurl%v", i)
		expectedMetaNotes := ""

		cred, err := v.Get(expectedLocation)
		if err != nil {
			t.Fatal(err)
		}

		if cred.Username != expectedUsername {
			t.Fatal("migrated credential did not have expected username")
		}

		if cred.Password != expectedPassword {
			t.Fatal("migrated credential did not have expected password")
		}

		if len(cred.Meta) != 3 {
			t.Fatal("expected 3 meta fields")
		}

		for metaname, metaval := range cred.Meta {
			if metaname == "Group" {
				if metaval != expectedMetaGroup {
					t.Fatal("incorrect meta value for Group meta key")
				}
			}
			if metaname == "URL" {
				if metaval != expectedMetaUrl {
					t.Fatal("incorrect meta value for Group meta key")
				}
			}
			if metaname == "Notes" {
				if metaval != expectedMetaNotes {
					t.Fatal("incorrect meta value for Group meta key")
				}
			}
		}
	}
}

func TestFindCredential(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = v.Find("acid")
	if err != ErrNoSuchCredential {
		t.Fatal("expected no such credential")
	}

	err = v.Add("testloc", Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("deadbeef", Credential{Username: "testusername1", Password: "testpassword1"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("acidburn", Credential{Username: "testusername2", Password: "testpassword2"})
	if err != nil {
		t.Fatal(err)
	}

	location, cred, err := v.Find("acid")
	if err != nil {
		t.Fatal(err)
	}

	if location != "acidburn" {
		t.Fatal("Find returned the wrong location")
	}

	if cred.Username != "testusername2" || cred.Password != "testpassword2" {
		t.Fatal("Find returned the wrong credential")
	}

	location, cred, err = v.Find("beef")
	if err != nil {
		t.Fatal(err)
	}

	if location != "deadbeef" {
		t.Fatal("Find returned the wrong location")
	}

	if cred.Username != "testusername1" || cred.Password != "testpassword1" {
		t.Fatal("Find returned the wrong credential")
	}
}

func TestDeleteLocation(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Delete("testlocation")
	if err != ErrNoSuchCredential {
		t.Fatal("expected Delete on non-existent location to return ErrNoSuchCredential")
	}

	err = v.Add("testlocation", Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.Delete("testlocation")
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Get("testlocation")
	if err != ErrNoSuchCredential {
		t.Fatal("vault still had credential after Delete")
	}
}

func TestVaultDeleteMeta(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("testlocation", Credential{Username: "testuser", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.DeleteMeta("testlocation", "test")
	if err != ErrMetaDoesNotExist {
		t.Fatal("delete on nonexistent meta did not return ErrMetaDoesNotExist")
	}

	err = v.AddMeta("testlocation", "test", "test1")
	if err != nil {
		t.Fatal(err)
	}

	err = v.DeleteMeta("testlocation", "test")
	if err != nil {
		t.Fatal(err)
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := cred.Meta["test"]; exists {
		t.Fatal("credential still had meta after DeleteMeta")
	}
}

func TestVaultEditMeta(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("testlocation", Credential{Username: "test", Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.EditMeta("testlocation", "test", "test1")
	if err != ErrMetaDoesNotExist {
		t.Fatal("expected EditMeta on nonexistent meta to return ErrMetaDoesNotExist")
	}
	err = v.AddMeta("testlocation", "test", "test1")
	if err != nil {
		t.Fatal(err)
	}
	err = v.EditMeta("testlocation", "test", "test2")
	if err != nil {
		t.Fatal(err)
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}

	meta, exists := cred.Meta["test"]
	if !exists || meta != "test2" {
		t.Fatal("vault.EditMeta did not update the meta data")
	}
}

func TestVaultAddMetaExistingMeta(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", Credential{Username: "test", Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.AddMeta("testlocation", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	err = v.AddMeta("testlocation", "test", "test")
	if err != ErrMetaExists {
		t.Fatal("expected AddMeta on existing meta to return ErrMetaExists")
	}
}

func TestVaultAddMetaNonexistingLocation(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.AddMeta("testlocation", "test", "test")
	if err != ErrNoSuchCredential {
		t.Fatal("expected AddMeta on non existent location to return ErrNoSuchCredential")
	}
}

func TestVaultAddMeta(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", Credential{Username: "testuser", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.AddMeta("testlocation", "2fa", "thisisa2fatoken")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	meta, exists := cred.Meta["2fa"]
	if !exists || meta != "thisisa2fatoken" {
		t.Fatal("vault.AddMeta did not add metadata to the credential at testlocation")
	}
}

func TestEditWithMeta(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.AddMeta("testlocation", "testmeta", "testmetaval")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Edit("testlocation", Credential{Username: "testusername2", Password: "testpassword2"})
	if err != nil {
		t.Fatal(err)
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}

	meta, exists := cred.Meta["testmeta"]
	if !exists || meta != "testmetaval" {
		t.Fatal("credential missing metadata after edit call")
	}
}

func TestEditLocationNonexisting(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Edit("testlocation", Credential{Username: "testusername", Password: "testpassword"})
	if err != ErrNoSuchCredential {
		t.Fatal("expected Edit on non-existent location to return ErrNoSuchCredential")
	}
}

func TestEditLocation(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("testlocation", Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.Edit("testlocation", Credential{Username: "testusername2", Password: "testpassword2"})
	if err != nil {
		t.Fatal(err)
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}

	if cred.Username != "testusername2" || cred.Password != "testpassword2" {
		t.Fatal("vault.Edit did not change credential data")
	}
}

func TestGetInvalidKey(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	v.secret = [32]byte{}
	if _, err = v.Get("test"); err != ErrCouldNotDecrypt {
		t.Fatal("expected v.Get to return ErrCouldNotDecrypt with invalid secret")
	}
}

func TestAddInvalidKey(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	v.secret = [32]byte{}
	if err = v.Add("testlocation", Credential{Username: "test", Password: "test2"}); err != ErrCouldNotDecrypt {
		t.Fatal("expected v.Add to return ErrCouldNotDecrypt with invalid secret")
	}
}

func TestHeavyVault(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	size := 10000

	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < size; i++ {
		err = v.Add(fmt.Sprintf("testlocation%v", i), Credential{Username: "testuser", Password: "testpassword"})
		if err != nil {
			t.Fatal(err)
		}
	}

	err = v.Save("testvault.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("testvault.db")

	v.Close()

	vopen, err := Open("testvault.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < size; i++ {
		cred, err := vopen.Get(fmt.Sprintf("testlocation%v", i))
		if err != nil {
			t.Fatal(err)
		}
		if cred.Username != "testuser" || cred.Password != "testpassword" {
			t.Fatal("huge vault did not contain testuser or testvault")
		}
	}
}

func TestAddFile(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// generate a file with random bytes
	f, err := os.Create("testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer os.Remove("testfile")

	_, err = io.CopyN(f, rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	err = v.AddFile("testfile", f.Name())
	if err != nil {
		t.Fatal(err)
	}

	err = v.GetFile("testfile", "testfile-res")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("testfile-res")

	originalBytes, err := ioutil.ReadFile("testfile")
	if err != nil {
		t.Fatal(err)
	}
	newBytes, err := ioutil.ReadFile("testfile-res")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(originalBytes, newBytes) != 0 {
		t.Fatal("expected extracted file to have the same contents as the original file")
	}

	// test adding a credential that doesnt have file data. GetFile should return
	// an error.
	err = v.Add("testlocation", Credential{Username: "test", Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.GetFile("testlocation", "nofile")
	if err != ErrNoSuchFile {
		t.Fatal("expected GetFile on credential that doesnt have file data to fail with ErrNoSuchFile")
	}

	// should be able to add a file to an existing credential that doesnt have
	// file data
	err = v.AddFile("testlocation", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	err = v.GetFile("testlocation", "testfile-res")
	if err != nil {
		t.Fatal(err)
	}

	newBytes, err = ioutil.ReadFile("testfile-res")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(originalBytes, newBytes) != 0 {
		t.Fatal("expected extracted file to have the same contents as the original file")
	}
}

func TestNonexistentVaultOpen(t *testing.T) {
	_, err := Open("doesntexist.jpg", "nopass")
	if !os.IsNotExist(err) {
		t.Fatal("Open did not return IsNotExist for non-existent filename")
	}
}

func TestGenerate(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Generate("testlocation", "testusername"); err != nil {
		t.Fatal(err)
	}
	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "testusername" {
		t.Fatal("Generate did not set username")
	}
	if cred.Password == "" {
		t.Fatal("generate did not generate a password")
	}
}

func TestGenerateExisting(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.Generate("testlocation", "testuser")
	if err != ErrCredentialExists {
		t.Fatal("expected credential exists error on generate with existing location")
	}
}

func TestGetLocations(t *testing.T) {
	creds := []Credential{
		{Username: "test1", Password: "testpass1"},
		{Username: "test2", Password: "testpass2"},
		{Username: "test3", Password: "testpass3"},
	}
	locs := []string{"testloc1", "testloc2", "testloc3"}

	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	for i, cred := range creds {
		if err = v.Add(locs[i], cred); err != nil {
			t.Fatal(err)
		}
	}

	vaultLocations, err := v.Locations()
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(vaultLocations)
	if !reflect.DeepEqual(locs, vaultLocations) {
		t.Fatalf("expected %v to equal %v\n", vaultLocations, locs)
	}
}

func TestGetNonexisting(t *testing.T) {
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Get("testlocation"); err != ErrNoSuchCredential {
		t.Fatal("expected vault.Get on nonexisting credential to return ErrNoSuchCredential")
	}
}

func TestAddExisting(t *testing.T) {
	testCredential := Credential{Username: "testuser", Password: "testpass"}
	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", testCredential)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", testCredential)
	if err != ErrCredentialExists {
		t.Fatal("expected add on existing location to return ErrCredentialExists")
	}
}

func TestNewSaveOpen(t *testing.T) {
	testCredential := Credential{Username: "testuser", Password: "testpass"}

	v, err := New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", testCredential)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Save("pass.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("pass.db")

	vopen, err := Open("pass.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	defer vopen.Close()

	credential, err := vopen.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&testCredential, credential) {
		t.Fatalf("vault did not store credential correctly. wanted %v got %v", testCredential, credential)
	}

	err = vopen.Close()
	if err != nil {
		t.Fatal(err)
	}

	vopen, err = Open("pass.db", "wrongpass")
	if err != ErrCouldNotDecrypt {
		t.Fatal("Open decrypted given an incorrect passphrase")
	}
}

func TestNonceRotation(t *testing.T) {
	testCredential := Credential{Username: "testuser", Password: "testpass"}

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
	defer os.Remove("pass.db")

	vopen, err := Open("pass.db", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	defer vopen.Close()

	if vopen.secret == oldsecret {
		t.Fatal("opened vault had the same secret as the previous vault")
	}
	if vopen.nonce == oldnonce {
		t.Fatal("opened vault had the same nonce as the previous vault")
	}
}

func BenchmarkVaultAdd(b *testing.B) {
	v, _ := New("testpass")
	for i := 0; i < b.N; i++ {
		v.Add(fmt.Sprintf("testlocation%v", i), Credential{Username: "testuser", Password: "testpass"})
	}
}
