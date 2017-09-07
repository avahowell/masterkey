package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/atotto/clipboard"
	"github.com/avahowell/masterkey/vault"
)

func TestListCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	listcmd := list(v)

	res, err := listcmd([]string{})
	if err != nil {
		t.Fatal(err)
	}

	if res != "Locations stored in this vault: \n" {
		t.Fatal("expected empty vault to have empty list()")
	}

	err = v.Add("testlocation", vault.Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}

	res, err = listcmd([]string{})
	if err != nil {
		t.Fatal(err)
	}

	if res != "Locations stored in this vault: \ntestlocation\n" {
		t.Fatal("incorrect output from list cmd")
	}
}

func TestGetCmd(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	getcmd := get(v)

	_, err = getcmd([]string{})
	if err == nil {
		t.Fatal("expected get cmd to fail with no args")
	}

	_, err = getcmd([]string{"t1", "t2"})
	if err == nil {
		t.Fatal("expected get cmd to fail with too many args")
	}
}

func TestAddCmd(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	addcmd := add(v)
	_, err = addcmd([]string{})
	if err == nil {
		t.Fatal("expected add cmd to fail with no args")
	}
	res, err := addcmd([]string{"testlocation", "testusername", "testpassword"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "testlocation added successfully\n" {
		t.Fatal("add returned the incorrect result")
	}
	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "testusername" {
		t.Fatal("add command did not set username")
	}
	if cred.Password != "testpassword" {
		t.Fatal("add command did not set password")
	}
}

func TestGenCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	gencmd := gen(v)
	_, err = gencmd([]string{})
	if err == nil {
		t.Fatal("expected gen cmd to fail with no args")
	}
	res, err := gencmd([]string{"testlocation", "testusername"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "testlocation generated successfully\n" {
		t.Fatal("gen did not return successfully")
	}
	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "testusername" {
		t.Fatal(err)
	}
	if cred.Password == "" {
		t.Fatal("gencmd did not generate a password")
	}
}

func TestSaveCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	savecmd := save(v, "testvault")

	testcredential := vault.Credential{Username: "testuser", Password: "testpass"}

	err = v.Add("testlocation", testcredential)
	if err != nil {
		t.Fatal(err)
	}

	res, err := savecmd([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if res != "testvault saved successfully.\n" {
		t.Fatal("expected save command to save successfully")
	}

	vopen, err := vault.Open("testvault", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	defer vopen.Close()

	cred, err := vopen.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cred, &testcredential) {
		t.Fatalf("expected on-disk vault to have test credential after save cmd, wanted %v got %v\n", testcredential, cred)
	}
}

func TestEditCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	editcmd := edit(v)

	_, err = editcmd([]string{"testlocation"})
	if err == nil {
		t.Fatal("expected edit command to return error if 3 args are not provided")
	}

	err = v.Add("testlocation", vault.Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := editcmd([]string{"testlocation", "testuser2", "testpass2"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "testlocation updated successfully\n" {
		t.Fatal("expected edit command to return updated successfully on edit")
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "testuser2" || cred.Password != "testpass2" {
		t.Fatal("edit did not update credential")
	}
}

func TestClipCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	clipcmd := clip(v)

	_, err = clipcmd([]string{})
	if err == nil {
		t.Fatal("clipcmd should return an error with no args")
	}

	err = v.Add("testlocation", vault.Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := clipcmd([]string{"testlocation"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "testuser@testlocation copied to clipboard, will clear in 30 seconds\n" {
		t.Fatal("clip command should return success string")
	}

	clipcontents, err := clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if clipcontents != "testpass" {
		t.Fatal("clip command did not copy the passphrase into the clipboard")
	}

	err = v.AddMeta("testlocation", "test", "test1")
	if err != nil {
		t.Fatal(err)
	}

	res, err = clipcmd([]string{"testlocation", "test"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "test@testlocation copied to clipboard, will clear in 30 seconds\n" {
		t.Fatal("clip command should return success string")
	}

	clipcontents, err = clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if clipcontents != "test1" {
		t.Fatal("clip command did not copy the metadata into the clipboard")
	}
}

func TestAddMetaCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", vault.Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}

	addmetacmd := addmeta(v)
	_, err = addmetacmd([]string{})
	if err == nil {
		t.Fatal("expected add meta command to return an error with no args")
	}

	_, err = addmetacmd([]string{"testlocation", "testmeta", "testmetaval"})
	if err != nil {
		t.Fatal(err)
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}

	meta, exists := cred.Meta["testmeta"]
	if !exists || meta != "testmetaval" {
		t.Fatal("meta command did not correctly add meta")
	}
}

func TestEditMetaCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("testlocation", vault.Credential{Username: "testusername", Password: "testpassword"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.AddMeta("testlocation", "test", "test1")
	if err != nil {
		t.Fatal(err)
	}

	editmetacmd := editmeta(v)
	_, err = editmetacmd([]string{})
	if err == nil {
		t.Fatal("expected edit meta command to return an error with no args")
	}

	_, err = editmetacmd([]string{"testlocation", "test", "test2"})
	if err != nil {
		t.Fatal(err)
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}
	meta, exists := cred.Meta["test"]
	if !exists || meta != "test2" {
		t.Fatal("edit meta command did not update the meta val")
	}
}

func TestSearchCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	searchcmd := search(v)

	_, err = searchcmd([]string{})
	if err == nil {
		t.Fatal("searchcmd could return an error with no args")
	}

	err = v.Add("testloc", vault.Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := searchcmd([]string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "testloc\n" {
		t.Fatal("search command did not find our credential")
	}

	err = v.Add("loc2", vault.Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond * 250)

	res, err = searchcmd([]string{"loc"})
	if err != nil {
		t.Fatal(err)
	}
	// Both orders are fine.
	if res != "testloc\nloc2\n" && res != "loc2\ntestloc\n" {
		t.Log(res)
		t.Fatal("search command did not find credentials")
	}

	res, err = searchcmd([]string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "testloc\n" {
		t.Fatal("search command did not find credential")
	}
}

func TestDeleteCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	deletecmd := deletelocation(v)

	_, err = deletecmd([]string{})
	if err == nil {
		t.Fatal("deletecmd should return an error with no args")
	}

	err = v.Add("testlocation", vault.Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = deletecmd([]string{"testlocation"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Get("testlocation")
	if err != vault.ErrNoSuchCredential {
		t.Fatal("credential existed after deletecmd")
	}
}

func TestDeleteMetaCommand(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	deletemetacmd := deletemeta(v)

	_, err = deletemetacmd([]string{})
	if err == nil {
		t.Fatal("deletemeta should return an error with no args")
	}

	err = v.Add("testlocation", vault.Credential{Username: "testuser", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}

	err = v.AddMeta("testlocation", "testmeta", "testval")
	if err != nil {
		t.Fatal(err)
	}

	_, err = deletemetacmd([]string{"testlocation", "testmeta"})
	if err != nil {
		t.Fatal(err)
	}

	cred, err := v.Get("testlocation")
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := cred.Meta["testmeta"]; exists {
		t.Fatal("credential still had meta after delete command")
	}
}

func TestFuzzyClip(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("deadbeef", vault.Credential{Username: "testuser0", Password: "testpassword0"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("acidburn", vault.Credential{Username: "testuser1", Password: "testpassword1"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("gibson", vault.Credential{Username: "testuser2", Password: "testpassword2"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = clip(v)([]string{"gibs"})
	if err != nil {
		t.Fatal(err)
	}

	clipcontents, err := clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	if clipcontents != "testpassword2" {
		t.Fatal("clip did not copy using an incomplete search string")
	}

	_, err = clip(v)([]string{"acid"})
	if err != nil {
		t.Fatal(err)
	}

	clipcontents, err = clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	if clipcontents != "testpassword1" {
		t.Fatal("clip did not copy using an incomplete search string")
	}

	_, err = clip(v)([]string{"beef"})
	if err != nil {
		t.Fatal(err)
	}

	clipcontents, err = clipboard.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	if clipcontents != "testpassword0" {
		t.Fatal("clip did not copy using an incomplete search string")
	}
}

func TestFuzzyGet(t *testing.T) {
	v, err := vault.New("testpass")
	if err != nil {
		t.Fatal(err)
	}

	err = v.Add("deadbeef", vault.Credential{Username: "testuser0", Password: "testpassword0"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("acidburn", vault.Credential{Username: "testuser1", Password: "testpassword1"})
	if err != nil {
		t.Fatal(err)
	}
	err = v.Add("gibson", vault.Credential{Username: "testuser2", Password: "testpassword2"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = get(v)([]string{"gibs"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = get(v)([]string{"acid"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = get(v)([]string{"beef"})
	if err != nil {
		t.Fatal(err)
	}
}
