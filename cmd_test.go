package main

import (
	"github.com/johnathanhowell/masterkey/vault"
	"reflect"
	"testing"
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

	if res != "Locations stored in this vault: " {
		t.Fatal("expected empty vault to have empty list()")
	}

	err = v.Add("testlocation", vault.Credential{"testuser", "testpass"})
	if err != nil {
		t.Fatal(err)
	}

	res, err = listcmd([]string{})
	if err != nil {
		t.Fatal(err)
	}

	if res != "Locations stored in this vault: \ntestlocation" {
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
	if res != "testlocation added successfully" {
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
	if res != "testlocation generated successfully" {
		t.Fatal("gen did not return succesfully")
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

	testcredential := vault.Credential{"testuser", "testpass"}

	err = v.Add("testlocation", testcredential)
	if err != nil {
		t.Fatal(err)
	}

	res, err := savecmd([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if res != "saved successfully" {
		t.Fatal("expected save command to save successfully")
	}

	vopen, err := vault.Open("testvault", "testpass")
	if err != nil {
		t.Fatal(err)
	}
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
	if res != "testlocation updated successfully" {
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
