package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/avahowell/masterkey/secureclip"
	"github.com/avahowell/masterkey/vault"

	ui "github.com/gizak/termui"
)

type uiConfig struct {
	timeout   time.Duration
	vaultPath string
}

type masterkeyUI struct {
	selectedIdx       int
	lastInputTime     int64
	genDialog         *ui.Par
	delDialog         *ui.Par
	addDialog         *ui.Par
	flash             *ui.Par
	searchBar         *ui.Par
	list              *ui.List
	searching         bool
	locations         []string
	searchText        string
	searchMatches     []int
	searchIdx         int
	vaultPath         string
	displayDelDialog  bool
	displayGenDialog  bool
	displayFlash      bool
	displayEditDialog bool
	genDialogInput    bool
	genDialogLocation string
	genDialogUsername string
	addDialogInput    int
	addDialogLocation string
	addDialogUsername string
	addDialogPassword string
	displayAddDialog  bool
	v                 *vault.Vault
}

func getListItems(v *vault.Vault, selectedIdx int, listHeight int) ([]string, []string) {
	locations, err := v.Locations()
	if err != nil {
		panic(err)
	}
	sort.Strings(locations)
	var listItems []string
	for i, loc := range locations {
		var item string
		if i == selectedIdx {
			item = fmt.Sprintf("> %v <", loc)
		} else {
			item = fmt.Sprintf("%v", loc)
		}
		listItems = append(listItems, item)
	}
	if selectedIdx > listHeight-3 && len(listItems) > listHeight-3 {
		listItems = listItems[(listHeight-3)*(selectedIdx/(listHeight-3)):]
	}
	return listItems, locations
}

func newMasterkeyUI(v *vault.Vault, vaultPath string) (*masterkeyUI, error) {
	if v == nil {
		return nil, errors.New("vault must be initialized")
	}

	// password list
	ls := ui.NewList()
	ls.ItemFgColor = ui.ColorYellow
	ls.Height = ui.TermHeight() - 2
	ls.BorderLabel = "Passwords"
	listItems, _ := getListItems(v, 0, ls.Height)
	ls.Items = listItems

	// search bar
	spar := ui.NewPar("search: ")
	spar.Height = 1
	spar.Width = 60
	spar.Border = false
	spar.Float = ui.AlignBottom

	// buttons
	enterButton := ui.NewPar("[ enter ](fg-black,bg-white) Copy")
	enterButton.Height = 1
	enterButton.Border = false
	generateButton := ui.NewPar("[ G ](fg-black,bg-white) Generate")
	generateButton.Height = 1
	generateButton.Border = false
	addButton := ui.NewPar("[ A ](fg-black,bg-white) Add")
	addButton.Height = 1
	addButton.Border = false
	editButton := ui.NewPar("[ E ](fg-black,bg-white) Edit")
	editButton.Height = 1
	editButton.Border = false
	quitButton := ui.NewPar("[ Q ](fg-black,bg-white) Save+Quit")
	quitButton.Height = 1
	quitButton.Border = false
	searchButton := ui.NewPar("[ / ](fg-black,bg-white) Search")
	searchButton.Height = 1
	searchButton.Border = false

	// dialogs
	genDialogLocation := ""
	genDialogUsername := ""
	genDialog := ui.NewPar("")
	genDialog.BorderLabel = "Generate Login"
	genDialog.Float = ui.AlignCenter
	genDialog.Text = fmt.Sprintf(`Location: %v
		Username: %v`, genDialogLocation, genDialogUsername)
	genDialog.Height = 4
	genDialog.Width = 30

	addDialog := ui.NewPar("")
	addDialog.BorderLabel = "Add Login"
	addDialog.Float = ui.AlignCenter
	addDialog.Text = fmt.Sprintf(`Location: %v
				Username: %v
				Password: %v`, "", "", "")
	addDialog.Height = 5
	addDialog.Width = 30

	delDialog := ui.NewPar("")
	delDialog.BorderLabel = "Delete Login"
	delDialog.Float = ui.AlignCenter
	delDialog.Height = 3

	delDialog.Width = 30

	// flash dialog
	flash := ui.NewPar("")
	flash.Height = 1
	flash.Width = 50
	flash.Border = false
	flash.Float = ui.AlignBottom

	ui.Body.AddRows(
		ui.NewRow(
			ui.NewCol(12, 0, ls),
		),
		ui.NewRow(
			ui.NewCol(2, 0, enterButton),
			ui.NewCol(2, 0, generateButton),
			ui.NewCol(2, 0, addButton),
			ui.NewCol(2, 0, editButton),
			ui.NewCol(2, 0, searchButton),
			ui.NewCol(2, 0, quitButton),
		),
	)

	return &masterkeyUI{
		lastInputTime: time.Now().Unix(),
		selectedIdx:   0,
		vaultPath:     vaultPath,
		genDialog:     genDialog,
		delDialog:     delDialog,
		addDialog:     addDialog,
		searchBar:     spar,
		flash:         flash,
		list:          ls,
		v:             v,
	}, nil
}

func (m *masterkeyUI) searchInputHandler(inputKey string) error {
	if inputKey == "<enter>" {
		m.searching = false
		for i, item := range m.locations {
			if strings.Contains(item, m.searchText) {
				m.searchMatches = append(m.searchMatches, i)
			}
		}
		if len(m.searchMatches) > 0 {
			m.selectedIdx = m.searchMatches[m.searchIdx]
		}
	} else if inputKey == "<escape>" {
		m.searching = false
	}
	if inputKey == "C-8" {
		if len(m.searchText) > 0 {
			m.searchText = m.searchText[:len(m.searchText)-1]
		}
	} else if inputKey == "<space>" {
		m.searchText += " "
	} else {
		m.searchText += inputKey
	}

	return nil
}

func (m *masterkeyUI) delDialogInputHandler(inputKey string) error {
	if inputKey == "y" {
		err := m.v.Delete(m.locations[m.selectedIdx])
		if err != nil {
			return err
		}
		err = m.v.Save(m.vaultPath)
		if err != nil {
			return err
		}
		m.displayDelDialog = false
	} else if inputKey == "n" {
		m.displayDelDialog = false
	} else if inputKey == "<escape>" {
		m.displayDelDialog = false
	}

	return nil
}

func (m *masterkeyUI) genDialogInputHandler(inputKey string) error {
	if inputKey == "<escape>" {
		m.displayGenDialog = false
	} else if inputKey == "<tab>" {
		m.genDialogInput = !m.genDialogInput
	} else if inputKey == "C-8" {
		if m.genDialogInput == false {
			if len(m.genDialogLocation) > 0 {
				m.genDialogLocation = m.genDialogLocation[:len(m.genDialogLocation)-1]
			}
		} else {
			if len(m.genDialogUsername) > 0 {
				m.genDialogUsername = m.genDialogUsername[:len(m.genDialogUsername)-1]
			}
		}
	} else if inputKey == "<enter>" {
		err := m.v.Generate(m.genDialogLocation, m.genDialogUsername)
		if err != nil {
			return err
		}
		err = m.v.Save(m.vaultPath)
		if err != nil {
			return err
		}
		m.displayGenDialog = false
		m.genDialogLocation = ""
		m.genDialogUsername = ""
	} else {
		if m.genDialogInput == false {
			m.genDialogLocation += inputKey
		} else {
			m.genDialogUsername += inputKey
		}
	}
	m.genDialog.Text = fmt.Sprintf(`Location: %v
				Username: %v`, m.genDialogLocation, m.genDialogUsername)
	return nil
}

func (m *masterkeyUI) addDialogInputHandler(inputKey string, editMode bool) error {
	if inputKey == "<escape>" {
		m.displayEditDialog = false
		m.displayAddDialog = false
	} else if inputKey == "<tab>" {
		m.addDialogInput = (m.addDialogInput + 1) % 3
	} else if inputKey == "C-8" {
		switch m.addDialogInput {
		case 0:
			if len(m.addDialogLocation) > 0 {
				m.addDialogLocation = m.addDialogLocation[:len(m.addDialogLocation)-1]
			}
		case 1:
			if len(m.addDialogUsername) > 0 {
				m.addDialogUsername = m.addDialogUsername[:len(m.addDialogUsername)-1]
			}
		case 2:
			if len(m.addDialogPassword) > 0 {
				m.addDialogPassword = m.addDialogPassword[:len(m.addDialogPassword)-1]
			}
		}
	} else if inputKey == "<enter>" {
		var err error
		if !editMode {
			err = m.v.Add(m.addDialogLocation, vault.Credential{Username: m.addDialogUsername, Password: m.addDialogPassword})
		} else {
			err = m.v.Edit(m.addDialogLocation, vault.Credential{Username: m.addDialogUsername, Password: m.addDialogPassword})
		}
		if err != nil {
			return err
		}
		err = m.v.Save(m.vaultPath)
		if err != nil {
			return err
		}
		m.displayAddDialog = false
		m.displayEditDialog = false
		m.addDialogInput = 0
		m.addDialogLocation = ""
		m.addDialogUsername = ""
		m.addDialogPassword = ""
	} else {
		switch m.addDialogInput {
		case 0:
			if !editMode {
				m.addDialogLocation += inputKey
			}
		case 1:
			m.addDialogUsername += inputKey
		case 2:
			m.addDialogPassword += inputKey
		}
	}
	m.addDialog.Text = fmt.Sprintf(`Location: %v
				Username: %v
				Password: %v`, m.addDialogLocation, m.addDialogUsername, m.addDialogPassword)
	return nil

}

func (m *masterkeyUI) inputHandler(inputKey string) error {
	if inputKey == "<up>" || inputKey == "k" {
		if m.selectedIdx > 0 {
			m.selectedIdx--
		}
	} else if inputKey == "<down>" || inputKey == "j" {
		if m.selectedIdx < len(m.locations)-1 {
			m.selectedIdx++
		}
	} else if inputKey == "C-f" {
		m.selectedIdx += m.list.Height - 1
		if m.selectedIdx > len(m.locations)-1 {
			m.selectedIdx = len(m.locations) - 1
		}
	} else if inputKey == "C-b" {
		m.selectedIdx -= m.list.Height - 1
		if m.selectedIdx < 0 {
			m.selectedIdx = 0
		}
	} else if inputKey == "n" { // next search item
		if len(m.searchMatches) > 0 {
			m.searchIdx = (m.searchIdx + 1) % len(m.searchMatches)
			m.selectedIdx = m.searchMatches[m.searchIdx]
		}
	} else if inputKey == "/" { //search
		m.searchMatches = []int{}
		m.searchText = ""
		m.searchIdx = 0
		m.searching = true
	} else if inputKey == "<enter>" { // copy
		cred, err := m.v.Get(m.locations[m.selectedIdx])
		if err != nil {
			return err
		}
		secureclip.Clip(cred.Password)
		m.flash.Text = "copied " + m.locations[m.selectedIdx] + " to keyboard, clearing in 30s"
		m.displayFlash = true
	} else if inputKey == "g" { // gen
		m.displayGenDialog = true
	} else if inputKey == "e" { // edit
		m.addDialogLocation = m.locations[m.selectedIdx]
		cred, _ := m.v.Get(m.addDialogLocation)
		m.addDialogUsername = cred.Username
		m.addDialogPassword = cred.Password
		m.addDialog.Text = fmt.Sprintf(`Location: %v
				Username: %v
				Password: %v`, m.addDialogLocation, m.addDialogUsername, m.addDialogPassword)
		m.addDialogInput = 1
		m.addDialog.BorderLabel = "Edit Login"
		m.displayEditDialog = true
	} else if inputKey == "a" { // add
		m.addDialog.BorderLabel = "Add Login"
		m.displayAddDialog = true
	} else if inputKey == "d" {
		m.displayDelDialog = true
		m.delDialog.Text = fmt.Sprintf("Delete %v? (y/n)", m.locations[m.selectedIdx])
	} else if inputKey == "q" {
		ui.StopLoop()
	}
	return nil
}

func (m *masterkeyUI) run() error {
	m.list.Items, m.locations = getListItems(m.v, m.selectedIdx, m.list.Height)
	ui.Handle("/sys/kbd", func(e ui.Event) {
		atomic.StoreInt64(&m.lastInputTime, time.Now().Unix())
		inputKey := e.Data.(ui.EvtKbd).KeyStr

		// search functionality
		if m.searching {
			m.searchInputHandler(inputKey)
		} else if m.displayDelDialog {
			m.delDialogInputHandler(inputKey)
		} else if m.displayGenDialog { // gen dialog functionality
			m.genDialogInputHandler(inputKey)
		} else if m.displayEditDialog {
			m.addDialogInputHandler(inputKey, true)
		} else if m.displayAddDialog {
			m.addDialogInputHandler(inputKey, false)
		} else {
			m.inputHandler(inputKey)
		}
		m.list.Items, m.locations = getListItems(m.v, m.selectedIdx, m.list.Height)
		m.searchBar.Text = "search: " + m.searchText
		ui.Clear()
		ui.Render(ui.Body)
		if m.searching {
			ui.Render(m.searchBar)
		}
		if m.displayFlash {
			m.displayFlash = false
			ui.Render(m.flash)
		}
		if m.displayGenDialog {
			ui.Render(m.genDialog)
		}
		if m.displayAddDialog {
			ui.Render(m.addDialog)
		}
		if m.displayEditDialog {
			m.addDialogLocation = m.locations[m.selectedIdx]
			ui.Render(m.addDialog)
		}
		if m.displayDelDialog {
			ui.Render(m.delDialog)
		}
	})
	ui.Handle("/sys/wnd/resize", func(ui.Event) {
		if ui.TermWidth() > 20 {
			ui.Body.Width = ui.TermWidth()
		}
		if ui.TermHeight() > 8 {
			m.list.Height = ui.TermHeight() - 2
		}

		ui.Body.Align()
		ui.Clear()
		ui.Render(ui.Body)
		if m.displayGenDialog {
			ui.Render(m.genDialog)
		}
	})
	ui.Clear()
	ui.Body.Align()
	ui.Render(ui.Body)
	ui.Loop()

	return nil
}

func masterPasswordInput(pwLen int, errorstring string) []ui.Bufferer {
	input := ui.NewPar("")
	input.Height = 3
	input.Width = 50
	input.Text = strings.Repeat("*", pwLen)
	input.TextFgColor = ui.ColorWhite
	input.BorderLabel = "Master Password"
	input.BorderFg = ui.ColorCyan
	input.Float = ui.AlignCenter
	errorbox := ui.NewPar(errorstring)
	errorbox.Height = 10
	errorbox.Width = 50
	errorbox.PaddingTop = 8
	errorbox.Border = false
	errorbox.Float = ui.AlignCenter

	return []ui.Bufferer{errorbox, input}
}
func runUI(vaultPath string, timeout time.Duration) {
	err := ui.Init()
	if err != nil {
		panic(err)
	}
	defer ui.Close()

	var v *vault.Vault

	pw := ""
	errorstring := ""
	pwInput := masterPasswordInput(len(pw), errorstring)
	ui.Handle("/sys/kbd", func(e ui.Event) {
		inputKey := e.Data.(ui.EvtKbd).KeyStr
		if inputKey == "C-8" { // backspace
			if len(pw) > 0 {
				pw = pw[:len(pw)-1]
			}
		} else if inputKey == "C-c" {
			ui.StopLoop()
		} else if inputKey == "<space>" { //space
			pw = pw + " "
		} else if inputKey == "<enter>" {
			// handle login
			errorstring = "deriving argon2id key, one moment"
			pwInput = masterPasswordInput(len(pw), errorstring)
			ui.Render(pwInput...)
			vopen, err := vault.Open(vaultPath, pw)
			if err != nil {
				errorstring = err.Error()
			} else {
				v = vopen
				pw = ""
				ui.StopLoop()
			}
		} else {
			pw = pw + inputKey
		}
		pwInput = masterPasswordInput(len(pw), errorstring)
		ui.Render(pwInput...)
	})
	ui.Handle("/sys/wnd/resize", func(ui.Event) {
		if ui.TermWidth() > 20 {
			ui.Body.Width = ui.TermWidth()
		}
		ui.Clear()
		ui.Render(pwInput...)
	})

	ui.Render(pwInput...)
	ui.Loop()

	if v == nil {
		return
	}

	// we have an initialzed vault now
	defer func() {
		v.Save(vaultPath)
		secureclip.Clear()
		v.Close()
	}()

	mui, err := newMasterkeyUI(v, vaultPath)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			time.Sleep(time.Second)

			if time.Since(time.Unix(atomic.LoadInt64(&mui.lastInputTime), 0)) > timeout {
				ui.StopLoop()
				return
			}
		}
	}()

	mui.run()
}
