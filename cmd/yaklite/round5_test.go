package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUSB(t *testing.T) {
	js := `{"SPUSBDataType":[{"_name":"USB31Bus","_items":[
	  {"_name":"USB2.0 Hub","_items":[{"_name":"Logitech USB Receiver","manufacturer":"Logitech","vendor_id":"0x046d","product_id":"0xc52b"}]},
	  {"_name":"Digispark","vendor_id":"0x16d0","product_id":"0x0753","serial_num":"1"},
	  {"_name":"Samsung T7","manufacturer":"Samsung","vendor_id":"0x04e8","product_id":"0x4001","serial_num":"S1"}]}]}`
	items := parseUSB(js)
	if len(items) != 3 {
		t.Fatalf("%+v", items)
	}
	var kb int
	for _, it := range items {
		if it.Sev == sevMedium {
			kb++
		}
	}
	if kb != 1 {
		t.Errorf("one device can type: %+v", items)
	}
}

func TestAuthorizedKeys(t *testing.T) {
	s := "# mine\nssh-ed25519 AAAAC3Nza me@laptop\nfrom=\"10.0.0.1\",no-pty ssh-rsa AAAAB3Nza attacker\n\n"
	items := parseAuthorizedKeys(s, "/Users/b/.ssh/authorized_keys")
	if len(items) != 2 || !strings.Contains(items[0].Label, "me@laptop") || !strings.Contains(items[1].Label, "ssh-rsa key") {
		t.Fatalf("%+v", items)
	}
}

func TestHostsFile(t *testing.T) {
	s := "127.0.0.1 localhost\n255.255.255.255 broadcasthost\n::1 localhost\n# 1.2.3.4 commented.example\n6.6.6.6 www.mybank.example mybank.example # added\n"
	items := parseHostsFile(s)
	if len(items) != 2 || items[0].Label != "www.mybank.example -> 6.6.6.6" {
		t.Fatalf("%+v", items)
	}
}

func TestShellAndRemoteApps(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export A=1\n"), 0o644)
	os.MkdirAll(filepath.Join(home, "Downloads", "AnyDesk.app"), 0o755)
	h := &hostOS{goos: "darwin", home: home, run: func(context.Context, string, ...string) string { return "" }, readFile: os.ReadFile, readDir: os.ReadDir}
	sh := shellItems(h)
	found := false
	for _, it := range sh {
		if strings.HasSuffix(it.Label, ".zshrc") {
			found = true
		}
	}
	if !found {
		t.Errorf("%+v", sh)
	}
	before := sh
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export A=1\ncurl x | sh\n"), 0o644)
	after := shellItems(h)
	if before[len(before)-1].id() == after[len(after)-1].id() && len(before) == len(after) {
		// the .zshrc entry must change identity when its content changes
		same := true
		for i := range before {
			if before[i].id() != after[i].id() {
				same = false
			}
		}
		if same {
			t.Error("changed file kept its identity")
		}
	}
	ra := remoteAppItems(h)
	if len(ra) != 1 || ra[0].Sev != sevHigh {
		t.Errorf("%+v", ra)
	}
	if !applePeriodic("110.clean-tmps") || applePeriodic("update.sh") {
		t.Error("periodic names")
	}
}

func TestBrowserSafety(t *testing.T) {
	if !chromeSafeBrowsingOff([]byte(`{"safebrowsing":{"enabled":false}}`)) || chromeSafeBrowsingOff([]byte(`{"safebrowsing":{"enhanced":true}}`)) {
		t.Error("safe browsing")
	}
	home := t.TempDir()
	prof := filepath.Join(home, "Library/Application Support/Google/Chrome/Default")
	os.MkdirAll(prof, 0o755)
	os.WriteFile(filepath.Join(prof, "Preferences"), []byte(`{"safebrowsing":{"enabled":false}}`), 0o644)
	h := &hostOS{goos: "darwin", home: home, readFile: os.ReadFile, readDir: os.ReadDir}
	run := func(_ context.Context, name string, args ...string) string {
		if name == "defaults" && strings.HasSuffix(args[1], "com.apple.Safari") {
			return "1"
		}
		return ""
	}
	fs := browserSafetyFindings(context.Background(), run, h)
	if len(fs) != 2 {
		t.Fatalf("%+v", fs)
	}
}
