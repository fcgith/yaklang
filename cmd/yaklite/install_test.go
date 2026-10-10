package main

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"
)

func TestLaunchdPlistIsWellFormed(t *testing.T) {
	p := launchdPlist(agentLabel, []string{"/Users/a b/Library/Application Support/yaklite/yaklite", "auto", "--webhook", "https://x/?a=1&b=<2>"}, time.Hour, false, "/tmp/log")
	d := xml.NewDecoder(strings.NewReader(p))
	d.Strict = true
	d.Entity = xml.HTMLEntity
	for {
		_, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("plist is not well-formed XML: %v\n%s", err, p)
		}
	}
	for _, want := range []string{"<integer>3600</integer>", "/Library/Preferences/SystemConfiguration", "a=1&amp;b=&lt;2&gt;", "<key>RunAtLoad</key><true/>"} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q", want)
		}
	}
	if strings.Contains(launchdPlist(webLabel, []string{"/bin/yaklite", "serve"}, 0, true, "/tmp/l"), "StartInterval") {
		t.Error("keep-alive job should not have StartInterval")
	}
}

func TestSystemdUnits(t *testing.T) {
	u := systemdUnits("/home/a b/.local/bin/yaklite", []string{"auto", "-q", "--webhook", "https://ntfy.sh/100%"}, 30*time.Minute)
	if !strings.Contains(u["yaklite-auto.service"], `ExecStart="/home/a b/.local/bin/yaklite" "auto" "-q" "--webhook" "https://ntfy.sh/100%%"`) {
		t.Errorf("ExecStart quoting:\n%s", u["yaklite-auto.service"])
	}
	if !strings.Contains(u["yaklite-auto.timer"], "OnUnitActiveSec=30min") {
		t.Error("timer interval")
	}
}

func TestEmptyRiskyPortsKeepsDefaults(t *testing.T) {
	inv := &Inventory{RiskyPorts: []int{}}
	if _, ok := inv.risky(3389, ""); !ok {
		t.Error("an empty risky_ports list must not disable the built-in list")
	}
}
