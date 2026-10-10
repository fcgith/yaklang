package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeInv(t *testing.T, body string) *Inventory {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := LoadInventory(p)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

const invYAML = `
hosts:
  10.0.0.10:
    name: NAS
    expect: [22, 443]
  10.0.0.20:
    name: TV
  10.0.0.99:
    ignore: true
`

func sev(cs []Change) map[string]string {
	m := map[string]string{}
	for _, c := range cs {
		m[c.Kind+" "+c.Host+" "+itoa(c.Port)] = c.Severity
	}
	return m
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestAnnotateWithInventory(t *testing.T) {
	inv := writeInv(t, invYAML)
	cs := Annotate([]Change{
		{Kind: "port_open", Host: "10.0.0.10", Port: 22, Proto: "tcp", After: "OpenSSH"},   // expected
		{Kind: "port_open", Host: "10.0.0.10", Port: 8080, Proto: "tcp", After: "http"},    // not expected
		{Kind: "port_open", Host: "10.0.0.20", Port: 23, Proto: "tcp", After: "telnet"},    // risky
		{Kind: "port_closed", Host: "10.0.0.10", Port: 443, Proto: "tcp", Before: "nginx"}, // expected service down
		{Kind: "host_new", Host: "10.0.0.50"},                                              // unknown device
		{Kind: "host_new", Host: "10.0.0.20"},                                              // known device back
		{Kind: "port_open", Host: "10.0.0.99", Port: 23, Proto: "tcp"},                     // ignored host
	}, inv)
	got := sev(cs)
	want := map[string]string{
		"port_open 10.0.0.10 22":    sevInfo,
		"port_open 10.0.0.10 8080":  sevMedium,
		"port_open 10.0.0.20 23":    sevHigh,
		"port_closed 10.0.0.10 443": sevMedium,
		"host_new 10.0.0.50 0":      sevMedium,
		"host_new 10.0.0.20 0":      sevInfo,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	for _, c := range cs {
		if c.Host == "10.0.0.10" && c.Name != "NAS" {
			t.Errorf("name not applied: %+v", c)
		}
	}
}

func TestAnnotateWithoutInventoryFlagsRiskyPorts(t *testing.T) {
	cs := Annotate([]Change{
		{Kind: "port_open", Host: "h", Port: 6379, Proto: "tcp", After: "redis"},
		{Kind: "port_open", Host: "h", Port: 8443, Proto: "tcp", After: "https"},
		{Kind: "service_changed", Host: "h", Port: 2323, Proto: "tcp", Before: "http", After: "telnetd"},
	}, nil)
	if cs[0].Severity != sevHigh || cs[1].Severity != sevLow || cs[2].Severity != sevHigh {
		t.Fatalf("got %v", sev(cs))
	}
	if got := filterSeverity(cs, sevHigh); len(got) != 2 {
		t.Fatalf("filter: %v", sev(got))
	}
}

func TestInventoryRejectsNonIPKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.yaml")
	os.WriteFile(p, []byte("hosts:\n  nas.local:\n    name: x\n"), 0o600)
	if _, err := LoadInventory(p); err == nil || !strings.Contains(err.Error(), "not an IP") {
		t.Fatalf("expected IP error, got %v", err)
	}
}

func svcWithCert(sha string, notAfter time.Time, issuer string) *Service {
	return &Service{Port: 443, Proto: "tcp", TLS: &TLSInfo{Subject: "CN=nas", Issuer: issuer, SHA256: sha, NotAfter: notAfter}}
}

func TestTLSExpiryReportedOnce(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	warn := 21 * 24 * time.Hour
	exp := now.Add(10 * 24 * time.Hour)
	first := snap(map[string][]*Service{"h": {svcWithCert("aa", exp, "CN=ca")}})
	prev := snap(map[string][]*Service{"h": {svcWithCert("aa", exp, "CN=ca")}}) // same cert, not yet flagged
	cs := Diff(prev, first, DiffOptions{GoneAfter: 1, TLSWarn: warn}, now)
	if len(cs) != 1 || cs[0].Kind != "tls_expiring" || !strings.Contains(cs[0].Detail, "10 days") {
		t.Fatalf("first: %+v", cs)
	}
	next := snap(map[string][]*Service{"h": {svcWithCert("aa", exp, "CN=ca")}})
	if cs := Diff(first, next, DiffOptions{GoneAfter: 1, TLSWarn: warn}, now.Add(time.Hour)); len(cs) != 0 {
		t.Fatalf("repeated: %+v", cs)
	}
	expired := snap(map[string][]*Service{"h": {svcWithCert("aa", exp, "CN=ca")}})
	cs = Diff(next, expired, DiffOptions{GoneAfter: 1, TLSWarn: warn}, exp.Add(time.Hour))
	if len(cs) != 1 || cs[0].Kind != "tls_expired" {
		t.Fatalf("expired: %+v", cs)
	}
	// renewal: new cert, far expiry, different issuer -> one change, medium after annotate
	renewed := snap(map[string][]*Service{"h": {svcWithCert("bb", now.Add(90*24*time.Hour), "CN=other")}})
	cs = Annotate(Diff(expired, renewed, DiffOptions{GoneAfter: 1, TLSWarn: warn}, now), nil)
	if len(cs) != 1 || cs[0].Kind != "tls_cert_changed" || cs[0].Severity != sevMedium {
		t.Fatalf("renewed: %+v", cs)
	}
}

func TestWebhookFormats(t *testing.T) {
	cases := map[string]string{
		"https://discord.com/api/webhooks/1/x":                  "discord",
		"https://api.telegram.org/bot1:x/sendMessage?chat_id=5": "telegram",
		"https://hooks.slack.com/services/a":                    "slack",
		"https://ntfy.sh/topic":                                 "ntfy",
		"https://push.example.com/message?token=abc":            "gotify",
		"https://example.com/hook":                              "json",
	}
	for u, want := range cases {
		if got := detectFormat(u); got != want {
			t.Errorf("%s: got %s want %s", u, got, want)
		}
	}
	changes := []Change{{Kind: "port_open", Host: "h", Port: 23, Proto: "tcp", Severity: sevHigh}}
	body, _, _ := buildWebhook("discord", changes)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m["content"] == nil {
		t.Fatalf("discord body: %s", body)
	}
	body, ctype, hdr := buildWebhook("ntfy", changes)
	if !strings.HasPrefix(ctype, "text/plain") || hdr["Priority"] != "5" || !strings.Contains(string(body), "PORT OPENED") {
		t.Fatalf("ntfy: %s %s %v", ctype, body, hdr)
	}
	body, _, _ = buildWebhook("gotify", changes)
	json.Unmarshal(body, &m)
	if m["priority"].(float64) != 8 {
		t.Fatalf("gotify: %s", body)
	}
}
