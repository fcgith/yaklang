package main

import (
	"testing"
	"time"
)

func TestCleanNameAndCertCovers(t *testing.T) {
	for in, want := range map[string]string{
		"*.Example.com.":     "example.com",
		"api.example.com":    "api.example.com",
		"evil-example.com":   "",
		"mail.example.com\n": "mail.example.com",
		"a b.example.com":    "",
	} {
		if got := cleanName(in, "example.com"); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
	c := &TLSInfo{DNSNames: []string{"example.com", "*.example.com"}}
	if !certCovers(c, "www.example.com") || !certCovers(c, "example.com") || certCovers(c, "a.b.example.com") || certCovers(c, "other.org") {
		t.Error("certCovers wildcard rules")
	}
}

func outsideSnap(names map[string]*NameInfo) *Snapshot {
	s := NewSnapshot("example.com", "top", "outside")
	s.Domains = []string{"example.com"}
	s.Names = names
	s.ZoneTransfer = map[string][]string{}
	return s
}

func TestOutsideDiff(t *testing.T) {
	now := time.Now()
	web := &WebInfo{Status: 200, Server: "nginx"}
	cert := &TLSInfo{SHA256: "a", Issuer: "R3", DNSNames: []string{"example.com", "www.example.com"}, NotAfter: now.Add(60 * 24 * time.Hour)}
	https := func(t *TLSInfo) *Service { return &Service{Port: 443, Proto: "tcp", TLS: t} }
	prev := outsideSnap(map[string]*NameInfo{
		"example.com":     {IPs: []string{"203.0.113.1"}, HTTPS: https(cert), Web: web},
		"www.example.com": {IPs: []string{"203.0.113.1"}, HTTPS: https(cert), Web: web},
		"old.example.com": {IPs: []string{"203.0.113.9"}},
	})
	evil := &TLSInfo{SHA256: "b", Issuer: "Someone Else", DNSNames: []string{"other.org"}, NotAfter: now.Add(90 * 24 * time.Hour)}
	cur := outsideSnap(map[string]*NameInfo{
		"example.com":     {IPs: []string{"198.51.100.66"}, HTTPS: https(cert), Web: web},
		"www.example.com": {IPs: []string{"203.0.113.1"}, HTTPS: https(evil), CertMismatch: true, Web: &WebInfo{Status: 502, Server: "nginx"}},
		"new.example.com": {IPs: []string{"203.0.113.5"}, Sources: []string{"ct"}},
	})
	cur.ZoneTransfer["example.com"] = []string{"ns1.example.com"}
	cur.Hosts["203.0.113.1"] = []*Service{{Port: 3389, Proto: "tcp", Service: "ms-wbt-server"}}

	got := map[string]Change{}
	for _, c := range Annotate(Diff(prev, cur, DiffOptions{GoneAfter: 2, TLSWarn: 21 * 24 * time.Hour}, now), nil) {
		got[c.Kind+" "+c.Host] = c
	}
	want := map[string]string{
		"dns_changed example.com":          sevMedium,
		"cert_mismatch www.example.com":    sevMedium,
		"tls_cert_changed www.example.com": sevMedium, // issuer changed
		"web_changed www.example.com":      sevMedium, // 5xx: site down
		"name_new new.example.com":         sevLow,
		"zone_transfer_open example.com":   sevHigh,
		"port_open 203.0.113.1":            sevHigh, // RDP on the internet
	}
	for k, sev := range want {
		c, ok := got[k]
		if !ok {
			t.Errorf("missing %s; got %v", k, got)
			continue
		}
		if c.Severity != sev {
			t.Errorf("%s: severity %s, want %s", k, c.Severity, sev)
		}
	}
	if _, ok := got["name_gone old.example.com"]; ok {
		t.Error("name reported gone after one miss")
	}
	if cur.Names["old.example.com"] == nil {
		t.Error("missing name not carried forward")
	}
}

func TestOutsidePortSeverity(t *testing.T) {
	c := Annotate([]Change{{Kind: "port_open", Host: "203.0.113.1", Port: 8080, Proto: "tcp", Outside: true}}, nil)
	if c[0].Severity != sevMedium {
		t.Errorf("internet-facing port: %s", c[0].Severity)
	}
}
