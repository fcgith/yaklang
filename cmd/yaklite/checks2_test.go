package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeviceRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "inv.yaml")
	os.WriteFile(p, []byte("rules:\n  - kind: Camera\n    vendor: hikvision\n  - kind: NAS\n    ports: [5000, 5001]\n  - kind: Printer\n    banner: '(?i)laserjet'\n"), 0o600)
	inv, err := LoadInventory(p)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSnapshot("", "", "t")
	s.Hosts["10.0.0.2"] = []*Service{{Port: 554}}
	s.Devices["10.0.0.2"] = &Device{Vendor: "Hangzhou Hikvision Digital"}
	s.Hosts["10.0.0.3"] = []*Service{{Port: 5000}, {Port: 5001}}
	s.Hosts["10.0.0.4"] = []*Service{{Port: 80, Product: "HP LaserJet"}}
	s.Hosts["10.0.0.5"] = []*Service{{Port: 5000}}
	inv.applyRules(s)
	for h, want := range map[string]string{"10.0.0.2": "Camera", "10.0.0.3": "NAS", "10.0.0.4": "Printer"} {
		if s.Devices[h] == nil || s.Devices[h].Kind != want {
			t.Errorf("%s: %+v", h, s.Devices[h])
		}
	}
	if s.Devices["10.0.0.5"] != nil {
		t.Error("partial port match labelled")
	}
	os.WriteFile(p, []byte("rules:\n  - kind: Everything\n"), 0o600)
	if _, err := LoadInventory(p); err == nil {
		t.Error("a rule that matches everything was accepted")
	}
}

func TestWiFiParsing(t *testing.T) {
	sp := `{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0","spairport_current_network_information":{"_name":"Home","spairport_security_mode":"spairport_security_mode_wpa2_personal"}}]}]}`
	if w := parseSPAirPort(sp); w == nil || w.SSID != "Home" || w.Security != "wpa2" {
		t.Errorf("%+v", w)
	}
	if w := parseNmcliWiFi("no:Other:WPA2\nyes:Cafe:\n"); w == nil || w.SSID != "Cafe" || w.Security != "open" {
		t.Errorf("%+v", w)
	}
	if normSecurity("WEP") != "wep" || normSecurity("WPA3 SAE") != "wpa3" || normSecurity("WPA1 WPA2") != "wpa2" {
		t.Error("normSecurity")
	}
}

func TestIPv6Neighbours(t *testing.T) {
	n := parseIPNeigh6("2001:db8::5 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\nfd00::7 dev eth0 lladdr aa:bb:cc:dd:ee:03 STALE\n")
	if len(n) != 1 || n["2001:db8::5"] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("%v", n)
	}
	m := parseNDP("Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n2a02:1:2::9%en0 a:b:c:d:e:f en0 23h59m R\n")
	if m["2a02:1:2::9"] != "0a:0b:0c:0d:0e:0f" {
		t.Errorf("%v", m)
	}
}

func TestEveAlerts(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	log := `{"timestamp":"2026-10-10T11:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.5","dest_ip":"192.168.1.10","dest_port":22,"alert":{"signature_id":2001219,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-10-08T11:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.6","alert":{"signature_id":1,"signature":"old","severity":1}}
{"timestamp":"2026-10-10T11:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.7","alert":{"signature_id":2,"signature":"low","severity":3}}
{"timestamp":"2026-10-10T11:00:00.000000+0000","event_type":"flow"}
`
	fs, err := eveFindings(strings.NewReader(log), now)
	if err != nil || len(fs) != 1 || fs[0].Severity != sevMedium || !strings.Contains(fs[0].Title, "SSH Scan") {
		t.Errorf("%+v %v", fs, err)
	}
}

func TestKEVMatching(t *testing.T) {
	list := []kevEntry{{CVE: "CVE-2021-41773", Vendor: "Apache", Product: "HTTP Server"}, {CVE: "CVE-1", Vendor: "Microsoft", Product: "Windows"}}
	v, p := cpeParts("cpe:/a:apache:http_server:2.4.49")
	if m := kevMatches(list, v, p); len(m) != 1 || m[0].CVE != "CVE-2021-41773" {
		t.Errorf("%q %q -> %+v", v, p, m)
	}
	v, p = cpeParts("cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*")
	if m := kevMatches(list, v, p); len(m) != 0 {
		t.Errorf("tomcat matched %+v", m)
	}
}

func TestMCP(t *testing.T) {
	dir := writeTestState(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_alerts","arguments":{"days":30}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope"}}
`)
	var out bytes.Buffer
	if err := serveMCP(context.Background(), in, &out, dir); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 replies (the notification gets none), got %d:\n%s", len(lines), out.String())
	}
	var r map[string]any
	json.Unmarshal([]byte(lines[2]), &r)
	text := r["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "telnet") {
		t.Errorf("list_alerts: %s", text)
	}
	if !strings.Contains(lines[3], `"error"`) {
		t.Errorf("unknown tool: %s", lines[3])
	}
}

func TestAPISummaryAndRelease(t *testing.T) {
	snap := NewSnapshot("", "", "connect")
	snap.addFinding(&Finding{ID: "a", Severity: sevHigh, Title: "bad"})
	snap.addFinding(&Finding{ID: "b", Severity: sevMedium, Title: "meh"})
	s := apiSummary([]*watchState{{Name: "n", Snap: snap}}, &acksFile{Acks: []ack{{Key: "a"}}}, time.Now())
	if s.Status != "warn" || s.OpenHigh != 0 || s.OpenMedium != 1 {
		t.Errorf("%+v", s)
	}
	if v := releaseVersion("Latest yaklite build from main (abc1234). Unsigned: install with curl."); v != "abc1234" {
		t.Errorf("release version %q", v)
	}
}
