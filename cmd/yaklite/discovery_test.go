package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseNeighbourTables(t *testing.T) {
	linux := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:91:b1:00:00:01     *        wlan0
192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.1.20     0x1         0x2         B8:27:EB:12:34:56     *        wlan0
`
	got := parseProcNetARP(linux)
	if len(got) != 2 || got["192.168.1.20"] != "b8:27:eb:12:34:56" || got["192.168.1.7"] != "" {
		t.Errorf("linux: %v", got)
	}

	mac := `? (192.168.1.1) at a4:91:b1:0:0:1 on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
`
	got = parseArpA(mac)
	if got["192.168.1.1"] != "a4:91:b1:00:00:01" || got["192.168.1.9"] != "" || got["192.168.1.255"] != "" {
		t.Errorf("macos: %v", got)
	}

	windows := `
Interface: 192.168.1.50 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           a4-91-b1-00-00-01     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
`
	got = parseArpA(windows)
	if got["192.168.1.1"] != "a4:91:b1:00:00:01" || len(got) != 1 {
		t.Errorf("windows: %v", got)
	}
}

func TestMACVendor(t *testing.T) {
	if v, r := macVendor("b8:27:eb:12:34:56"); v != "Raspberry Pi Foundation" || r {
		t.Errorf("raspberry pi: %q %v", v, r)
	}
	if v, r := macVendor("da:a1:19:00:00:01"); v != "" || !r {
		t.Errorf("randomized MAC should be flagged: %q %v", v, r)
	}
}

func devSnap(gw string, devs map[string]string) *Snapshot {
	s := NewSnapshot("192.168.1.0/24", "top", "connect")
	s.Gateway = gw
	for ip, mac := range devs {
		s.Hosts[ip] = []*Service{}
		d := &Device{MAC: mac}
		d.Vendor, d.Randomized = macVendor(mac)
		s.Devices[ip] = d
	}
	return s
}

func TestGatewayMACChangeAndSpoofing(t *testing.T) {
	now := time.Now()
	prev := devSnap("192.168.1.1", map[string]string{"192.168.1.1": "a4:91:b1:00:00:01", "192.168.1.30": "b8:27:eb:00:00:30"})

	// the router's MAC changes
	cur := devSnap("192.168.1.1", map[string]string{"192.168.1.1": "a4:91:b1:00:00:99", "192.168.1.30": "b8:27:eb:00:00:30"})
	ch := Annotate(Diff(prev, cur, DiffOptions{GoneAfter: 2}, now), nil)
	if len(ch) != 1 || ch[0].Kind != "mac_changed" || ch[0].Severity != sevHigh {
		t.Fatalf("gateway MAC change: %+v", ch)
	}

	// another host starts answering with the router's MAC
	cur = devSnap("192.168.1.1", map[string]string{"192.168.1.1": "a4:91:b1:00:00:01", "192.168.1.30": "a4:91:b1:00:00:01"})
	ch = Annotate(Diff(prev, cur, DiffOptions{GoneAfter: 2}, now), nil)
	var spoof bool
	for _, c := range ch {
		if c.Kind == "gateway_impersonated" && c.Host == "192.168.1.30" && c.Severity == sevHigh {
			spoof = true
		}
	}
	if !spoof {
		t.Fatalf("gateway impersonation not reported: %+v", ch)
	}
	// and it is not repeated on the next scan
	next := devSnap("192.168.1.1", map[string]string{"192.168.1.1": "a4:91:b1:00:00:01", "192.168.1.30": "a4:91:b1:00:00:01"})
	for _, c := range Diff(cur, next, DiffOptions{GoneAfter: 2}, now) {
		if c.Kind == "gateway_impersonated" {
			t.Fatal("gateway impersonation repeated")
		}
	}
}

func TestInventoryByMAC(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "inv.yaml")
	os.WriteFile(p, []byte("hosts:\n  \"B8-27-EB-00-00-30\":\n    name: Pi\n"), 0o600)
	inv, err := LoadInventory(p)
	if err != nil {
		t.Fatal(err)
	}
	prev := devSnap("", map[string]string{})
	cur := devSnap("", map[string]string{"192.168.1.77": "b8:27:eb:00:00:30", "192.168.1.78": "00:11:32:00:00:01"})
	ch := Annotate(Diff(prev, cur, DiffOptions{GoneAfter: 2}, time.Now()), inv)
	for _, c := range ch {
		switch c.Host {
		case "192.168.1.77":
			if c.Name != "Pi" || c.Severity != sevInfo {
				t.Errorf("known device by MAC: %+v", c)
			}
		case "192.168.1.78":
			if c.Severity != sevMedium || c.Detail != "unknown device joined the network" {
				t.Errorf("unknown device: %+v", c)
			}
			if c.After != "Synology; no open ports" {
				t.Errorf("summary: %q", c.After)
			}
		}
	}
}
