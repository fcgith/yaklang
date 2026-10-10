package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Checks about the network this computer is on, rather than the devices on
// it: Wi-Fi security and fake copies of your Wi-Fi, and smart gadgets
// sharing a network with your computers. Also battery detection, so scans
// are gentler on a laptop that is not plugged in.

func init() {
	registerCheck(&check{name: "wifi", about: "open or weak Wi-Fi, and a fake copy of your own Wi-Fi", run: wifiCheck})
	registerCheck(&check{name: "iot", about: "smart gadgets (cameras, TVs, plugs) sharing a network with your computers", trustedOnly: true, run: iotCheck})
}

// onBattery is true for a laptop running on battery.
func onBattery(ctx context.Context) bool {
	switch runtime.GOOS {
	case "darwin":
		return strings.Contains(cmdOut(ctx, "pmset", "-g", "batt"), "'Battery Power'")
	case "linux":
		files, _ := filepath.Glob("/sys/class/power_supply/*/online")
		if len(files) == 0 {
			return false
		}
		for _, f := range files {
			if b, _ := os.ReadFile(f); strings.TrimSpace(string(b)) == "1" {
				return false
			}
		}
		return true
	}
	return false
}

type wifiInfo struct {
	SSID     string
	Security string // normalised: open, wep, wpa, wpa2, wpa3, enterprise, or ""
}

func currentWiFi(ctx context.Context) *wifiInfo {
	switch runtime.GOOS {
	case "darwin":
		return parseSPAirPort(cmdOut(ctx, "system_profiler", "SPAirPortDataType", "-json"))
	case "linux":
		return parseNmcliWiFi(cmdOut(ctx, "nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"))
	}
	return nil
}

func normSecurity(s string) string {
	s = strings.ToLower(s)
	switch {
	case s == "" || s == "--" || strings.Contains(s, "none") || strings.Contains(s, "open"):
		return "open"
	case strings.Contains(s, "wep"):
		return "wep"
	case strings.Contains(s, "enterprise") || strings.Contains(s, "802.1x") || strings.Contains(s, "eap"):
		return "enterprise"
	case strings.Contains(s, "wpa3") || strings.Contains(s, "sae"):
		return "wpa3"
	case strings.Contains(s, "wpa2") || strings.Contains(s, "rsn"):
		return "wpa2"
	case strings.Contains(s, "wpa"):
		return "wpa"
	}
	return ""
}

func parseSPAirPort(out string) *wifiInfo {
	var doc struct {
		Data []struct {
			Interfaces []struct {
				Current *struct {
					Name     string `json:"_name"`
					Security string `json:"spairport_security_mode"`
				} `json:"spairport_current_network_information"`
			} `json:"spairport_airport_interfaces"`
		} `json:"SPAirPortDataType"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return nil
	}
	for _, d := range doc.Data {
		for _, i := range d.Interfaces {
			if i.Current != nil && i.Current.Name != "" {
				sec := strings.TrimPrefix(i.Current.Security, "spairport_security_mode_")
				return &wifiInfo{SSID: i.Current.Name, Security: normSecurity(sec)}
			}
		}
	}
	return nil
}

func parseNmcliWiFi(out string) *wifiInfo {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && f[0] == "yes" {
			return &wifiInfo{SSID: strings.ReplaceAll(f[1], `\:`, ":"), Security: normSecurity(f[len(f)-1])}
		}
	}
	return nil
}

func wifiCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	w := currentWiFi(ctx)
	if w == nil {
		return nil, nil // wired, or not readable
	}
	var out []*Finding
	switch w.Security {
	case "open":
		f := &Finding{ID: "wifi:open:" + w.SSID, Severity: sevMedium,
			Title: fmt.Sprintf("The Wi-Fi %q has no password, so anyone nearby can see traffic that is not encrypted", w.SSID),
			Fix:   "Avoid logging in to anything that is not HTTPS here, or use a VPN."}
		if env.trusted {
			f.Severity = sevHigh
			f.Fix = "Set a WPA2 or WPA3 password on your router's Wi-Fi settings."
		}
		out = append(out, f)
	case "wep", "wpa":
		out = append(out, &Finding{ID: "wifi:weak:" + w.SSID, Severity: sevHigh,
			Title: fmt.Sprintf("The Wi-Fi %q uses old %s protection that can be broken in minutes", w.SSID, strings.ToUpper(w.Security)),
			Fix:   "Switch the router to WPA2 or WPA3 (WPA2/WPA3 mixed mode is fine)."})
	}
	if env.net == nil || w.SSID == "" {
		return out, nil
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	nf, p := loadNetworks()
	cur := nf.Networks[env.net.ID()]
	if cur != nil && cur.Trusted {
		if cur.SSID == "" {
			cur.SSID = w.SSID
			nf.save(p)
		}
		return out, nil
	}
	for id, k := range nf.Networks {
		if k.Trusted && k.SSID == w.SSID && id != env.net.ID() {
			out = append(out, &Finding{ID: "wifi:twin:" + w.SSID + ":" + env.net.ID(), Severity: sevHigh,
				Title:  fmt.Sprintf("This Wi-Fi is called %q like your network %s, but its router is a different device", w.SSID, k.Name),
				Detail: "A fake copy of a known Wi-Fi is a common way to intercept traffic. It can also be a new router or a second access point of your own.",
				Fix:    "If you did not replace the router or add an access point, disconnect and forget this network. If you did, run: yaklite trust --name " + k.Name})
			break
		}
	}
	return out, nil
}

// ---- smart gadgets on the same network as computers ----

var iotVendors = []string{"hikvision", "dahua", "ezviz", "reolink", "wyze", "tuya", "espressif", "shelly", "sonoff", "itead", "xiaomi", "yeelight",
	"roku", "sonos", "signify", "philips lighting", "ring", "amazon", "nest", "chromecast", "lifx", "ecobee", "arlo", "eufy", "anker",
	"lg electronics", "hisense", "tcl", "vizio", "broadlink", "meross", "gree", "midea", "irobot"}

var iotPorts = map[int]bool{554: true, 8554: true, 1883: true, 8883: true, 6668: true, 8008: true, 8009: true, 1400: true, 9295: true, 37777: true, 34567: true}

var computerVendors = []string{"apple", "dell", "lenovo", "hewlett", "hp inc", "intel", "microsoft", "asustek", "acer", "framework", "liteon", "azurewave", "giga-byte", "micro-star"}

func vendorIn(v string, list []string) bool {
	v = strings.ToLower(v)
	for _, x := range list {
		if strings.Contains(v, x) {
			return true
		}
	}
	return false
}

func iotCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	var gadgets []string
	computers := 0
	for h, d := range env.snap.Devices {
		if h == env.snap.Gateway || d == nil {
			continue
		}
		gadget := vendorIn(d.Vendor, iotVendors) || strings.Contains(strings.ToLower(d.Kind), "camera")
		for _, s := range env.snap.Hosts[h] {
			if iotPorts[s.Port] {
				gadget = true
			}
		}
		switch {
		case gadget:
			name := h
			if desc := d.describe(); desc != "" {
				name += " (" + desc + ")"
			}
			gadgets = append(gadgets, name)
		case d.Self || vendorIn(d.Vendor, computerVendors):
			computers++
		}
	}
	if len(gadgets) == 0 || computers == 0 {
		return nil, nil
	}
	sort.Strings(gadgets)
	shown := gadgets
	if len(shown) > 8 {
		shown = append(shown[:8:8], fmt.Sprintf("and %d more", len(gadgets)-8))
	}
	return []*Finding{{ID: "iot:shared-network", Severity: sevLow,
		Title:  fmt.Sprintf("%d smart gadget(s) share the network with your computers", len(gadgets)),
		Detail: strings.Join(shown, "; "),
		Fix:    "Cameras, TVs and smart plugs rarely get security updates. Put them on the router's guest or IoT network so a hacked gadget cannot reach your computers."}}, nil
}
