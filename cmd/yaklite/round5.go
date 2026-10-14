package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Round 5: more places on the Mac where an intruder leaves something
// behind, and settings that make the next attack easier:
//
//   - USB and Thunderbolt devices, above all new keyboards (a gadget that
//     pretends to be a keyboard can type commands in seconds)
//   - SSH keys allowed to log in to this Mac without a password
//   - shell startup files, the hosts file, sudo rules, login hooks and
//     periodic scripts, all quiet ways to run code or redirect websites
//   - remote control apps (AnyDesk, TeamViewer and others), the favourite
//     tool of "tech support" scammers
//   - browser safety settings: Safari opening downloads by itself, and
//     Chrome's Safe Browsing turned off

func init() {
	hostCats["usb"] = hostCat{sevLow, false, "New USB or Thunderbolt device: %s", "",
		"A device that says it is a keyboard can type commands into the Mac by itself; a few cost under $10 and look like a USB stick or cable.",
		"If you did not just plug this in, unplug it. Check what is connected to the Mac and to any dock or hub."}
	hostCats["sshkey"] = hostCat{sevHigh, true, "A new key can now log in to this Mac without a password: %s", "Please check this key, which can log in to this Mac without a password: %s",
		"Attackers add their own key here so they can come back whenever they like, even after you change your password.",
		"If you did not add it, delete that line from ~/.ssh/authorized_keys and turn off Remote Login in System Settings > General > Sharing."}
	hostCats["shellrc"] = hostCat{sevMedium, false, "A Terminal startup file changed: %s", "",
		"Commands in these files run every time a Terminal window opens. Malware and some installers add lines here.",
		"Open the file named above in TextEdit and look at the last lines. If something there downloads or runs a program you do not know, remove it."}
	hostCats["hosts"] = hostCat{sevMedium, true, "The hosts file now sends a website to a fixed address: %s", "Please check this hosts file entry: %s",
		"The hosts file overrides the internet's address book. Malware uses it to send you to fake bank or update sites, or to block security updates.",
		"If you did not add it, remove the line: run sudo nano /etc/hosts in Terminal, delete it, and save with Ctrl+O."}
	hostCats["sudoers"] = hostCat{sevHigh, true, "A new rule lets a program get administrator rights: %s", "Please check this administrator rule: %s",
		"Rules in /etc/sudoers.d can let a program act as administrator without asking for a password.",
		"If you did not add it, remove the file named above: sudo rm followed by its path."}
	hostCats["hook"] = hostCat{sevHigh, true, "A program now runs at every login or on a schedule: %s", "Please check this program that runs at login or on a schedule: %s",
		"Login hooks and periodic scripts are old, little-known ways to start a program; legitimate apps rarely use them now.",
		"If you do not know it, remove it (the place is named above) and run yaklite incident."}
	hostCats["remoteapp"] = hostCat{sevMedium, true, "A remote control app is installed: %s", "Please check this remote control app: %s",
		"Apps like this let someone else see and control the Mac. Scammers who call or pop up pretending to be Apple, Microsoft or your bank ask you to install one.",
		"If you did not install it yourself for someone you trust, delete it from Applications, then change your passwords from another device. If anyone had control of the Mac, run yaklite incident."}
}

// ---- USB and Thunderbolt ----

type usbNode struct {
	Name     string    `json:"_name"`
	Vendor   string    `json:"manufacturer"`
	VendorID string    `json:"vendor_id"`
	ProdID   string    `json:"product_id"`
	Serial   string    `json:"serial_num"`
	Items    []usbNode `json:"_items"`
}

// keyboardish names devices that can type: keyboards, and the boards that
// keystroke-injection gadgets are built on.
var keyboardishRe = regexp.MustCompile(`(?i)keyboard|keypad|hid|digispark|teensy|arduino|rubber ?ducky|bad ?usb|pico|atmel|attiny|leonardo|cactus`)

// parseUSB reads `system_profiler -json SPUSBDataType SPUSBHostDataType SPThunderboltDataType`.
func parseUSB(js string) []hostItem {
	var r map[string][]usbNode
	if json.Unmarshal([]byte(js), &r) != nil {
		return nil
	}
	var out []hostItem
	var walk func(ns []usbNode, depth int)
	walk = func(ns []usbNode, depth int) {
		for _, n := range ns {
			// the top levels are the Mac's own buses and hubs
			isBus := depth == 0 || strings.Contains(strings.ToLower(n.Name), "hub") || strings.Contains(strings.ToLower(n.Name), "bus")
			if !isBus && n.Name != "" {
				key := n.VendorID + ":" + n.ProdID + ":" + n.Serial
				if n.VendorID == "" && n.ProdID == "" {
					key = n.Name + ":" + n.Serial
				}
				it := hostItem{Cat: "usb", Key: key, Label: n.Name}
				if n.Vendor != "" && !strings.Contains(n.Name, n.Vendor) {
					it.Label += " (" + n.Vendor + ")"
				}
				if keyboardishRe.MatchString(n.Name + " " + n.Vendor) {
					it.Sev = sevMedium
					it.Label += ", which can type like a keyboard"
				}
				out = append(out, it)
			}
			walk(n.Items, depth+1)
		}
	}
	for _, k := range sortedKeys(r) {
		walk(r[k], 0)
	}
	return out
}

// ---- SSH keys ----

func parseAuthorizedKeys(s, file string) []hostItem {
	var out []hostItem
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Fields(line)
		// options may come first; the key is the field after the type
		label, key := "", line
		for i, w := range f {
			if strings.HasPrefix(w, "ssh-") || strings.HasPrefix(w, "ecdsa-") || strings.HasPrefix(w, "sk-") {
				if i+1 < len(f) {
					key = f[i+1]
					sum := sha256.Sum256([]byte(key))
					label = w + " key " + hex.EncodeToString(sum[:])[:12]
					if i+2 < len(f) {
						label += " (" + strings.Join(f[i+2:], " ") + ")"
					}
				}
				break
			}
		}
		if label == "" {
			label = trunc(line, 60)
		}
		out = append(out, hostItem{Cat: "sshkey", Key: file + ":" + key, Label: label + " in " + file})
	}
	return out
}

// ---- shell files, hosts, sudo rules, hooks ----

var shellFiles = []string{".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile", ".config/fish/config.fish"}

// shellItems fingerprints each startup file, so any change is one item.
func shellItems(h *hostOS) []hostItem {
	var out []hostItem
	files := []string{"/etc/zshrc", "/etc/zprofile", "/etc/profile", "/etc/bashrc", "/etc/zshenv"}
	for _, f := range shellFiles {
		files = append(files, filepath.Join(h.home, f))
	}
	for _, p := range files {
		data, err := h.readFile(p)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		out = append(out, hostItem{Cat: "shellrc", Key: p + ":" + hex.EncodeToString(sum[:8]), Label: p})
	}
	return out
}

var standardHosts = map[string]bool{"localhost": true, "broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true, "localhost.localdomain": true}

func parseHostsFile(s string) []hostItem {
	var out []hostItem
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		for _, name := range f[1:] {
			if standardHosts[strings.ToLower(name)] {
				continue
			}
			out = append(out, hostItem{Cat: "hosts", Key: f[0] + " " + name, Label: name + " -> " + f[0]})
		}
	}
	return out
}

func hookItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	if h.goos != "darwin" && h.goos != "linux" {
		return nil
	}
	ents, _ := h.readDir("/etc/sudoers.d")
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join("/etc/sudoers.d", e.Name())
		data, _ := h.readFile(p)
		sum := sha256.Sum256(data)
		out = append(out, hostItem{Cat: "sudoers", Key: p + ":" + hex.EncodeToString(sum[:8]), Label: p})
	}
	if h.goos == "darwin" {
		for _, k := range []string{"LoginHook", "LogoutHook"} {
			v := h.run(ctx, "defaults", "read", "com.apple.loginwindow", k)
			if v != "" && !strings.Contains(v, "does not exist") {
				it := hostItem{Cat: "hook", Key: k + ":" + v, Label: k + " runs " + v}
				if suspiciousPath(v) {
					it.Label += ", from a temporary or hidden folder"
				}
				out = append(out, it)
			}
		}
		// periodic scripts: Apple's own are numbered like 100.clean-logs
		for _, d := range []string{"/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly", "/usr/local/etc/periodic/daily"} {
			ents, _ := h.readDir(d)
			for _, e := range ents {
				if !applePeriodic(e.Name()) {
					p := filepath.Join(d, e.Name())
					out = append(out, hostItem{Cat: "hook", Key: p, Label: "periodic script " + p})
				}
			}
		}
		ents, _ := h.readDir("/etc/emond.d/rules")
		for _, e := range ents {
			if e.Name() != "SampleRules.plist" {
				p := filepath.Join("/etc/emond.d/rules", e.Name())
				out = append(out, hostItem{Cat: "hook", Key: p, Label: "event monitor rule " + p})
			}
		}
	}
	return out
}

var applePeriodicRe = regexp.MustCompile(`^\d{3}\.[a-z0-9.-]+$`)

func applePeriodic(name string) bool {
	return applePeriodicRe.MatchString(name)
}

// ---- remote control apps ----

var remoteApps = map[string]string{
	"AnyDesk.app": "AnyDesk", "TeamViewer.app": "TeamViewer", "TeamViewerHost.app": "TeamViewer Host", "TeamViewerQS.app": "TeamViewer QuickSupport",
	"RustDesk.app": "RustDesk", "UltraViewer.app": "UltraViewer", "ScreenConnect Client.app": "ScreenConnect", "ConnectWiseControl.app": "ScreenConnect",
	"LogMeIn Client.app": "LogMeIn", "GoTo Resolve.app": "GoTo Resolve", "Splashtop Streamer.app": "Splashtop", "Splashtop Business.app": "Splashtop",
	"Zoho Assist.app": "Zoho Assist", "RemotePC.app": "RemotePC", "Supremo.app": "Supremo", "AeroAdmin.app": "AeroAdmin", "Chrome Remote Desktop Host.app": "Chrome Remote Desktop",
	"NoMachine.app": "NoMachine", "Remote Utilities.app": "Remote Utilities", "ISL Light.app": "ISL Light", "Ammyy Admin.app": "Ammyy Admin",
}

func remoteAppItems(h *hostOS) []hostItem {
	var out []hostItem
	for _, dir := range []string{"/Applications", filepath.Join(h.home, "Applications"), filepath.Join(h.home, "Downloads"), "/Applications/Utilities"} {
		ents, _ := h.readDir(dir)
		for _, e := range ents {
			if name, ok := remoteApps[e.Name()]; ok {
				p := filepath.Join(dir, e.Name())
				it := hostItem{Cat: "remoteapp", Key: p, Label: name + " (" + p + ")"}
				if strings.HasSuffix(dir, "Downloads") {
					it.Sev = sevHigh
					it.Label += ", run straight from Downloads, which is how scammers ask for it"
				}
				out = append(out, it)
			}
		}
	}
	return out
}

// round5HostItems gathers the items above for the host check.
func round5HostItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	if h.goos == "darwin" {
		out = append(out, parseUSB(h.run(ctx, "system_profiler", "-json", "SPUSBDataType", "SPUSBHostDataType", "SPThunderboltDataType"))...)
	}
	if h.goos == "darwin" || h.goos == "linux" {
		for _, f := range []string{filepath.Join(h.home, ".ssh/authorized_keys"), filepath.Join(h.home, ".ssh/authorized_keys2")} {
			if data, err := h.readFile(f); err == nil {
				out = append(out, parseAuthorizedKeys(string(data), f)...)
			}
		}
		out = append(out, shellItems(h)...)
		if data, err := h.readFile("/etc/hosts"); err == nil {
			out = append(out, parseHostsFile(string(data))...)
		}
		out = append(out, hookItems(ctx, h)...)
	}
	if h.goos == "darwin" {
		out = append(out, remoteAppItems(h)...)
	}
	return out
}

// ---- browser safety settings (self check) ----

// chromeSafeBrowsingOff reads a Chrome-family Preferences file.
func chromeSafeBrowsingOff(data []byte) bool {
	var p struct {
		SafeBrowsing *struct {
			Enabled *bool `json:"enabled"`
		} `json:"safebrowsing"`
	}
	if json.Unmarshal(data, &p) != nil || p.SafeBrowsing == nil || p.SafeBrowsing.Enabled == nil {
		return false
	}
	return !*p.SafeBrowsing.Enabled
}

func browserSafetyFindings(ctx context.Context, run runner, h *hostOS) []*Finding {
	var out []*Finding
	v := run(ctx, "defaults", "read", filepath.Join(h.home, "Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari"), "AutoOpenSafeDownloads")
	if v == "" || strings.Contains(v, "does not exist") {
		v = run(ctx, "defaults", "read", "com.apple.Safari", "AutoOpenSafeDownloads")
	}
	if strings.TrimSpace(v) == "1" {
		out = append(out, &Finding{ID: "self:safari-auto-open", Severity: sevMedium,
			Title: "Safari opens downloaded files by itself",
			Fix:   "In Safari > Settings > General, untick \"Open 'safe' files after downloading\". Malware has used this to run as soon as a page downloads it."})
	}
	base := filepath.Join(h.home, "Library/Application Support")
	for _, sub := range sortedKeys(chromeBrowsers) {
		root := filepath.Join(base, sub)
		profiles, err := h.readDir(root)
		if err != nil {
			continue
		}
		for _, p := range profiles {
			if !p.IsDir() || (p.Name() != "Default" && !strings.HasPrefix(p.Name(), "Profile ")) {
				continue
			}
			data, err := h.readFile(filepath.Join(root, p.Name(), "Preferences"))
			if err == nil && chromeSafeBrowsingOff(data) {
				out = append(out, &Finding{ID: "self:safebrowsing-off:" + chromeBrowsers[sub] + ":" + p.Name(), Severity: sevMedium,
					Title: fmt.Sprintf("%s's protection against dangerous sites and downloads (Safe Browsing) is off (%s profile)", chromeBrowsers[sub], p.Name()),
					Fix:   "Turn it back on: Settings > Privacy and security > Security > Standard protection (or Enhanced)."})
			}
		}
	}
	return out
}
