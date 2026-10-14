package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// More of the Mac's insides: browser extensions, apps holding sensitive
// permissions (screen recording, accessibility, full disk access, camera,
// microphone), Apple's own malware protection being current, Find My and
// sharing settings, and Time Machine backups.

func init() {
	hostCats["extension"] = hostCat{sevMedium, false, "New browser extension: %s", "",
		"Extensions can read what you type and see on websites; bad ones steal passwords and bank logins.",
		"If you did not just add it, remove it in the browser's extensions page (Safari: Settings > Extensions; Chrome: chrome://extensions). Then change the passwords you typed since it arrived."}
	hostCats["permission"] = hostCat{sevMedium, false, "%s", "",
		"Spyware needs exactly these permissions: to see the screen, control the Mac, read all files or listen.",
		"If you do not know why this app needs it, turn it off in System Settings > Privacy & Security, in the section named above."}
}

// ---- browser extensions ----

type chromeManifest struct {
	Name            string   `json:"name"`
	DefaultLocale   string   `json:"default_locale"`
	UpdateURL       string   `json:"update_url"`
	Permissions     []any    `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`
	ContentScripts  []struct {
		Matches []string `json:"matches"`
	} `json:"content_scripts"`
}

func allSites(patterns []string) bool {
	for _, p := range patterns {
		switch p {
		case "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "https://*/":
			return true
		}
	}
	return false
}

func (m chromeManifest) readsAllSites() bool {
	var ps []string
	for _, p := range m.Permissions {
		if s, ok := p.(string); ok {
			ps = append(ps, s)
		}
	}
	ps = append(ps, m.HostPermissions...)
	for _, cs := range m.ContentScripts {
		ps = append(ps, cs.Matches...)
	}
	return allSites(ps)
}

func (m chromeManifest) fromStore() bool {
	u := strings.ToLower(m.UpdateURL)
	return strings.Contains(u, "clients2.google.com") || strings.Contains(u, "edge.microsoft.com") || strings.Contains(u, "extensionupdate.microsoft.com")
}

var chromeBrowsers = map[string]string{
	"Google/Chrome":                 "Chrome",
	"Google/Chrome Beta":            "Chrome Beta",
	"BraveSoftware/Brave-Browser":   "Brave",
	"Microsoft Edge":                "Edge",
	"Chromium":                      "Chromium",
	"Vivaldi":                       "Vivaldi",
	"Arc/User Data":                 "Arc",
	"com.operasoftware.Opera":       "Opera",
	"google-chrome":                 "Chrome",
	"BraveSoftware/Brave-Browser-B": "Brave Beta",
}

// chromeExtName resolves "__MSG_name__" through the extension's _locales.
func chromeExtName(h *hostOS, dir string, m chromeManifest) string {
	name := m.Name
	if strings.HasPrefix(name, "__MSG_") && strings.HasSuffix(name, "__") {
		key := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
		for _, loc := range []string{m.DefaultLocale, "en", "en_US"} {
			if loc == "" {
				continue
			}
			data, err := h.readFile(filepath.Join(dir, "_locales", loc, "messages.json"))
			if err != nil {
				continue
			}
			var msgs map[string]struct {
				Message string `json:"message"`
			}
			json.Unmarshal(data, &msgs)
			for k, v := range msgs {
				if strings.EqualFold(k, key) && v.Message != "" {
					return v.Message
				}
			}
		}
	}
	return name
}

func chromeExtensionItems(h *hostOS, base string) []hostItem {
	var out []hostItem
	for sub, browser := range chromeBrowsers {
		root := filepath.Join(base, sub)
		profiles, err := h.readDir(root)
		if err != nil {
			continue
		}
		for _, p := range profiles {
			if !p.IsDir() || (p.Name() != "Default" && !strings.HasPrefix(p.Name(), "Profile ")) {
				continue
			}
			extDir := filepath.Join(root, p.Name(), "Extensions")
			exts, err := h.readDir(extDir)
			if err != nil {
				continue
			}
			for _, e := range exts {
				if !e.IsDir() || e.Name() == "Temp" {
					continue
				}
				vers, err := h.readDir(filepath.Join(extDir, e.Name()))
				if err != nil || len(vers) == 0 {
					continue
				}
				vdir := filepath.Join(extDir, e.Name(), vers[len(vers)-1].Name())
				data, err := h.readFile(filepath.Join(vdir, "manifest.json"))
				if err != nil {
					continue
				}
				var m chromeManifest
				if json.Unmarshal(data, &m) != nil {
					continue
				}
				out = append(out, extensionItem(browser, e.Name(), chromeExtName(h, vdir, m), m.readsAllSites(), !m.fromStore()))
			}
		}
	}
	return out
}

func extensionItem(browser, id, name string, all, outsideStore bool) hostItem {
	it := hostItem{Cat: "extension", Key: browser + ":" + id, Label: fmt.Sprintf("%s in %s", orStr(name, id), browser)}
	if all {
		it.Label += ", which can read and change every website you visit"
	}
	if outsideStore {
		it.Label += ", installed from outside the browser's store"
		it.Sev = sevHigh
	}
	return it
}

func firefoxExtensionItems(h *hostOS, base string) []hostItem {
	var out []hostItem
	profiles, err := h.readDir(filepath.Join(base, "Profiles"))
	if err != nil {
		return nil
	}
	for _, p := range profiles {
		data, err := h.readFile(filepath.Join(base, "Profiles", p.Name(), "extensions.json"))
		if err != nil {
			continue
		}
		out = append(out, parseFirefoxExtensions(data)...)
	}
	return out
}

func parseFirefoxExtensions(data []byte) []hostItem {
	var f struct {
		Addons []struct {
			ID            string `json:"id"`
			Type          string `json:"type"`
			Location      string `json:"location"`
			Active        bool   `json:"active"`
			DefaultLocale struct {
				Name string `json:"name"`
			} `json:"defaultLocale"`
			UserPermissions struct {
				Origins []string `json:"origins"`
			} `json:"userPermissions"`
			SignedState int `json:"signedState"`
		} `json:"addons"`
	}
	if json.Unmarshal(data, &f) != nil {
		return nil
	}
	var out []hostItem
	for _, a := range f.Addons {
		if a.Type != "extension" || !strings.HasPrefix(a.Location, "app-profile") {
			continue // built-in and system add-ons
		}
		out = append(out, extensionItem("Firefox", a.ID, a.DefaultLocale.Name, allSites(a.UserPermissions.Origins), a.SignedState <= 0))
	}
	return out
}

// pluginkit lists Safari web extensions: "+    com.example.ext(1.2)\tUUID\tdate\t/path/Ext.appex"
var pluginkitRe = regexp.MustCompile(`^\s*[+!-=]?\s*([A-Za-z0-9._-]+)\(([^)]*)\)\s+\S+\s+.*?\s(/\S.*\.appex)\s*$`)

func parseSafariExtensions(s string) []hostItem {
	var out []hostItem
	for _, line := range strings.Split(s, "\n") {
		m := pluginkitRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		app := m[3]
		if i := strings.Index(app, ".app/"); i > 0 {
			app = filepath.Base(app[:i+4])
		}
		out = append(out, extensionItem("Safari", m[1], strings.TrimSuffix(app, ".app"), false, false))
	}
	return out
}

func extensionItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	switch h.goos {
	case "darwin":
		as := filepath.Join(h.home, "Library/Application Support")
		out = append(out, chromeExtensionItems(h, as)...)
		out = append(out, firefoxExtensionItems(h, filepath.Join(as, "Firefox"))...)
		out = append(out, parseSafariExtensions(h.run(ctx, "pluginkit", "-mAvvv", "-p", "com.apple.Safari.web-extension"))...)
	case "linux":
		out = append(out, chromeExtensionItems(h, filepath.Join(h.home, ".config"))...)
		out = append(out, firefoxExtensionItems(h, filepath.Join(h.home, ".mozilla/firefox"))...)
	}
	return out
}

// ---- privacy permissions (TCC) ----

var tccServices = map[string]string{
	"kTCCServiceScreenCapture":        "Screen Recording",
	"kTCCServiceAccessibility":        "Accessibility (can control the Mac)",
	"kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
	"kTCCServiceListenEvent":          "Input Monitoring (can see every key you press)",
	"kTCCServicePostEvent":            "Accessibility (can send key presses)",
	"kTCCServiceMicrophone":           "Microphone",
	"kTCCServiceCamera":               "Camera",
	"kTCCServiceRemoteDesktop":        "Remote Desktop control",
}

var tccHigh = map[string]bool{"kTCCServiceScreenCapture": true, "kTCCServiceAccessibility": true, "kTCCServiceListenEvent": true, "kTCCServiceSystemPolicyAllFiles": true, "kTCCServicePostEvent": true}

// parseTCC reads `sqlite3 -separator '|' TCC.db "select service, client, auth_value ..."` output.
func parseTCC(s string) []hostItem {
	var out []hostItem
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		f := strings.Split(line, "|")
		if len(f) < 3 || strings.TrimSpace(f[2]) != "2" {
			continue // 2 = allowed
		}
		svc, client := f[0], f[1]
		what, ok := tccServices[svc]
		if !ok || isOwnClient(client) {
			continue
		}
		name := client
		if strings.HasPrefix(client, "/") {
			name = filepath.Base(client)
		}
		it := hostItem{Cat: "permission", Key: svc + ":" + client, Label: fmt.Sprintf("%s was given %s permission", name, what)}
		if strings.HasPrefix(client, "/") && suspiciousPath(client) {
			it.Sev = sevHigh
			it.Label += ", and it runs from a temporary or hidden folder"
		} else if tccHigh[svc] && strings.HasPrefix(client, "/") && !strings.HasPrefix(client, "/Applications/") && !strings.HasPrefix(client, "/System/") && !strings.HasPrefix(client, "/usr/") {
			it.Label += " (a program outside Applications)"
		}
		out = append(out, it)
	}
	return out
}

func isOwnClient(c string) bool {
	return strings.Contains(c, "/yaklite") || strings.HasPrefix(c, "com.apple.") || strings.HasPrefix(c, "/System/") || strings.HasPrefix(c, "/usr/libexec/")
}

const tccQuery = "select service, client, auth_value from access"

// tccItems returns the apps holding sensitive permissions, and whether the
// permission databases could be read (they need Full Disk Access).
func tccItems(ctx context.Context, h *hostOS) ([]hostItem, bool) {
	if h.goos != "darwin" {
		return nil, true
	}
	var out []hostItem
	readable := false
	for _, db := range []string{filepath.Join(h.home, "Library/Application Support/com.apple.TCC/TCC.db"), "/Library/Application Support/com.apple.TCC/TCC.db"} {
		res := h.run(ctx, "sqlite3", "-readonly", "-separator", "|", db, tccQuery)
		if strings.Contains(res, "unable to open") || strings.Contains(res, "authorization denied") || strings.Contains(res, "Error") {
			continue
		}
		readable = true
		out = append(out, parseTCC(res)...)
	}
	return out, readable
}

func tccUnreadableFinding() *Finding {
	bin := installedBinPath()
	return &Finding{ID: "host:permissions-unreadable", Severity: sevLow,
		Title: "yaklite cannot see which apps have screen, microphone or full disk permissions",
		Fix:   "Give yaklite Full Disk Access: System Settings > Privacy & Security > Full Disk Access > +, press Cmd+Shift+G and paste " + bin + ". yaklite only reads the permission list; it changes nothing."}
}

// ---- Apple's protection, Find My, sharing, backups (self check) ----

type installEntry struct {
	Name    string `json:"_name"`
	Date    string `json:"install_date"`
	Version string `json:"install_version"`
	Source  string `json:"package_source"`
}

func parseInstallHistory(js string) []installEntry {
	var r struct {
		Items []installEntry `json:"SPInstallHistoryDataType"`
	}
	json.Unmarshal([]byte(js), &r)
	return r.Items
}

func latestInstall(items []installEntry, match func(string) bool) time.Time {
	var t time.Time
	for _, it := range items {
		if !match(it.Name) {
			continue
		}
		d, err := time.Parse(time.RFC3339, it.Date)
		if err != nil {
			continue
		}
		if d.After(t) {
			t = d
		}
	}
	return t
}

// appleProtectionFindings checks that XProtect and macOS updates are recent.
func appleProtectionFindings(items []installEntry, now time.Time) []*Finding {
	if len(items) == 0 {
		return nil
	}
	var out []*Finding
	xp := latestInstall(items, func(n string) bool { return strings.HasPrefix(n, "XProtect") })
	if !xp.IsZero() {
		if days := int(now.Sub(xp).Hours() / 24); days > 30 {
			out = append(out, &Finding{ID: "self:xprotect-old", Severity: sevMedium,
				Title: fmt.Sprintf("Apple's built-in malware protection (XProtect) has not updated in %d days", days),
				Fix:   "Turn on \"Install Security Responses and system files\" in System Settings > General > Software Update > Automatic updates, then restart. Updates arrive within a day once it is on."})
		}
	}
	sysUpd := latestInstall(items, func(n string) bool {
		return strings.HasPrefix(n, "macOS") || strings.Contains(n, "Security Response") || strings.Contains(n, "Background Security")
	})
	if !sysUpd.IsZero() {
		if days := int(now.Sub(sysUpd).Hours() / 24); days > 75 {
			out = append(out, &Finding{ID: "self:macos-update-old", Severity: sevMedium,
				Title: fmt.Sprintf("No macOS update has been installed in %d days", days),
				Fix:   "Open System Settings > General > Software Update and install what it offers. Apple fixes actively exploited flaws in these updates."})
		}
	}
	return out
}

type tmDestination struct {
	SnapshotDates            []time.Time `json:"SnapshotDates"`
	LastKnownEncryptionState string      `json:"LastKnownEncryptionState"`
}

// backupFindings judges Time Machine's settings (plutil -convert json of
// /Library/Preferences/com.apple.TimeMachine.plist).
func backupFindings(js string, now time.Time) []*Finding {
	var tm struct {
		AutoBackup   *bool           `json:"AutoBackup"`
		Destinations []tmDestination `json:"Destinations"`
	}
	if strings.TrimSpace(js) == "" || json.Unmarshal([]byte(js), &tm) != nil || len(tm.Destinations) == 0 {
		return []*Finding{{ID: "self:no-backup", Severity: sevMedium,
			Title: "No Time Machine backup is set up",
			Fix:   "Plug in an external drive and choose it in System Settings > General > Time Machine, with \"Encrypt backup\" on. A recent backup is the only real answer to ransomware. If you use another backup service, acknowledge this alert."}}
	}
	var out []*Finding
	var last time.Time
	encrypted := true
	for _, d := range tm.Destinations {
		for _, t := range d.SnapshotDates {
			if t.After(last) {
				last = t
			}
		}
		if d.LastKnownEncryptionState == "NotEncrypted" {
			encrypted = false
		}
	}
	if tm.AutoBackup != nil && !*tm.AutoBackup {
		out = append(out, &Finding{ID: "self:backup-manual", Severity: sevLow,
			Title: "Time Machine only backs up when you ask it to",
			Fix:   "Turn on automatic backups in System Settings > General > Time Machine > Options."})
	}
	switch days := int(now.Sub(last).Hours() / 24); {
	case last.IsZero():
		out = append(out, &Finding{ID: "self:backup-never", Severity: sevMedium,
			Title: "Time Machine is set up but has never finished a backup",
			Fix:   "Connect the backup drive and choose \"Back Up Now\" from the Time Machine menu."})
	case days >= 7:
		out = append(out, &Finding{ID: "self:backup-old", Severity: sevMedium,
			Title: fmt.Sprintf("The last Time Machine backup was %d days ago", days),
			Fix:   "Connect the backup drive (or wake the backup disk on the network) and let it run. Ransomware recovery is only as good as the latest backup."})
	case days >= 3:
		out = append(out, &Finding{ID: "self:backup-old", Severity: sevLow,
			Title: fmt.Sprintf("The last Time Machine backup was %d days ago", days),
			Fix:   "Connect the backup drive when you can."})
	}
	if !encrypted {
		out = append(out, &Finding{ID: "self:backup-unencrypted", Severity: sevLow,
			Title: "The Time Machine backup is not encrypted, so anyone with the drive can read your files",
			Fix:   "Time Machine can only encrypt a new backup: remove the disk in System Settings > General > Time Machine, add it again and tick \"Encrypt backup\"."})
	}
	return out
}

var screenLockRe = regexp.MustCompile(`screenLock delay is (\d+) seconds`)

// macExtraSelfCheck covers Find My, sharing, screen lock, auto login,
// Apple's protection, backups and an outgoing firewall.
func macExtraSelfCheck(ctx context.Context, run runner, now time.Time, exists func(string) bool) []*Finding {
	var out []*Finding
	if nv := run(ctx, "nvram", "-x", "-p"); nv != "" && !strings.Contains(nv, "fmm-mobileme-token-FMM") {
		out = append(out, &Finding{ID: "self:findmy-off", Severity: sevMedium,
			Title: "Find My Mac is off, so a lost or stolen Mac cannot be located, locked or wiped",
			Fix:   "Turn it on in System Settings > (your name) > iCloud > Find My Mac. It also turns on Activation Lock, which makes a stolen Mac useless to a thief."})
	}
	if m := run(ctx, "defaults", "read", "com.apple.sharingd", "DiscoverableMode"); m == "Everyone" {
		out = append(out, &Finding{ID: "self:airdrop-everyone", Severity: sevLow,
			Title: "AirDrop accepts from everyone, so strangers nearby can send you files and pictures",
			Fix:   "Set AirDrop to \"Contacts Only\" in System Settings > General > AirDrop & Handoff."})
	}
	if b := run(ctx, "defaults", "-currentHost", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"); b == "1" {
		out = append(out, &Finding{ID: "self:bluetooth-sharing", Severity: sevLow,
			Title: "Bluetooth Sharing is on, so nearby devices can send files to this Mac",
			Fix:   "Turn it off in System Settings > General > Sharing > Bluetooth Sharing."})
	}
	if u := run(ctx, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"); u != "" && !strings.Contains(u, "does not exist") {
		out = append(out, &Finding{ID: "self:auto-login", Severity: sevHigh,
			Title: "The Mac logs in by itself at startup, without asking for a password",
			Fix:   "Turn off automatic login in System Settings > Users & Groups. Disk encryption cannot protect a Mac that logs itself in."})
	}
	if sl := run(ctx, "sysadminctl", "-screenLock", "status"); sl != "" {
		if strings.Contains(sl, "screenLock is off") {
			out = append(out, &Finding{ID: "self:screenlock-off", Severity: sevMedium,
				Title: "The Mac does not ask for a password when it wakes up",
				Fix:   "In System Settings > Lock Screen, set \"Require password after screen saver begins or display is turned off\" to \"Immediately\"."})
		} else if m := screenLockRe.FindStringSubmatch(sl); m != nil {
			var secs int
			fmt.Sscan(m[1], &secs)
			if secs > 300 {
				out = append(out, &Finding{ID: "self:screenlock-slow", Severity: sevLow,
					Title: fmt.Sprintf("The Mac only asks for a password %d minutes after the screen turns off", secs/60),
					Fix:   "In System Settings > Lock Screen, set the password requirement to \"Immediately\" or a few seconds."})
			}
		}
	}
	out = append(out, appleProtectionFindings(parseInstallHistory(run(ctx, "system_profiler", "-json", "SPInstallHistoryDataType")), now)...)
	out = append(out, backupFindings(run(ctx, "plutil", "-convert", "json", "-o", "-", "/Library/Preferences/com.apple.TimeMachine.plist"), now)...)
	if !exists("/Applications/LuLu.app") && !exists("/Applications/Little Snitch.app") && !exists("/Applications/Little Snitch Mini.app") {
		out = append(out, &Finding{ID: "self:no-outgoing-firewall", Severity: sevInfo,
			Title: "Nothing asks before an app connects out to the internet",
			Fix:   "The Mac firewall only stops connections coming in. LuLu (free, open source, objective-see.org) asks before an unknown app connects out, so you can block it. yaklite cannot do this itself without a special permission from Apple."})
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// sortedKeys is a small helper for stable output.
func sortedKeys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
