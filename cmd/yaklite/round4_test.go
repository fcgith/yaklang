package main

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineAbsorbsNewKinds(t *testing.T) {
	old := &hostBaseline{Items: map[string]bool{}, Review: map[string]bool{}}
	start := hostItem{Cat: "startup", Key: "a", Label: "a"}
	old.Items[start.id()] = true
	ext := hostItem{Cat: "extension", Key: "Chrome:x", Label: "X in Chrome"}
	bad := hostItem{Cat: "extension", Key: "Chrome:y", Label: "Y", Sev: sevHigh}
	items := []hostItem{start, ext, bad}
	if !old.absorbNewCats(items) {
		t.Fatal("expected a change")
	}
	fs := hostFindings(items, old)
	// the existing plain extension is quiet; the risky one is a review item
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Title, "Please check") || fs[0].Severity != sevMedium {
		t.Fatalf("%+v", fs)
	}
	if old.absorbNewCats(items) {
		t.Error("second run should change nothing")
	}
	newExt := hostItem{Cat: "extension", Key: "Chrome:z", Label: "Z in Chrome"}
	fs = hostFindings(append(items, newExt), old)
	found := false
	for _, f := range fs {
		if strings.Contains(f.Title, "New browser extension: Z in Chrome") {
			found = true
		}
	}
	if !found {
		t.Errorf("%+v", fs)
	}
}

func TestExtensionParsers(t *testing.T) {
	ff := []byte(`{"addons":[
	 {"id":"ublock@x","type":"extension","location":"app-profile","defaultLocale":{"name":"uBlock"},"userPermissions":{"origins":["<all_urls>"]},"signedState":2},
	 {"id":"side@x","type":"extension","location":"app-profile","defaultLocale":{"name":"Side"},"signedState":0},
	 {"id":"sys@x","type":"extension","location":"app-system-defaults","signedState":2}]}`)
	items := parseFirefoxExtensions(ff)
	if len(items) != 2 || !strings.Contains(items[0].Label, "every website") || items[1].Sev != sevHigh {
		t.Errorf("%+v", items)
	}
	pk := "+    com.example.Blocker.Extension(1.2)\tABCD-1234\t2024-01-01 00:00:00 +0000\t/Applications/Blocker.app/Contents/PlugIns/Blocker Extension.appex\n"
	s := parseSafariExtensions(pk)
	if len(s) != 1 || !strings.Contains(s[0].Label, "Blocker in Safari") {
		t.Errorf("%+v", s)
	}
	m := chromeManifest{UpdateURL: "https://clients2.google.com/service/update2/crx"}
	if !m.fromStore() {
		t.Error("store extension")
	}
}

func TestParseTCC(t *testing.T) {
	out := "kTCCServiceScreenCapture|us.zoom.xos|2\nkTCCServiceCamera|com.apple.FaceTime|2\nkTCCServiceMicrophone|com.x|0\nkTCCServiceAccessibility|/tmp/.x/agent|2\n"
	items := parseTCC(out)
	if len(items) != 2 || items[1].Sev != sevHigh {
		t.Fatalf("%+v", items)
	}
}

func TestBackupFindings(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	if fs := backupFindings("No destinations configured.", "", "", now); len(fs) != 1 || fs[0].ID != "self:no-backup" {
		t.Errorf("%+v", fs)
	}
	if fs := backupFindings("", "", "", now); fs != nil {
		t.Errorf("unknown should say nothing: %+v", fs)
	}
	prefs := `{
    AutoBackup = 0;
    Destinations =     (
                {
            LastKnownEncryptionState = NotEncrypted;
            SnapshotDates =             (
                "2026-10-01 10:00:00 +0000",
                "2026-10-02 10:00:00 +0000"
            );
        }
    );
}`
	fs := backupFindings("Name : Backup\nKind : Local", prefs, "", now)
	ids := map[string]string{}
	for _, f := range fs {
		ids[f.ID] = f.Severity
	}
	if ids["self:backup-manual"] == "" || ids["self:backup-old"] != sevMedium || ids["self:backup-unencrypted"] == "" {
		t.Errorf("%+v", ids)
	}
	fs = backupFindings("Name : Backup", "AutoBackup = 1;", "/Volumes/B/Backups.backupdb/mac/2026-10-14-080000", now)
	if len(fs) != 0 {
		t.Errorf("%+v", fs)
	}
}

func TestAppleProtection(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	items := parseInstallHistory(`{"SPInstallHistoryDataType":[
	 {"_name":"XProtectPlistConfigData","install_date":"2026-07-01T00:00:00Z"},
	 {"_name":"macOS Sequoia 15.6","install_date":"2026-09-01T00:00:00Z"}]}`)
	fs := appleProtectionFindings(items, now)
	if len(fs) != 1 || fs[0].ID != "self:xprotect-old" {
		t.Errorf("%+v", fs)
	}
}

func TestSpctlVerdict(t *testing.T) {
	cases := map[string]string{
		"/Applications/X.app: accepted\nsource=Notarized Developer ID": "notarized",
		"/Applications/X.app: accepted\nsource=Mac App Store":          "app-store",
		"/Applications/X.app: rejected\nsource=no usable signature":    "unsigned",
		"/Applications/X.app: accepted\nsource=Developer ID":           "signed",
		"": "",
	}
	for in, want := range cases {
		if got := spctlVerdict(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestAppMemoryAndFindings(t *testing.T) {
	dir := t.TempDir()
	mk := func(name, body string) appFile {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		st, _ := os.Stat(p)
		return appFile{Path: p, Kind: "download", Exe: p, Mod: st.ModTime(), Size: st.Size()}
	}
	verdicts := map[string]string{}
	run := func(_ context.Context, name string, args ...string) string {
		if name == "spctl" {
			return verdicts[args[len(args)-1]]
		}
		if name == "mdls" {
			return "(\n    \"https://bad.example/x.dmg\",\n    \"https://bad.example/\"\n)"
		}
		return ""
	}
	a := mk("old.dmg", "old")
	mem := &appMemory{Apps: map[string]*appRecord{}}
	now := time.Now()
	verdicts[a.Path] = "x: rejected"
	updateAppMemory(context.Background(), run, mem, []appFile{a}, now)
	if fs := appFindings(mem, nil); len(fs) != 0 {
		t.Fatalf("first run should be quiet: %+v", fs)
	}
	b := mk("new.dmg", "evil")
	verdicts[b.Path] = "x: rejected"
	updateAppMemory(context.Background(), run, mem, []appFile{a, b}, now)
	fs := appFindings(mem, nil)
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "new.dmg") || !strings.Contains(fs[0].Detail, "https://bad.example/x.dmg") {
		t.Fatalf("%+v", fs)
	}
	bad := map[string]bool{mem.Apps[a.Path].SHA: true}
	fs = appFindings(mem, bad)
	if len(fs) != 2 || fs[1].Severity != sevHigh && fs[0].Severity != sevHigh {
		t.Fatalf("%+v", fs)
	}
	// removed files are forgotten
	updateAppMemory(context.Background(), run, mem, []appFile{a}, now)
	if len(mem.Apps) != 1 {
		t.Error(len(mem.Apps))
	}
	if plistString([]byte("<key>CFBundleExecutable</key>\n\t<string>Foo</string>"), "CFBundleExecutable") != "Foo" {
		t.Error("plist")
	}
}

func TestSiteLists(t *testing.T) {
	l := &siteLists{hosts: map[string]string{}, urls: map[string]string{}}
	parseSiteFeed(bufio.NewScanner(strings.NewReader("# hosts\n127.0.0.1\tlocalhost\n127.0.0.1\tmalware.example\n127.0.0.1\tgithub.com\n")), "urlhaus-hosts", "hosts", l)
	parseSiteFeed(bufio.NewScanner(strings.NewReader("https://docs.google.com/forms/d/phish/\n")), "openphish", "urls", l)
	if n, ok := l.match("http://malware.example/a.exe"); !ok || n != "urlhaus-hosts" {
		t.Error("host match")
	}
	if _, ok := l.match("https://github.com/someone/project"); ok {
		t.Error("shared hosts only match exact pages")
	}
	if n, ok := l.match("https://docs.google.com/forms/d/phish#x"); !ok || n != "openphish" {
		t.Error("url match")
	}
	if _, ok := l.match("https://docs.google.com/forms/d/other"); ok {
		t.Error("other page on a shared host")
	}
	vs := parseVisits("https://a.example/|13300000000000000\nbroken\nhttps://b.example/?q=a|b|13300000000000001\n", "Chrome", chromeTime)
	if len(vs) != 2 || vs[1].URL != "https://b.example/?q=a|b" || vs[0].Time.Year() < 2020 {
		t.Errorf("%+v", vs)
	}
	f := siteHitFinding(siteHit{URL: "https://phish.example/login", Browser: "Safari", List: "openphish", Time: time.Now()})
	if f.Severity != sevMedium || !strings.Contains(f.Title, "phish.example") {
		t.Errorf("%+v", f)
	}
}

func TestVPNDetection(t *testing.T) {
	run := func(out map[string]string) runner {
		return func(_ context.Context, name string, args ...string) string {
			return out[name+" "+strings.Join(args, " ")]
		}
	}
	if !vpnActive(context.Background(), run(map[string]string{"scutil --nc list": "* (Connected) ABC IPSec \"Work\""})) {
		t.Error("connected service")
	}
	if !tunnelIface("utun4") || tunnelIface("en0") {
		t.Error("tunnel names")
	}
}

func TestFirstOnline(t *testing.T) {
	mem := &connMemory{Countries: map[string]time.Time{}, Programs: map[string]time.Time{}}
	v := connView{sock: sock{RemoteIP: net.ParseIP("8.8.8.8"), RemotePort: 443, Process: "Zoom"}}
	if fs := firstOnlineFindings(mem, []connView{v}, time.Now(), true); len(fs) != 0 {
		t.Error("learning")
	}
	v2 := connView{sock: sock{RemoteIP: net.ParseIP("1.1.1.1"), RemotePort: 443, Process: "Stealer"}}
	fs := firstOnlineFindings(mem, []connView{v, v2}, time.Now(), false)
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "Stealer") {
		t.Errorf("%+v", fs)
	}
	if fs := firstOnlineFindings(mem, []connView{v2}, time.Now(), false); len(fs) != 0 {
		t.Error("only the first time")
	}
}

func TestIncidentReport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	rep := incidentReport(context.Background(), dir, time.Now())
	for _, want := range []string{"WHAT TO DO", "SAFETY SCORE", "OPEN PROBLEMS", "INTERNET CONNECTIONS"} {
		if !strings.Contains(rep, want) {
			t.Errorf("missing %s", want)
		}
	}
}
