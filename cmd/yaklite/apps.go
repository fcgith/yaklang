package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The apps check looks at the apps in /Applications and ~/Applications and
// at what is in ~/Downloads:
//
//   - a new app or download that Apple has not checked (not notarized, or
//     not signed at all), with the website it came from when macOS knows it
//   - an app whose signature stopped matching (something changed its files)
//   - a file whose fingerprint (SHA-256) is on MalwareBazaar's list of
//     recent malware, which yaklite downloads and keeps adding to locally
//
// Only fingerprints are compared; no file leaves the computer.

func init() {
	registerCheck(&check{name: "apps", about: "apps and downloads that Apple has not checked, changed apps, and known malware (MalwareBazaar list)", run: appsCheck})
}

const bazaarURL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

type appRecord struct {
	Kind    string    `json:"kind"` // app, download
	Mod     time.Time `json:"mod"`
	Size    int64     `json:"size"`
	Verdict string    `json:"verdict"` // apple, app-store, notarized, signed, unsigned, or "" (not assessed)
	SHA     string    `json:"sha,omitempty"`
	From    string    `json:"from,omitempty"`
	First   time.Time `json:"first"`
	Flag    string    `json:"flag,omitempty"` // new-unchecked, changed
}

type appMemory struct {
	Created time.Time             `json:"created"`
	Apps    map[string]*appRecord `json:"apps"`
}

func appMemoryPath(dir string) string { return filepath.Join(dir, "apps-memory.json") }

func loadAppMemory(dir string) *appMemory {
	m := &appMemory{}
	if data, err := os.ReadFile(appMemoryPath(dir)); err == nil {
		json.Unmarshal(data, m)
	}
	if m.Apps == nil {
		m.Apps = map[string]*appRecord{}
	}
	return m
}

type appFile struct {
	Path string
	Kind string // app, download
	Exe  string // the file to fingerprint
	Mod  time.Time
	Size int64
}

var downloadExts = map[string]bool{".dmg": true, ".pkg": true, ".mpkg": true, ".zip": true, ".app": true, ".command": true, ".sh": true, ".jar": true, ".iso": true}

// appFiles lists the apps and the downloads worth a look.
func appFiles(h *hostOS) []appFile {
	var out []appFile
	for _, dir := range []string{"/Applications", filepath.Join(h.home, "Applications")} {
		ents, _ := h.readDir(dir)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if f, ok := appBundle(h, p, "app"); ok {
				out = append(out, f)
			}
		}
	}
	dl := filepath.Join(h.home, "Downloads")
	ents, _ := h.readDir(dl)
	type dent struct {
		e   os.DirEntry
		mod time.Time
	}
	var ds []dent
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") || !downloadExts[strings.ToLower(filepath.Ext(e.Name()))] {
			continue
		}
		if fi, err := e.Info(); err == nil {
			ds = append(ds, dent{e, fi.ModTime()})
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].mod.After(ds[j].mod) })
	if len(ds) > 300 {
		ds = ds[:300]
	}
	for _, d := range ds {
		p := filepath.Join(dl, d.e.Name())
		if strings.HasSuffix(d.e.Name(), ".app") {
			if f, ok := appBundle(h, p, "download"); ok {
				out = append(out, f)
			}
			continue
		}
		fi, err := d.e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, appFile{Path: p, Kind: "download", Exe: p, Mod: fi.ModTime(), Size: fi.Size()})
	}
	return out
}

// appBundle finds an app's main program, whose change means the app changed.
func appBundle(h *hostOS, p, kind string) (appFile, bool) {
	macos := filepath.Join(p, "Contents", "MacOS")
	ents, err := h.readDir(macos)
	if err != nil || len(ents) == 0 {
		return appFile{}, false
	}
	exe := ""
	if data, err := h.readFile(filepath.Join(p, "Contents", "Info.plist")); err == nil {
		exe = plistString(data, "CFBundleExecutable")
	}
	if exe == "" {
		exe = ents[0].Name()
	}
	exePath := filepath.Join(macos, exe)
	fi, err := os.Stat(exePath)
	if err != nil {
		return appFile{}, false
	}
	return appFile{Path: p, Kind: kind, Exe: exePath, Mod: fi.ModTime(), Size: fi.Size()}, true
}

// plistString reads a string value from an XML property list. Binary ones
// return "" (the caller falls back to the folder listing).
func plistString(data []byte, key string) string {
	re := regexp.MustCompile(`<key>` + regexp.QuoteMeta(key) + `</key>\s*<string>([^<]*)</string>`)
	if m := re.FindSubmatch(data); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// spctlVerdict turns Gatekeeper's answer into a short verdict.
func spctlVerdict(out string) string {
	switch {
	case out == "":
		return ""
	case strings.Contains(out, "rejected") || strings.Contains(out, "no usable signature") || strings.Contains(out, "not signed"):
		return "unsigned"
	case strings.Contains(out, "source=Apple System") || strings.Contains(out, "source=Apple\n") || strings.HasSuffix(out, "source=Apple"):
		return "apple"
	case strings.Contains(out, "source=Mac App Store") || strings.Contains(out, "source=Apple Store"):
		return "app-store"
	case strings.Contains(out, "source=Notarized"):
		return "notarized"
	case strings.Contains(out, "accepted"):
		return "signed"
	}
	return ""
}

func assessFile(ctx context.Context, run runner, f appFile) string {
	ext := strings.ToLower(filepath.Ext(f.Path))
	switch {
	case ext == ".app":
		return spctlVerdict(run(ctx, "spctl", "--assess", "--type", "execute", "-vv", f.Path))
	case ext == ".pkg" || ext == ".mpkg":
		return spctlVerdict(run(ctx, "spctl", "--assess", "--type", "install", "-vv", f.Path))
	case ext == ".dmg":
		return spctlVerdict(run(ctx, "spctl", "--assess", "--type", "open", "--context", "context:primary-signature", "-vv", f.Path))
	}
	return ""
}

var whereFromRe = regexp.MustCompile(`"([^"]+)"`)

// whereFrom asks macOS which website a download came from.
func whereFrom(ctx context.Context, run runner, p string) string {
	out := run(ctx, "mdls", "-raw", "-name", "kMDItemWhereFroms", p)
	if m := whereFromRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func fileSHA256(p string, max int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || fi.Size() > max {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// bazaarHashes keeps MalwareBazaar's recent list, adding each download to
// what was kept before so older entries still match. It returns the set.
func bazaarHashes(ctx context.Context, stateDir string, download bool) (map[string]bool, error) {
	dir := filepath.Join(stateDir, "threat-lists")
	os.MkdirAll(dir, 0o700)
	keep := filepath.Join(dir, "malwarebazaar-sha256.txt")
	set := map[string]bool{}
	readHashes(keep, set)
	var ferr error
	if st, err := os.Stat(keep); download && (err != nil || time.Since(st.ModTime()) > 6*time.Hour) {
		tmp := keep + ".new"
		if ferr = fetchToFile(ctx, bazaarURL, tmp); ferr == nil {
			readHashes(tmp, set)
			os.Remove(tmp)
			keys := sortedKeys(set)
			if len(keys) > 300000 {
				keys = keys[len(keys)-300000:]
			}
			writeFilePrivate(keep, []byte(strings.Join(keys, "\n")+"\n"))
		}
	}
	return set, ferr
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func readHashes(p string, set map[string]bool) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.ToLower(strings.TrimSpace(sc.Text()))
		if sha256Re.MatchString(l) {
			set[l] = true
		}
	}
}

func checkedByApple(v string) bool { return v == "apple" || v == "app-store" || v == "notarized" }

// updateAppMemory assesses new and changed files and flags what is worth
// an alert. On the first run nothing is flagged as new.
func updateAppMemory(ctx context.Context, run runner, mem *appMemory, files []appFile, now time.Time) {
	first := len(mem.Apps) == 0
	if mem.Created.IsZero() {
		mem.Created = now
	}
	present := map[string]bool{}
	for _, f := range files {
		present[f.Path] = true
		r := mem.Apps[f.Path]
		if r != nil && r.Mod.Equal(f.Mod) && r.Size == f.Size {
			continue
		}
		verdict := assessFile(ctx, run, f)
		nr := &appRecord{Kind: f.Kind, Mod: f.Mod, Size: f.Size, Verdict: verdict, First: now, SHA: fileSHA256(f.Exe, 300<<20)}
		if f.Kind == "download" {
			nr.From = whereFrom(ctx, run, f.Path)
		}
		switch {
		case r == nil && !first && verdict == "unsigned":
			nr.Flag = "new-unchecked"
		case r != nil:
			nr.First = r.First
			nr.Flag = r.Flag
			if checkedByApple(r.Verdict) && verdict == "unsigned" {
				nr.Flag = "changed"
			} else if verdict != "unsigned" && nr.Flag == "new-unchecked" {
				nr.Flag = ""
			}
		}
		mem.Apps[f.Path] = nr
	}
	for p := range mem.Apps {
		if !present[p] {
			delete(mem.Apps, p)
		}
	}
}

func appFindings(mem *appMemory, bad map[string]bool) []*Finding {
	var out []*Finding
	for _, p := range sortedKeys(mem.Apps) {
		r := mem.Apps[p]
		name := filepath.Base(p)
		from := ""
		if r.From != "" {
			from = " It came from " + r.From + "."
		}
		switch {
		case r.SHA != "" && bad[r.SHA]:
			out = append(out, &Finding{ID: "app-malware:" + r.SHA[:16], Severity: sevHigh,
				Title:  "Known malware found on this Mac: " + name,
				Detail: "Its fingerprint is on MalwareBazaar's list of recent malware. Location: " + p + "." + from,
				Fix:    "Do not open it. Move it to the Bin and empty the Bin. If it was already opened, disconnect from the internet, run `yaklite incident` and follow the steps, and change your passwords from another device."})
		case r.Flag == "changed":
			out = append(out, &Finding{ID: "app-changed:" + shortHash(p), Severity: sevHigh,
				Title:  "An app was changed after it was installed and Apple's check no longer matches: " + name,
				Detail: "Location: " + p + ". Malware sometimes hides inside a real app this way; a broken update can also cause it.",
				Fix:    "Delete the app and install it again from its maker's website or the App Store. If it keeps happening, run `yaklite incident`."})
		case r.Flag == "new-unchecked" && r.Kind == "app":
			out = append(out, &Finding{ID: "app-unchecked:" + shortHash(p), Severity: sevMedium,
				Title:  "A new app that Apple has not checked was installed: " + name,
				Detail: "Apps from known developers are checked by Apple for malware (notarized). This one is not." + from,
				Fix:    "If you did not install it on purpose, move it to the Bin. If you did, make sure it came from the maker's own website, then acknowledge this alert."})
		case r.Flag == "new-unchecked":
			out = append(out, &Finding{ID: "download-unchecked:" + shortHash(p), Severity: sevLow,
				Title:  "A download that Apple has not checked: " + name,
				Detail: "Fake installers and \"codec\" or \"player update\" downloads are the most common way Macs get infected." + from,
				Fix:    "Only open it if you trust where it came from. If you are not sure, delete it."})
		}
	}
	return out
}

func appsCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	h := realHostOS()
	if h.goos != "darwin" {
		return nil, nil
	}
	mem := loadAppMemory(env.stateDir)
	updateAppMemory(ctx, cmdOut, mem, appFiles(h), time.Now())
	if data, err := json.MarshalIndent(mem, "", "  "); err == nil {
		writeFilePrivate(appMemoryPath(env.stateDir), data)
	}
	bad, err := bazaarHashes(ctx, env.stateDir, env.opts != nil && env.opts.threatLists)
	if err != nil {
		env.warn(fmt.Sprintf("malware list: %v", err))
	}
	return appFindings(mem, bad), nil
}
