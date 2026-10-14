package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// The menu bar app (YakliteBar, macOS) shows the safety status, the top
// problems and new alerts. It talks to the local dashboard through
// /api/app/*, which only answers on this computer and only with the secret
// in ~/.config/yaklite/app-token.

const menubarAppName = "YakliteBar.app"

func menubarAppPath() string          { return filepath.Join(homeDir(), "Applications", menubarAppName) }
func menubarMarker() string           { return filepath.Join(configDir(), "menubar-installed") }
func appTokenPath() string            { return filepath.Join(configDir(), "app-token") }
func appConfigPath() string           { return filepath.Join(configDir(), "app.json") }
func appEventsPath(dir string) string { return filepath.Join(dir, "app-events.jsonl") }

type appConfig struct {
	Port int    `json:"port"`
	Bin  string `json:"bin"`
}

// readAppToken returns the saved app secret, or "" when there is none.
func readAppToken() string {
	data, err := os.ReadFile(appTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ensureAppToken creates the app secret if it does not exist yet.
func ensureAppToken() (string, error) {
	if t := readAppToken(); t != "" {
		return t, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := hex.EncodeToString(b)
	return t, writeFilePrivate(appTokenPath(), []byte(t+"\n"))
}

// menubarActive reports whether the menu bar app is installed, running and
// can reach the dashboard; then it shows alerts itself.
func menubarActive() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if _, err := os.Stat(menubarMarker()); err != nil {
		return false
	}
	if exec.Command("pgrep", "-x", "YakliteBar").Run() != nil {
		return false
	}
	port := 9842
	if data, err := os.ReadFile(appConfigPath()); err == nil {
		var c appConfig
		if json.Unmarshal(data, &c) == nil && c.Port > 0 {
			port = c.Port
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false // no dashboard, so the app cannot see new alerts
	}
	conn.Close()
	return true
}

// ---- yaklite menubar install|uninstall|status ----

func cmdMenubar(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: yaklite menubar install|uninstall|status|connect")
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("menubar install", flag.ExitOnError)
		port := fs.Int("port", 9842, "the dashboard's port")
		fs.Parse(args[1:])
		if err := installMenubar(*port); err != nil {
			return err
		}
		fmt.Println("The menu bar app is installed:", menubarAppPath())
		fmt.Println("Look for the shield at the top of the screen. It needs the dashboard, which `yaklite install` turns on.")
		return nil
	case "connect":
		// link an app that was opened by hand (the app's Setup runs this)
		fs := flag.NewFlagSet("menubar connect", flag.ExitOnError)
		port := fs.Int("port", 9842, "the dashboard's port")
		fs.Parse(args[1:])
		if err := connectMenubar(*port); err != nil {
			return err
		}
		fmt.Println("The menu bar app is linked to yaklite.")
		return nil
	case "uninstall":
		uninstallMenubar()
		fmt.Println("The menu bar app is removed. Alerts show as normal notifications again.")
		return nil
	case "status":
		return menubarStatus()
	}
	return fmt.Errorf("unknown menubar command %q (use install, uninstall, status or connect)", args[0])
}

func installMenubar(port int) error {
	if runtime.GOOS != "darwin" {
		return errors.New("the menu bar app is for macOS only")
	}
	if len(menubarZip) == 0 {
		return errors.New("this build does not include the menu bar app; download YakliteBar.zip from the release page and open it")
	}
	if port <= 0 || port > 65535 {
		return errors.New("bad port")
	}
	exec.Command("pkill", "-x", "YakliteBar").Run()
	appsDir := filepath.Dir(menubarAppPath())
	if err := os.MkdirAll(appsDir, 0o755); err != nil {
		return err
	}
	if err := extractMenubarApp(menubarZip, appsDir); err != nil {
		return fmt.Errorf("unpack the menu bar app: %w", err)
	}
	if err := connectMenubar(port); err != nil {
		return err
	}
	if err := exec.Command("open", menubarAppPath()).Run(); err != nil {
		fmt.Println("Could not start it; open", menubarAppPath(), "yourself.")
	}
	return nil
}

// connectMenubar writes what the app reads: app.json, the app secret and
// the marker that lets the app show the alerts.
func connectMenubar(port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("bad port")
	}
	bin := installedBinPath()
	if _, err := os.Stat(bin); err != nil {
		if self, err := os.Executable(); err == nil {
			bin = self
		}
	}
	cfg, _ := json.MarshalIndent(appConfig{Port: port, Bin: bin}, "", "  ")
	if err := writeFilePrivate(appConfigPath(), append(cfg, '\n')); err != nil {
		return err
	}
	if _, err := ensureAppToken(); err != nil {
		return err
	}
	return writeFilePrivate(menubarMarker(), []byte("The menu bar app shows yaklite's alerts. Remove this file to use normal notifications.\n"))
}

func uninstallMenubar() {
	exec.Command("pkill", "-x", "YakliteBar").Run()
	os.RemoveAll(menubarAppPath())
	os.Remove(menubarMarker())
}

func menubarStatus() error {
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	_, err := os.Stat(menubarAppPath())
	fmt.Println("Installed:          ", yes(err == nil))
	fmt.Println("Running:            ", yes(runtime.GOOS == "darwin" && exec.Command("pgrep", "-x", "YakliteBar").Run() == nil))
	fmt.Println("Set up:             ", yes(readAppToken() != ""))
	fmt.Println("Showing the alerts: ", yes(menubarActive()))
	fmt.Println("Included in build:  ", yes(len(menubarZip) > 0))
	return nil
}

// extractMenubarApp unpacks YakliteBar.app from the zip into dir, replacing
// an older copy. Entries outside YakliteBar.app, absolute paths, ".." and
// links are refused.
func extractMenubarApp(data []byte, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if err := checkZipName(f.Name); err != nil {
			return err
		}
		if f.Mode()&os.ModeSymlink != 0 || (f.Mode()&os.ModeType != 0 && !f.FileInfo().IsDir()) {
			return fmt.Errorf("unexpected link or special file %q", f.Name)
		}
	}
	tmp, err := os.MkdirTemp(dir, ".yaklitebar-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	var total int64
	for _, f := range zr.File {
		if skipZipName(f.Name) {
			continue
		}
		target := filepath.Join(tmp, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		perm := f.Mode().Perm() | 0o600
		if f.Mode().Perm()&0o111 != 0 {
			perm |= 0o755
		} else {
			perm |= 0o644
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			rc.Close()
			return err
		}
		n, err := io.Copy(out, io.LimitReader(rc, 200<<20-total+1))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		total += n
		if total > 200<<20 {
			return errors.New("the app is unexpectedly large")
		}
		os.Chmod(target, perm) // umask may have dropped bits
	}
	src := filepath.Join(tmp, menubarAppName)
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		return errors.New("the zip does not hold " + menubarAppName)
	}
	dst := filepath.Join(dir, menubarAppName)
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

func skipZipName(name string) bool {
	return strings.HasPrefix(name, "__MACOSX/") || strings.HasPrefix(path.Base(name), "._")
}

func checkZipName(name string) error {
	bad := name == "" || strings.Contains(name, "\\") || strings.Contains(name, "\x00") ||
		path.IsAbs(name) || filepath.IsAbs(name) || filepath.VolumeName(name) != ""
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			bad = true
		}
	}
	if bad {
		return fmt.Errorf("unsafe path in zip: %q", name)
	}
	if skipZipName(name) {
		return nil
	}
	if name != menubarAppName+"/" && !strings.HasPrefix(name, menubarAppName+"/") {
		return fmt.Errorf("unexpected file in zip: %q", name)
	}
	return nil
}

// ---- /api/app/* ----

type appProblem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Fix      string `json:"fix,omitempty"`
	Severity string `json:"severity"`
	AckKey   string `json:"ack_key"`
	Time     string `json:"time,omitempty"`
}

type appSummary struct {
	Status      string       `json:"status"` // ok, warn or alert
	OpenHigh    int          `json:"open_high"`
	OpenMedium  int          `json:"open_medium"`
	Score       int          `json:"score"`
	Grade       string       `json:"grade"`
	LastCheck   string       `json:"last_check,omitempty"`
	TopProblems []appProblem `json:"top_problems"`
	Alerts      []appProblem `json:"recent_alerts"`
}

func buildAppSummary(r *stateReader, states []*watchState, acks *acksFile, now time.Time) appSummary {
	base := apiSummary(states, acks, now)
	sc := computeScore(states, r.inv, acks, now)
	s := appSummary{Status: base.Status, OpenHigh: base.OpenHigh, OpenMedium: base.OpenMedium, Score: sc.Score, Grade: sc.Grade,
		LastCheck: base.LastCheck, TopProblems: []appProblem{}, Alerts: []appProblem{}}

	// the same open problems the score counts, keyed the way /ack expects
	seen := map[string]bool{}
	var probs []appProblem
	add := func(id, sev, title, fix string) {
		if seen[id] || acks.matches(id, now) || (sev != sevHigh && sev != sevMedium) {
			return
		}
		seen[id] = true
		probs = append(probs, appProblem{ID: id, Title: title, Fix: fix, Severity: sev, AckKey: id})
	}
	for _, st := range states {
		for _, f := range st.Snap.Findings {
			add(f.ID, f.Severity, f.Title, f.Fix)
		}
		for _, it := range riskyOpenPorts(st, r.inv) {
			add(it.ID, it.Severity, it.Title, it.Fix)
		}
	}
	sort.SliceStable(probs, func(i, j int) bool {
		if sevRank[probs[i].Severity] != sevRank[probs[j].Severity] {
			return sevRank[probs[i].Severity] > sevRank[probs[j].Severity]
		}
		return probs[i].ID < probs[j].ID
	})
	if len(probs) > 5 {
		probs = probs[:5]
	}
	s.TopProblems = append(s.TopProblems, probs...)

	// new alerts of the last day, newest first
	type timed struct {
		t time.Time
		p appProblem
	}
	var alerts []timed
	for _, st := range states {
		for _, c := range st.Changes {
			if now.Sub(c.Time) > 24*time.Hour || sevRank[c.Severity] < sevRank[sevMedium] || acks.matches(c.Key(), now) {
				continue
			}
			if c.Name == "" {
				c.Name = r.hostName(c.Host, st.Snap)
			}
			text := c.String()
			if c.Severity != "" && len(text) >= len(c.Severity) {
				text = text[len(c.Severity):]
			}
			fix := c.Fix
			if fix == "" {
				fix = fixFor(c)
			}
			sum := sha256.Sum256([]byte(st.Name + "|" + c.Key() + "|" + c.Time.UTC().Format(time.RFC3339Nano)))
			alerts = append(alerts, timed{c.Time, appProblem{ID: hex.EncodeToString(sum[:8]), Title: strings.Join(strings.Fields(text), " "),
				Fix: fix, Severity: c.Severity, AckKey: c.Key(), Time: c.Time.UTC().Format(time.RFC3339)}})
		}
	}
	sort.SliceStable(alerts, func(i, j int) bool { return alerts[i].t.After(alerts[j].t) })
	for i := 0; i < len(alerts) && i < 20; i++ {
		s.Alerts = append(s.Alerts, alerts[i].p)
	}
	return s
}

var (
	appCheckRunning atomic.Bool
	// appCheckCmd is the background check "Check now" starts.
	appCheckCmd = func(stateDir string) (*exec.Cmd, error) {
		self, err := os.Executable()
		if err != nil {
			return nil, err
		}
		return exec.Command(self, "auto", "-q", "--min-interval", "0", "--state", stateDir), nil
	}
	appEventsMu sync.Mutex
)

// handleAppAPI serves /api/app/*: loopback only, with the app secret.
func handleAppAPI(r *stateReader, w http.ResponseWriter, req *http.Request) {
	if !isLoopback(req.RemoteAddr) {
		http.Error(w, "only from this computer", http.StatusForbidden)
		return
	}
	want := readAppToken()
	got := req.Header.Get("X-Yaklite-App-Token")
	if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	method := func(m string) bool {
		if req.Method != m {
			http.Error(w, "not allowed", http.StatusMethodNotAllowed)
			return false
		}
		return true
	}
	writeJSON := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	switch req.URL.Path {
	case "/api/app/summary":
		if !method(http.MethodGet) {
			return
		}
		states, err := r.load()
		if err != nil {
			http.Error(w, "could not read state", http.StatusInternalServerError)
			return
		}
		writeJSON(http.StatusOK, buildAppSummary(r, states, loadAcks(), time.Now()))
	case "/api/app/ack":
		if !method(http.MethodPost) {
			return
		}
		var body struct {
			Key string `json:"key"`
			For string `json:"for"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		d, err := parseDuration(body.For)
		key := strings.TrimSpace(body.Key)
		if err != nil || key == "" || len(key) > 300 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if _, err := addAck(key, d, "from the menu bar app"); err != nil {
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		writeJSON(http.StatusOK, map[string]bool{"ok": true})
	case "/api/app/check":
		if !method(http.MethodPost) {
			return
		}
		if !appCheckRunning.CompareAndSwap(false, true) {
			writeJSON(http.StatusAccepted, map[string]any{"started": false, "running": true})
			return
		}
		cmd, err := appCheckCmd(r.dir)
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			appCheckRunning.Store(false)
			http.Error(w, "could not start a check", http.StatusInternalServerError)
			return
		}
		go func() {
			cmd.Wait()
			appCheckRunning.Store(false)
		}()
		writeJSON(http.StatusAccepted, map[string]any{"started": true, "running": true})
	case "/api/app/event":
		if !method(http.MethodPost) {
			return
		}
		var ev struct {
			Kind string `json:"kind"`
			App  string `json:"app"`
			On   bool   `json:"on"`
		}
		if err := json.NewDecoder(req.Body).Decode(&ev); err != nil || (ev.Kind != "camera" && ev.Kind != "mic") || !plainAppName(ev.App) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		rec := struct {
			Time time.Time `json:"time"`
			Kind string    `json:"kind"`
			App  string    `json:"app"`
			On   bool      `json:"on"`
		}{time.Now().UTC(), ev.Kind, ev.App, ev.On}
		line, _ := json.Marshal(rec)
		if err := appendCapped(appEventsPath(r.dir), line, 1000); err != nil {
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		writeJSON(http.StatusOK, map[string]bool{"ok": true})
	default:
		http.NotFound(w, req)
	}
}

func plainAppName(s string) bool {
	if len(s) > 100 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// appendCapped adds one line to a JSON lines file and keeps the last max lines.
func appendCapped(p string, line []byte, max int) error {
	appEventsMu.Lock()
	defer appEventsMu.Unlock()
	var lines [][]byte
	if f, err := os.Open(p); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if len(sc.Bytes()) > 0 {
				lines = append(lines, append([]byte(nil), sc.Bytes()...))
			}
		}
		f.Close()
	}
	lines = append(lines, line)
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	return writeFilePrivate(p, append(bytes.Join(lines, []byte("\n")), '\n'))
}
