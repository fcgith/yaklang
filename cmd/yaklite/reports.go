package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Other computers in the house can send their own check results (this
// computer's settings, startup programs, certificates, connections) to one
// dashboard, so the family's laptops show up in one place. Each computer
// still alerts on its own when yaklite is installed there; the dashboard
// just collects.

type computerReport struct {
	Name     string     `json:"name"`
	OS       string     `json:"os"`
	Version  string     `json:"version"`
	Time     time.Time  `json:"time"`
	Findings []*Finding `json:"findings"`
	Received time.Time  `json:"received,omitempty"`
}

var reportNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._'-]{0,59}$`)

func reportTokenPath() string { return filepath.Join(configDir(), "report-token") }

// reportToken returns the token other computers must present, creating one.
func reportToken() (string, error) {
	if data, err := os.ReadFile(reportTokenPath()); err == nil && len(bytes.TrimSpace(data)) >= 16 {
		return string(bytes.TrimSpace(data)), nil
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := hex.EncodeToString(b)
	os.MkdirAll(configDir(), 0o700)
	return t, writeFilePrivate(reportTokenPath(), []byte(t+"\n"))
}

func reportsDir(stateDir string) string { return filepath.Join(stateDir, "reports") }

// handleReport stores one computer's report.
func handleReport(stateDir, token string, w http.ResponseWriter, req *http.Request) {
	auth := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if token == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var rep computerReport
	if err := json.NewDecoder(io.LimitReader(req.Body, 512<<10)).Decode(&rep); err != nil {
		http.Error(w, "bad report", http.StatusBadRequest)
		return
	}
	if !reportNameRe.MatchString(rep.Name) || len(rep.Findings) > 500 {
		http.Error(w, "bad report", http.StatusBadRequest)
		return
	}
	for _, f := range rep.Findings {
		if f == nil || len(f.Title) > 1000 || len(f.Detail) > 2000 || len(f.Fix) > 2000 || !validSeverity(f.Severity) {
			http.Error(w, "bad report", http.StatusBadRequest)
			return
		}
	}
	rep.Received = time.Now()
	dir := reportsDir(stateDir)
	os.MkdirAll(dir, 0o700)
	data, _ := json.MarshalIndent(rep, "", " ")
	if err := writeFilePrivate(filepath.Join(dir, safeName(rep.Name)+".json"), data); err != nil {
		http.Error(w, "could not save", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type pageComputer struct {
	Name, OS, Last string
	Stale          bool
	Findings       []pageFinding
}

func (r *stateReader) computers(now time.Time) []pageComputer {
	files, _ := filepath.Glob(filepath.Join(reportsDir(r.dir), "*.json"))
	acks := loadAcks()
	var out []pageComputer
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var rep computerReport
		if json.Unmarshal(data, &rep) != nil {
			continue
		}
		pc := pageComputer{Name: rep.Name, OS: rep.OS, Last: rep.Received.Local().Format("Mon 2 Jan 15:04"), Stale: now.Sub(rep.Received) > 48*time.Hour}
		for _, fd := range rep.Findings {
			if sevRank[fd.Severity] < sevRank[sevLow] {
				continue
			}
			pc.Findings = append(pc.Findings, pageFinding{Severity: fd.Severity, Title: fd.Title, Detail: fd.Detail, Fix: fd.Fix, ID: fd.ID, Acked: acks.matches(rep.Name+"/"+fd.ID, now)})
		}
		sort.Slice(pc.Findings, func(i, j int) bool { return sevRank[pc.Findings[i].Severity] > sevRank[pc.Findings[j].Severity] })
		out = append(out, pc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- sending ----

// reportURLAllowed accepts https anywhere, and plain http only to an address
// on the home network or this computer.
func reportURLAllowed(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("bad --report-to URL %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || isCGNAT(ip)) {
			return nil
		}
		return errors.New("--report-to over plain http is only allowed to an address on your own network (like http://192.168.1.10:9842) or Tailscale")
	}
	return fmt.Errorf("--report-to must be http(s), not %q", u.Scheme)
}

// isCGNAT covers Tailscale's 100.64.0.0/10.
func isCGNAT(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64
}

func sendReport(ctx context.Context, to, token string, snap *Snapshot) error {
	name, _ := os.Hostname()
	name = strings.TrimSuffix(name, ".local")
	if !reportNameRe.MatchString(name) {
		name = safeName(name)
	}
	rep := computerReport{Name: name, OS: runtime.GOOS, Version: version, Time: time.Now()}
	for _, f := range snap.Findings {
		switch f.Check {
		case "self", "host", "conns":
			rep.Findings = append(rep.Findings, f)
		}
	}
	body, _ := json.Marshal(rep)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(to, "/")+"/api/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("dashboard answered %s", resp.Status)
	}
	return nil
}

// cmdReport runs this computer's own checks once and sends them.
func cmdReport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	to := fs.String("to", "", "the dashboard to report to, e.g. http://192.168.1.10:9842")
	token := fs.String("token", "", "the token printed by yaklite serve --accept-reports on that computer")
	fs.Parse(args)
	if *to == "" || *token == "" {
		return errors.New("usage: yaklite report --to http://HUB:9842 --token TOKEN")
	}
	if err := reportURLAllowed(*to); err != nil {
		return err
	}
	snap := NewSnapshot("this computer", "", "report")
	env := &checkEnv{snap: snap, stateDir: defaultStateDir(), prog: func(string, ...any) {}, opts: defaultCheckOptions()}
	runChecks(ctx, env, map[string]bool{"self": true, "host": true, "conns": true})
	if err := sendReport(ctx, *to, *token, snap); err != nil {
		return err
	}
	fmt.Printf("Sent %d problem(s) to %s\n", len(snap.Findings), *to)
	return nil
}

func validSeverity(s string) bool {
	return s == sevInfo || s == sevLow || s == sevMedium || s == sevHigh
}

type reportTarget struct {
	To    string `json:"to"`
	Token string `json:"token"`
}

func reportTargetPath() string { return filepath.Join(configDir(), "report-to.json") }

func loadReportTarget() *reportTarget {
	data, err := os.ReadFile(reportTargetPath())
	if err != nil {
		return nil
	}
	var t reportTarget
	if json.Unmarshal(data, &t) != nil || t.To == "" || reportURLAllowed(t.To) != nil {
		return nil
	}
	return &t
}

func saveReportTarget(to, token string) error {
	if err := reportURLAllowed(to); err != nil {
		return err
	}
	data, _ := json.Marshal(reportTarget{To: to, Token: token})
	os.MkdirAll(configDir(), 0o700)
	return writeFilePrivate(reportTargetPath(), data)
}
