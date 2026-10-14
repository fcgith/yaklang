package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The sites check reads the browsers' own history on this computer and
// compares the sites visited since the last check with public lists of
// malware sites (URLhaus) and phishing pages (OpenPhish). The history never
// leaves the computer; only the lists are downloaded.
//
// Safari's history needs Full Disk Access, like the app permissions check.

func init() {
	registerCheck(&check{name: "sites", about: "visits to known malware and phishing sites, from the browsers' history (URLhaus, OpenPhish)", run: sitesCheck})
}

var siteFeeds = []struct{ name, url, kind string }{
	{"urlhaus-hosts", "https://urlhaus.abuse.ch/downloads/hostfile/", "hosts"},
	{"urlhaus-urls", "https://urlhaus.abuse.ch/downloads/text_online/", "urls"},
	{"openphish", "https://openphish.com/feed.txt", "urls"},
}

// sharedHosts serve many people's files; one bad file there does not make
// every visit bad, so only exact page addresses count for them.
var sharedHosts = map[string]bool{
	"github.com": true, "raw.githubusercontent.com": true, "objects.githubusercontent.com": true, "gist.github.com": true,
	"drive.google.com": true, "docs.google.com": true, "sites.google.com": true, "storage.googleapis.com": true, "firebasestorage.googleapis.com": true,
	"dropbox.com": true, "www.dropbox.com": true, "dl.dropboxusercontent.com": true, "onedrive.live.com": true, "1drv.ms": true,
	"cdn.discordapp.com": true, "bitbucket.org": true, "gitlab.com": true, "pastebin.com": true, "mediafire.com": true, "www.mediafire.com": true,
}

type siteLists struct {
	hosts map[string]string // host -> list name
	urls  map[string]string // normalised url -> list name
}

func normURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimSuffix(u, "/")
	if i := strings.Index(u, "#"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

func parseSiteFeed(sc *bufio.Scanner, name, kind string, l *siteLists) {
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch kind {
		case "hosts":
			f := strings.Fields(line)
			h := f[len(f)-1]
			if h != "localhost" && !sharedHosts[h] {
				l.hosts[strings.ToLower(h)] = name
			}
		case "urls":
			if strings.HasPrefix(line, "http") {
				l.urls[normURL(line)] = name
			}
		}
	}
}

func loadSiteLists(ctx context.Context, stateDir string, download bool) (*siteLists, []string) {
	dir := filepath.Join(stateDir, "threat-lists")
	os.MkdirAll(dir, 0o700)
	l := &siteLists{hosts: map[string]string{}, urls: map[string]string{}}
	var errs []string
	for _, f := range siteFeeds {
		p := filepath.Join(dir, f.name+".txt")
		st, err := os.Stat(p)
		if download && (err != nil || time.Since(st.ModTime()) > 6*time.Hour) {
			if err := fetchToFile(ctx, f.url, p); err != nil {
				errs = append(errs, fmt.Sprintf("site list %s: %v", f.name, err))
			}
		}
		fh, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		parseSiteFeed(sc, f.name, f.kind, l)
		fh.Close()
	}
	return l, errs
}

func (l *siteLists) match(raw string) (string, bool) {
	if n, ok := l.urls[normURL(raw)]; ok {
		return n, true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	if n, ok := l.hosts[strings.ToLower(u.Hostname())]; ok {
		return n, true
	}
	return "", false
}

type visit struct {
	URL     string
	Time    time.Time
	Browser string
}

// historyDB is one browser profile's history file and how to read it.
type historyDB struct {
	browser, path, query string
	toTime               func(int64) time.Time
	since                func(time.Time) int64
}

var safariEpoch = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

// Chrome counts microseconds from 1601, too far back for time.Duration.
const chromeEpochOffset = 11644473600 * 1000000

func chromeTime(v int64) time.Time  { return time.UnixMicro(v - chromeEpochOffset) }
func chromeSince(t time.Time) int64 { return t.UnixMicro() + chromeEpochOffset }

func historyDBs(h *hostOS) []historyDB {
	var out []historyDB
	var bases []string
	switch h.goos {
	case "darwin":
		bases = []string{filepath.Join(h.home, "Library/Application Support")}
	case "linux":
		bases = []string{filepath.Join(h.home, ".config")}
	}
	for _, base := range bases {
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
				out = append(out, historyDB{browser: chromeBrowsers[sub], path: filepath.Join(root, p.Name(), "History"),
					query: "select url, last_visit_time from urls where last_visit_time > %d", toTime: chromeTime, since: chromeSince})
			}
		}
	}
	ff := filepath.Join(h.home, "Library/Application Support/Firefox/Profiles")
	if h.goos == "linux" {
		ff = filepath.Join(h.home, ".mozilla/firefox")
	}
	if profiles, err := h.readDir(ff); err == nil {
		for _, p := range profiles {
			if p.IsDir() {
				out = append(out, historyDB{browser: "Firefox", path: filepath.Join(ff, p.Name(), "places.sqlite"),
					query:  "select url, last_visit_date from moz_places where last_visit_date > %d",
					toTime: func(v int64) time.Time { return time.UnixMicro(v) }, since: func(t time.Time) int64 { return t.UnixMicro() }})
			}
		}
	}
	if h.goos == "darwin" {
		out = append(out, historyDB{browser: "Safari", path: filepath.Join(h.home, "Library/Safari/History.db"),
			query:  "select i.url, cast(v.visit_time as integer) from history_visits v join history_items i on i.id = v.history_item where v.visit_time > %d",
			toTime: func(v int64) time.Time { return safariEpoch.Add(time.Duration(v) * time.Second) },
			since:  func(t time.Time) int64 { return int64(t.Sub(safariEpoch).Seconds()) }})
	}
	return out
}

// parseVisits reads sqlite3's "url|number" rows.
func parseVisits(out, browser string, toTime func(int64) time.Time) []visit {
	var vs []visit
	for _, line := range strings.Split(out, "\n") {
		i := strings.LastIndex(line, "|")
		if i <= 0 {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(line[i+1:]), 10, 64)
		if err != nil {
			continue
		}
		vs = append(vs, visit{URL: line[:i], Time: toTime(n), Browser: browser})
	}
	return vs
}

// readHistory copies a history file (browsers keep it locked) and reads the
// visits after since.
func readHistory(ctx context.Context, run runner, db historyDB, since time.Time, tmp string) []visit {
	data, err := os.ReadFile(db.path)
	if err != nil {
		return nil
	}
	cp := filepath.Join(tmp, "h.sqlite")
	if writeFilePrivate(cp, data) != nil {
		return nil
	}
	defer os.Remove(cp)
	if wal, err := os.ReadFile(db.path + "-wal"); err == nil {
		writeFilePrivate(cp+"-wal", wal)
		defer os.Remove(cp + "-wal")
	}
	out := run(ctx, "sqlite3", "-readonly", "-separator", "|", cp, fmt.Sprintf(db.query, db.since(since)))
	if strings.HasPrefix(out, "Error") || strings.Contains(out, "unable to open") {
		return nil
	}
	return parseVisits(out, db.browser, db.toTime)
}

type siteHit struct {
	URL     string    `json:"url"`
	Browser string    `json:"browser"`
	List    string    `json:"list"`
	Time    time.Time `json:"time"`
}

type siteMemory struct {
	Last time.Time          `json:"last"`
	Hits map[string]siteHit `json:"hits"`
}

func siteHitFinding(h siteHit) *Finding {
	host := h.URL
	if u, err := url.Parse(h.URL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	f := &Finding{ID: "badsite:" + shortHash(h.URL), Until: h.Time.Add(7 * 24 * time.Hour),
		Detail: fmt.Sprintf("%s opened %s on %s. Listed by %s.", h.Browser, trunc(h.URL, 150), h.Time.Local().Format("Mon 2 Jan 15:04"), h.List)}
	if h.List == "openphish" {
		f.Severity = sevMedium
		f.Title = "A known phishing page was opened in " + h.Browser + ": " + host
		f.Fix = "If you typed a password or card number on that page, change that password now (and anywhere you reuse it) and call your bank about the card. Turn on two-step login where you can."
	} else {
		f.Severity = sevHigh
		f.Title = "A known malware site was opened in " + h.Browser + ": " + host
		f.Fix = "If anything was downloaded from it, do not open it and delete it. If something was opened or installed, run `yaklite incident` and follow the steps."
	}
	return f
}

func sitesCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	if env.opts == nil || !env.opts.threatLists {
		return nil, nil
	}
	h := realHostOS()
	p := filepath.Join(env.stateDir, "sites-memory.json")
	mem := &siteMemory{}
	if data, err := os.ReadFile(p); err == nil {
		json.Unmarshal(data, mem)
	}
	if mem.Hits == nil {
		mem.Hits = map[string]siteHit{}
	}
	now := time.Now()
	since := mem.Last
	if since.IsZero() || now.Sub(since) > 7*24*time.Hour {
		since = now.Add(-24 * time.Hour)
	}
	lists, errs := loadSiteLists(ctx, env.stateDir, true)
	for _, e := range errs {
		env.warn(e)
	}
	tmp, err := os.MkdirTemp("", "yaklite-history")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	for _, db := range historyDBs(h) {
		for _, v := range readHistory(ctx, cmdOut, db, since, tmp) {
			if name, ok := lists.match(v.URL); ok {
				mem.Hits[shortHash(v.URL)] = siteHit{URL: v.URL, Browser: v.Browser, List: name, Time: v.Time}
			}
		}
	}
	mem.Last = now
	var out []*Finding
	for _, k := range sortedKeys(mem.Hits) {
		hit := mem.Hits[k]
		if now.Sub(hit.Time) > 7*24*time.Hour {
			delete(mem.Hits, k)
			continue
		}
		out = append(out, siteHitFinding(hit))
	}
	if data, err := json.MarshalIndent(mem, "", "  "); err == nil {
		writeFilePrivate(p, data)
	}
	return out, nil
}
