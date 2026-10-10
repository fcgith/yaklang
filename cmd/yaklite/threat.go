package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Public lists of addresses known to be attacking people or running malware.
// They are downloaded at most twice a day into the state directory; only the
// list is fetched, nothing about this machine is sent.
var threatFeeds = []struct {
	name, url, about string
}{
	{"feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "abuse.ch Feodo Tracker: botnet control servers"},
	{"spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt", "Spamhaus DROP: networks run by criminals"},
	{"dshield", "https://feeds.dshield.org/block.txt", "DShield: the networks attacking the most this week"},
	{"blocklist.de", "https://lists.blocklist.de/lists/all.txt", "blocklist.de: addresses that attacked servers in the last 48 hours"},
	{"cins", "https://cinsscore.com/list/ci-badguys.txt", "CINS Army: addresses with a poor reputation for attacks"},
}

type threatSet struct {
	ips  map[string]string // ip -> feed
	nets []struct {
		n    *net.IPNet
		feed string
	}
}

func (t *threatSet) lookup(ip net.IP) (feed string, ok bool) {
	if t == nil || ip == nil {
		return "", false
	}
	if f, ok := t.ips[ip.String()]; ok {
		return f, true
	}
	for _, n := range t.nets {
		if n.n.Contains(ip) {
			return n.feed, true
		}
	}
	return "", false
}

func feedAbout(name string) string {
	for _, f := range threatFeeds {
		if f.name == name {
			return f.about
		}
	}
	return name
}

// parseFeed reads IPs and CIDRs, one per line, skipping comments. DShield's
// block.txt is "start end netblock ..." with tabs.
func parseFeed(r io.Reader, feed string, t *threatSet) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if i := strings.IndexAny(line, ";#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && net.ParseIP(fields[0]) != nil && net.ParseIP(fields[1]) != nil {
			line = fields[0] + "/" + fields[2]
		} else {
			line = fields[0]
		}
		if strings.Contains(line, "/") {
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			if ones, _ := n.Mask.Size(); ones == 0 || !isPublicAddr(n.IP) {
				continue // never let a feed flag the whole internet or a private range
			}
			t.nets = append(t.nets, struct {
				n    *net.IPNet
				feed string
			}{n, feed})
			continue
		}
		if ip := net.ParseIP(line); ip != nil && isPublicAddr(ip) {
			t.ips[ip.String()] = feed
		}
	}
}

var (
	threatMu     sync.Mutex
	threatCached *threatSet
	threatLoaded time.Time
)

// loadThreats returns the blocklists, refreshing files older than 12 hours.
// It works offline from whatever was downloaded before.
func loadThreats(ctx context.Context, stateDir string, download bool) (*threatSet, []string) {
	threatMu.Lock()
	defer threatMu.Unlock()
	if threatCached != nil && time.Since(threatLoaded) < 30*time.Minute {
		return threatCached, nil
	}
	dir := filepath.Join(stateDir, "threat-lists")
	os.MkdirAll(dir, 0o700)
	var errs []string
	t := &threatSet{ips: map[string]string{}}
	for _, f := range threatFeeds {
		p := filepath.Join(dir, f.name+".txt")
		st, err := os.Stat(p)
		if download && (err != nil || time.Since(st.ModTime()) > 12*time.Hour) {
			if err := fetchToFile(ctx, f.url, p); err != nil {
				errs = append(errs, fmt.Sprintf("threat list %s: %v", f.name, err))
			}
		}
		fh, err := os.Open(p)
		if err != nil {
			continue
		}
		parseFeed(fh, f.name, t)
		fh.Close()
	}
	threatCached, threatLoaded = t, time.Now()
	return t, errs
}

func fetchToFile(ctx context.Context, url, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "yaklite")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	return writeFilePrivate(path, data)
}
