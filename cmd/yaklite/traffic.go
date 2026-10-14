package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// The traffic box: a small always-on computer (a Raspberry Pi is enough)
// running Suricata, an intrusion detection system that watches the home
// network's traffic for known attacks and malware. yaklite reads Suricata's
// alerts (its eve.json file) and turns them into plain alerts.
// contrib/trafficbox has a ready-made setup.

type idsAlert struct {
	Time      time.Time
	Src, Dst  string
	DstPort   int
	Signature string
	Category  string
	Severity  int // Suricata: 1 high, 2 medium, 3 low
}

type eveLine struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Alert     *struct {
		Action    string `json:"action"`
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
}

// parseEve reads one eve.json line; it returns nil for anything but alerts.
func parseEve(line []byte) *idsAlert {
	var e eveLine
	if json.Unmarshal(line, &e) != nil || e.EventType != "alert" || e.Alert == nil {
		return nil
	}
	t, err := time.Parse("2006-01-02T15:04:05.999999-0700", e.Timestamp)
	if err != nil {
		t = time.Now()
	}
	return &idsAlert{Time: t, Src: e.SrcIP, Dst: e.DestIP, DstPort: e.DestPort, Signature: e.Alert.Signature, Category: e.Alert.Category, Severity: e.Alert.Severity}
}

// noisySignatures are informational rules that fire on ordinary home traffic.
var noisySignatures = []string{"ET INFO", "ET POLICY", "SURICATA STREAM", "SURICATA TLS invalid", "SURICATA UDPv4 invalid checksum", "SURICATA Applayer"}

func noisy(a idsAlert) bool {
	for _, p := range noisySignatures {
		if strings.HasPrefix(a.Signature, p) {
			return a.Severity >= 2
		}
	}
	return false
}

// trafficFindings groups the last day's alerts by rule and devices.
func trafficFindings(alerts []idsAlert, now time.Time) []*Finding {
	type group struct {
		a     idsAlert
		n     int
		first time.Time
		last  time.Time
	}
	groups := map[string]*group{}
	for _, a := range alerts {
		if now.Sub(a.Time) > 24*time.Hour || noisy(a) {
			continue
		}
		k := a.Signature + "|" + a.Src + "|" + a.Dst
		g := groups[k]
		if g == nil {
			g = &group{a: a, first: a.Time}
			groups[k] = g
		}
		g.n++
		if a.Time.After(g.last) {
			g.last = a.Time
		}
		if a.Time.Before(g.first) {
			g.first = a.Time
		}
	}
	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*Finding
	for _, k := range keys {
		g := groups[k]
		sev := sevLow
		switch g.a.Severity {
		case 1:
			sev = sevHigh
		case 2:
			sev = sevMedium
		}
		times := ""
		if g.n > 1 {
			times = fmt.Sprintf(" (%d times)", g.n)
		}
		out = append(out, &Finding{ID: "traffic:" + shortHash(k), Severity: sev, Host: g.a.Src, Until: g.last.Add(24 * time.Hour),
			Title:  fmt.Sprintf("Suspicious traffic from %s to %s:%d: %s%s", g.a.Src, g.a.Dst, g.a.DstPort, g.a.Signature, times),
			Detail: "Category: " + orStr(g.a.Category, "unknown") + ". First " + g.first.Local().Format("Mon 15:04") + ", last " + g.last.Local().Format("Mon 15:04") + ".",
			Fix:    trafficFix(g.a)})
	}
	return out
}

func trafficFix(a idsAlert) string {
	c := strings.ToLower(a.Category + " " + a.Signature)
	switch {
	case strings.Contains(c, "trojan") || strings.Contains(c, "malware") || strings.Contains(c, "command and control") || strings.Contains(c, "cnc"):
		return "A device may be infected. Find which one has address " + a.Src + " (yaklite history), disconnect it, and scan or reset it."
	case strings.Contains(c, "scan"):
		return "Something is scanning. If " + a.Src + " is inside your home, find that device; if it is on the internet, check that the router forwards no ports you do not need."
	case strings.Contains(c, "exploit") || strings.Contains(c, "attack"):
		return "Someone tried a known attack. Make sure the target device (" + a.Dst + ") is up to date, and that the router does not expose it."
	}
	return "Look up the rule name to see what it means. If it keeps coming up for a device you trust, it can be acknowledged."
}

// tailEve follows eve.json, also across log rotation, and hands over alerts.
func tailEve(ctx context.Context, path string, fromStart bool, add func(idsAlert)) error {
	var f *os.File
	var r *bufio.Reader
	open := func(seekEnd bool) error {
		nf, err := os.Open(path)
		if err != nil {
			return err
		}
		if seekEnd {
			nf.Seek(0, io.SeekEnd)
		}
		if f != nil {
			f.Close()
		}
		f, r = nf, bufio.NewReaderSize(nf, 256<<10)
		return nil
	}
	if err := open(!fromStart); err != nil {
		return err
	}
	defer func() { f.Close() }()
	var partial []byte
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			partial = append(partial, line...)
			if line[len(line)-1] == '\n' {
				if a := parseEve(partial); a != nil {
					add(*a)
				}
				partial = partial[:0]
			}
			continue
		}
		if err != nil && err != io.EOF {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
		// rotated or truncated: start over on the new file
		if st, err := os.Stat(path); err == nil {
			cur, _ := f.Seek(0, io.SeekCurrent)
			if fi, _ := f.Stat(); fi != nil && (!os.SameFile(st, fi) || st.Size() < cur) {
				open(false)
				partial = partial[:0]
			}
		}
	}
}

func cmdTraffic(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("traffic", flag.ExitOnError)
	wf := addWatchFlags(fs, time.Minute)
	eve := fs.String("eve", "/var/log/suricata/eve.json", "Suricata's eve.json alert log")
	fromStart := fs.Bool("from-start", false, "also read alerts already in the file")
	desktop := fs.Bool("notify", false, "show desktop notifications")
	quiet := fs.Bool("q", false, "quiet")
	fs.Parse(args)
	if _, err := os.Stat(*eve); err != nil {
		return fmt.Errorf("cannot read Suricata's log: %w (see contrib/trafficbox)", err)
	}
	if *wf.name == "" {
		*wf.name = "traffic"
	}
	prog := progress(*quiet)
	if prog == nil {
		prog = func(string, ...any) {}
	}
	var mu sync.Mutex
	var alerts []idsAlert
	add := func(a idsAlert) {
		mu.Lock()
		defer mu.Unlock()
		alerts = append(alerts, a)
		if len(alerts) > 50000 {
			alerts = alerts[len(alerts)-50000:]
		}
	}
	if *fromStart {
		// read what is there before the first check, then follow
		if f, err := os.Open(*eve); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 256<<10), 4<<20)
			for sc.Scan() {
				if a := parseEve(sc.Bytes()); a != nil {
					add(*a)
				}
			}
			f.Close()
		}
	}
	tailErr := make(chan error, 1)
	go func() { tailErr <- tailEve(ctx, *eve, false, add) }()
	scan := func(ctx context.Context) (*Snapshot, error) {
		select {
		case err := <-tailErr:
			if err == nil {
				err = errors.New("stopped reading the log")
			}
			return nil, err
		default:
		}
		snap := NewSnapshot("traffic box", "", "traffic")
		snap.Started = time.Now()
		mu.Lock()
		// drop what is older than a day
		cut := 0
		for cut < len(alerts) && time.Since(alerts[cut].Time) > 24*time.Hour {
			cut++
		}
		alerts = alerts[cut:]
		as := append([]idsAlert(nil), alerts...)
		mu.Unlock()
		for _, f := range trafficFindings(as, time.Now()) {
			f.Check = "traffic"
			snap.addFinding(f)
		}
		snap.Finished = time.Now()
		return snap, nil
	}
	w, err := wf.build(scan, prog, "traffic")
	if err != nil {
		return err
	}
	if *desktop {
		w.ac.desktop = "the traffic box"
	}
	return runWatch(ctx, w)
}
