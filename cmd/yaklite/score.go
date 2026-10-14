package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The security score is a simple number out of 100 from the problems
// yaklite currently sees: each open problem costs points by severity, an
// acknowledged one costs nothing. It is a nudge, not a certificate.

type scoreItem struct {
	Severity, Title, Fix, ID, Where string
}

type securityScore struct {
	Score  int         `json:"score"`
	Grade  string      `json:"grade"`
	High   int         `json:"high"`
	Medium int         `json:"medium"`
	Low    int         `json:"low"`
	Top    []scoreItem `json:"fix_first"`
}

var scoreCost = map[string]int{sevHigh: 15, sevMedium: 6, sevLow: 2}

// riskyOpenPorts turns risky services in a trusted-network snapshot into
// problems: a scan sees them as ports, not findings.
func riskyOpenPorts(w *watchState, inv *Inventory) []scoreItem {
	var out []scoreItem
	if w.Snap.Method == "connections" || w.Snap.Method == "tripwire" || w.Snap.Method == "router-log" || w.Snap.Method == "traffic" {
		return nil
	}
	for host, svcs := range w.Snap.Hosts {
		e := inv.entry(host, w.Snap.mac(host))
		if e != nil && e.Ignore {
			continue
		}
		for _, s := range svcs {
			if e != nil && e.expects(s.Port) {
				continue
			}
			why, risky := inv.risky(s.Port, s.Label())
			if !risky {
				continue
			}
			name := host
			if e != nil && e.Name != "" {
				name = e.Name + " (" + host + ")"
			}
			c := Change{Kind: "port_open", Host: host, Port: s.Port, Proto: s.Proto, Name: name, Severity: sevHigh}
			out = append(out, scoreItem{Severity: sevHigh, ID: c.Key(),
				Title: fmt.Sprintf("%s has %s/%d open: %s", name, s.Proto, s.Port, why), Fix: fixFor(c)})
		}
	}
	return out
}

func computeScore(states []*watchState, inv *Inventory, acks *acksFile, now time.Time) securityScore {
	seen := map[string]bool{}
	var items []scoreItem
	for _, w := range states {
		for _, f := range w.Snap.Findings {
			if seen[f.ID] || acks.matches(f.ID, now) {
				continue
			}
			seen[f.ID] = true
			items = append(items, scoreItem{Severity: f.Severity, Title: f.Title, Fix: f.Fix, ID: f.ID, Where: w.Name})
		}
		for _, it := range riskyOpenPorts(w, inv) {
			if seen[it.ID] || acks.matches(it.ID, now) {
				continue
			}
			seen[it.ID] = true
			it.Where = w.Name
			items = append(items, it)
		}
	}
	s := securityScore{Score: 100}
	cost := 0
	for _, it := range items {
		cost += scoreCost[it.Severity]
		switch it.Severity {
		case sevHigh:
			s.High++
		case sevMedium:
			s.Medium++
		case sevLow:
			s.Low++
		}
	}
	s.Score = max(0, 100-cost)
	switch {
	case s.High > 0 && s.Score > 69:
		s.Score = 69 // any high problem caps it
	}
	switch {
	case s.Score >= 90:
		s.Grade = "Good"
	case s.Score >= 70:
		s.Grade = "Fair"
	case s.Score >= 50:
		s.Grade = "Needs attention"
	default:
		s.Grade = "At risk"
	}
	sort.SliceStable(items, func(i, j int) bool {
		if sevRank[items[i].Severity] != sevRank[items[j].Severity] {
			return sevRank[items[i].Severity] > sevRank[items[j].Severity]
		}
		return items[i].ID < items[j].ID
	})
	for _, it := range items {
		if len(s.Top) == 3 {
			break
		}
		if it.Severity == sevInfo {
			continue
		}
		s.Top = append(s.Top, it)
	}
	return s
}

func (s securityScore) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Security score: %d/100 (%s). Open problems: %d high, %d medium, %d low.\n", s.Score, s.Grade, s.High, s.Medium, s.Low)
	if len(s.Top) > 0 {
		b.WriteString("\nFix these first:\n")
		for i, it := range s.Top {
			fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, strings.ToUpper(it.Severity), it.Title)
			if it.Fix != "" {
				fmt.Fprintf(&b, "   What to do: %s\n", it.Fix)
			}
			fmt.Fprintf(&b, "   Done or expected? yaklite ack %s\n", it.ID)
		}
	}
	return b.String()
}

func cmdScore(args []string) error {
	fs := flag.NewFlagSet("score", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	fs.Parse(args)
	r := &stateReader{dir: *stateDir, invFromConfig: true}
	states, err := r.load()
	if err != nil {
		return err
	}
	if len(states) == 0 {
		fmt.Println("No results yet. Run yaklite install, or yaklite check.")
		return nil
	}
	fmt.Print(computeScore(states, r.inv, loadAcks(), time.Now()).String())
	return nil
}
