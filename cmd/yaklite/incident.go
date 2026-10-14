package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// `yaklite incident` is for the moment something seems wrong: it writes
// one file with what to do, in order, and everything yaklite knows right
// now (open problems, recent alerts, current internet connections, startup
// programs, accounts and settings), so it can be handed to a helper.
// It changes nothing on the computer.

var incidentSteps = []string{
	"Stay calm and do not delete anything yet: what is there now helps find out what happened.",
	"If you think someone is controlling this Mac right now (the pointer moves by itself, windows open), turn off Wi-Fi or unplug the network cable.",
	"From another device you trust (a phone), change the password of your email first, then your Apple ID, bank and anything else important. Use a different password for each.",
	"Turn on two-step login (a code on your phone) for email, Apple ID and bank, if it is not on already.",
	"On appleid.apple.com, check the devices signed in to your Apple ID and remove any you do not know.",
	"If money or cards may be involved, call your bank with the number on the back of your card.",
	"Run a malware scan with Malwarebytes (free version is fine), or ask someone you trust to look at this report.",
	"If the scan finds something, or the problems below do not go away: restore from a Time Machine backup made before the first alert, or erase and reinstall macOS (System Settings > General > Transfer or Reset).",
	"Afterwards, run `yaklite check` again and make sure nothing high is left.",
}

func incidentReport(ctx context.Context, stateDir string, now time.Time) string {
	var b strings.Builder
	host, _ := os.Hostname()
	fmt.Fprintf(&b, "yaklite incident report\n%s, computer %q (%s), yaklite %s\n\n", now.Format("Monday 2 January 2006 15:04 MST"), host, runtime.GOOS, version)
	b.WriteString("WHAT TO DO, IN THIS ORDER\n")
	for i, s := range incidentSteps {
		fmt.Fprintf(&b, "%2d. %s\n", i+1, s)
	}

	r := &stateReader{dir: stateDir}
	states, _ := r.load()
	acks := loadAcks()
	sc := computeScore(states, nil, acks, now)
	fmt.Fprintf(&b, "\nSAFETY SCORE: %d/100 (%s), %d high, %d medium, %d low problems open\n", sc.Score, sc.Grade, sc.High, sc.Medium, sc.Low)

	b.WriteString("\nOPEN PROBLEMS\n")
	type open struct {
		f     *Finding
		where string
	}
	var opens []open
	seen := map[string]bool{}
	for _, w := range states {
		for _, f := range w.Snap.Findings {
			if seen[f.ID] || (!f.Until.IsZero() && f.Until.Before(now)) {
				continue
			}
			seen[f.ID] = true
			opens = append(opens, open{f, w.Name})
		}
	}
	rank := map[string]int{sevHigh: 0, sevMedium: 1, sevLow: 2}
	sort.SliceStable(opens, func(i, j int) bool {
		ri, ok := rank[opens[i].f.Severity]
		if !ok {
			ri = 3
		}
		rj, ok := rank[opens[j].f.Severity]
		if !ok {
			rj = 3
		}
		return ri < rj
	})
	if len(opens) == 0 {
		b.WriteString("  none recorded (run `yaklite check` first if yaklite was never set up)\n")
	}
	for _, o := range opens {
		ack := ""
		if acks.matches(o.f.ID, now) {
			ack = " [acknowledged]"
		}
		fmt.Fprintf(&b, "- [%s]%s %s (%s)\n", o.f.Severity, ack, o.f.Title, o.where)
		if o.f.Detail != "" {
			fmt.Fprintf(&b, "    %s\n", o.f.Detail)
		}
		if o.f.Fix != "" {
			fmt.Fprintf(&b, "    What to do: %s\n", o.f.Fix)
		}
	}

	b.WriteString("\nALERTS IN THE LAST 7 DAYS\n")
	var recent []Change
	for _, w := range states {
		for _, c := range w.Changes {
			if now.Sub(c.Time) < 7*24*time.Hour {
				recent = append(recent, c)
			}
		}
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].Time.After(recent[j].Time) })
	if len(recent) > 200 {
		recent = recent[:200]
	}
	if len(recent) == 0 {
		b.WriteString("  none\n")
	}
	for _, c := range recent {
		what := c.Detail
		if what == "" {
			what = strings.TrimSpace(c.Kind + " " + c.Host + " " + c.After)
		}
		fmt.Fprintf(&b, "- %s [%s] %s\n", c.Time.Local().Format("Mon 2 Jan 15:04"), orStr(c.Severity, "info"), what)
	}

	b.WriteString("\nINTERNET CONNECTIONS RIGHT NOW\n")
	if socks, err := listSockets(ctx); err != nil {
		fmt.Fprintf(&b, "  could not list them: %v\n", err)
	} else {
		threats, _ := loadThreats(ctx, stateDir, false)
		views := classify(socks, threats)
		if len(views) == 0 {
			b.WriteString("  none\n")
		}
		for _, c := range views {
			dir := "out to"
			if c.Inbound {
				dir = "IN from"
			}
			bad := ""
			if c.Threat != "" {
				bad = "  << on a list of known bad addresses (" + c.Threat + ")"
			}
			fmt.Fprintf(&b, "- %s %s %s:%d%s\n", orStr(c.proc(), "unknown program"), dir, c.who(), c.RemotePort, bad)
		}
	}

	b.WriteString("\nSTARTUP PROGRAMS, CERTIFICATES, ACCOUNTS AND SETTINGS\n")
	h := realHostOS()
	items := collectHostItems(ctx, h)
	if h.goos == "darwin" {
		tcc, _ := tccItems(ctx, h)
		items = append(items, tcc...)
	}
	base := loadHostBaseline(stateDir)
	sort.SliceStable(items, func(i, j int) bool { return items[i].Cat < items[j].Cat })
	for _, it := range items {
		mark := ""
		if base != nil && !base.Items[it.id()] {
			mark = "  << new since yaklite started watching"
		}
		fmt.Fprintf(&b, "- %s: %s%s\n", it.Cat, it.Label, mark)
	}

	b.WriteString("\nThis report stays on this computer unless you share it. It contains no passwords.\n")
	return b.String()
}

// incidentDir is where the report goes: the Desktop, so it is easy to find.
func incidentDir() string {
	home, _ := os.UserHomeDir()
	for _, d := range []string{"Desktop", "Downloads"} {
		p := filepath.Join(home, d)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return "."
}

func cmdIncident(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("incident", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	out := fs.String("o", "", "where to write the report (default: a new file on the Desktop)")
	fs.Parse(args)
	now := time.Now()
	fmt.Println("Collecting what yaklite knows (this takes a few seconds)...")
	rep := incidentReport(ctx, *stateDir, now)
	p := *out
	if p == "" {
		p = filepath.Join(incidentDir(), "yaklite-incident-"+now.Format("2006-01-02-1504")+".txt")
	}
	if err := writeFilePrivate(p, []byte(rep)); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("What to do, in this order:")
	for i, s := range incidentSteps {
		fmt.Printf("%2d. %s\n", i+1, s)
	}
	fmt.Printf("\nThe full report is in %s\n", p)
	return nil
}
