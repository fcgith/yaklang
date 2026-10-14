package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Finding is a standing problem found by a check other than the port scan:
// the firewall is off, the router opened a port by itself, someone on the
// internet is connected to this computer. Findings live in the snapshot, so
// the usual diff reports each one once, when it first appears, and again
// (as info) when it is gone.
type Finding struct {
	ID       string `json:"id"`    // stable across runs, e.g. "upnp:tcp/3389"
	Check    string `json:"check"` // which check produced it
	Severity string `json:"severity"`
	Host     string `json:"host,omitempty"`
	Title    string `json:"title"` // one plain sentence
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"` // what to do about it
	// Until keeps a finding that comes and goes (a connection) in the
	// snapshot after it was last seen, so it is not reported again each time.
	Until time.Time `json:"until,omitempty"`
}

func (s *Snapshot) addFinding(f *Finding) {
	if s.Findings == nil {
		s.Findings = map[string]*Finding{}
	}
	if f.Severity == "" {
		f.Severity = sevMedium
	}
	s.Findings[f.ID] = f
}

func diffFindings(prev, cur *Snapshot, now time.Time) []Change {
	var changes []Change
	var ids []string
	for id := range cur.Findings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f := cur.Findings[id]
		if prev != nil && prev.Findings[id] != nil {
			p := prev.Findings[id]
			if sevRank[f.Severity] > sevRank[p.Severity] {
				// got worse: report it again
				changes = append(changes, findingChange(f, now))
			}
			continue
		}
		changes = append(changes, findingChange(f, now))
	}
	if prev == nil {
		return changes
	}
	ids = ids[:0]
	for id := range prev.Findings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if cur.Findings[id] != nil {
			continue
		}
		p := prev.Findings[id]
		if p.Until.After(now) {
			cur.addFinding(p) // still remembered: keep it quietly
			continue
		}
		changes = append(changes, Change{Time: now, Kind: "finding_resolved", ID: id, Host: p.Host, Before: p.Title})
	}
	return changes
}

func findingChange(f *Finding, now time.Time) Change {
	return Change{Time: now, Kind: "finding", ID: f.ID, Severity: f.Severity, Host: f.Host, After: f.Title, Detail: f.Detail, Fix: f.Fix}
}

// Key identifies what a change is about, for acknowledging or snoozing it.
func (c Change) Key() string {
	switch c.Kind {
	case "finding", "finding_resolved":
		return c.ID
	}
	k := c.Kind + ":" + c.Host
	if c.Port != 0 {
		k += ":" + fmt.Sprintf("%s/%d", c.Proto, c.Port)
	}
	return k
}

// ---- checks ----

// checkEnv is what a check gets to work with.
type checkEnv struct {
	net      *networkInfo // nil when not known (e.g. `yaklite check` off-network)
	trusted  bool         // the user said this network is theirs
	snap     *Snapshot    // this run's scan, if any
	stateDir string
	prog     func(string, ...any)
	opts     *checkOptions
	inAuto   bool
	inv      *Inventory
	mu       sync.Mutex
}

// warn records a problem that did not stop a check.
func (e *checkEnv) warn(msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.snap.SourceErrors = append(e.snap.SourceErrors, msg)
}

type checkOptions struct {
	threatLists  bool   // download public blocklists of known bad addresses
	publicLookup bool   // ask a public service for this network's public IP and what scanners know about it
	countrySev   string // severity for a connection to a country never seen before
	learnFor     time.Duration
}

func defaultCheckOptions() *checkOptions {
	return &checkOptions{threatLists: true, publicLookup: true, countrySev: sevLow, learnFor: 7 * 24 * time.Hour}
}

type check struct {
	name        string
	about       string
	trustedOnly bool // only on networks the user said are theirs (it talks to other devices)
	autoSkip    bool // has its own background job, so the hourly check leaves it out
	after       bool // runs once the others are done, so it can use what they found
	last        bool // runs after the "after" checks
	run         func(ctx context.Context, env *checkEnv) ([]*Finding, error)
}

var (
	checksMu sync.Mutex
	checks   []*check
)

func registerCheck(c *check) {
	checksMu.Lock()
	defer checksMu.Unlock()
	checks = append(checks, c)
}

// runChecks runs every applicable check and adds what they find to snap.
func runChecks(ctx context.Context, env *checkEnv, only map[string]bool) {
	checksMu.Lock()
	list := append([]*check(nil), checks...)
	checksMu.Unlock()
	mu := &env.mu
	for phase := 0; phase < 3; phase++ {
		var wg sync.WaitGroup
		for _, c := range list {
			p := 0
			if c.last {
				p = 2
			} else if c.after {
				p = 1
			}
			if p != phase || (only != nil && !only[c.name]) {
				continue
			}
			if (c.trustedOnly && !env.trusted) || (c.autoSkip && env.inAuto) {
				continue
			}
			wg.Add(1)
			go func(c *check) {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				fs, err := c.run(cctx, env)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					env.snap.SourceErrors = append(env.snap.SourceErrors, c.name+": "+err.Error())
				}
				for _, f := range fs {
					f.Check = c.name
					env.snap.addFinding(f)
				}
			}(c)
		}
		wg.Wait()
	}
	sort.Strings(env.snap.SourceErrors)
}

// cmdCheck runs the checks once and prints what they find, without keeping
// state or alerting.
func cmdCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	only := fs.String("only", "", "comma separated checks to run (default: all); see --list")
	list := fs.Bool("list", false, "list the checks and exit")
	noThreat := fs.Bool("no-threat-lists", false, "do not download public lists of known bad addresses")
	noPublic := fs.Bool("no-public-lookup", false, "do not ask public services for this network's public IP")
	accept := fs.Bool("accept", false, "accept this computer's current startup programs, certificates, proxy/DNS settings, profiles and accounts as normal (the host check then reports only what is new)")
	fs.Parse(args)
	if *accept {
		items := collectHostItems(ctx, realHostOS())
		if err := saveHostBaseline(defaultStateDir(), items, false); err != nil {
			return err
		}
		fmt.Printf("Recorded %d startup programs, certificates, settings and accounts as normal.\n", len(items))
		return nil
	}
	if *list {
		checksMu.Lock()
		defer checksMu.Unlock()
		for _, c := range checks {
			t := ""
			if c.trustedOnly {
				t = " (trusted networks only)"
			}
			fmt.Printf("  %-10s %s%s\n", c.name, c.about, t)
		}
		return nil
	}
	env := &checkEnv{snap: NewSnapshot("", "", "check"), stateDir: defaultStateDir(), prog: func(string, ...any) {}, opts: defaultCheckOptions()}
	env.opts.threatLists, env.opts.publicLookup = !*noThreat, !*noPublic
	if n, err := currentNetwork(ctx); err == nil {
		env.net = n
		nf, _ := loadNetworks()
		if k := nf.Networks[n.ID()]; k != nil {
			env.trusted = k.Trusted
		}
	}
	var sel map[string]bool
	if *only != "" {
		sel = map[string]bool{}
		for _, s := range strings.Split(*only, ",") {
			sel[strings.TrimSpace(s)] = true
		}
	}
	runChecks(ctx, env, sel)
	printFindings(env.snap)
	if !env.trusted && env.net != nil {
		fmt.Println("\n(This network is not marked as yours, so checks that talk to other devices were skipped.)")
	}
	return nil
}

func printFindings(s *Snapshot) {
	var fs []*Finding
	for _, f := range s.Findings {
		fs = append(fs, f)
	}
	sort.Slice(fs, func(i, j int) bool {
		if sevRank[fs[i].Severity] != sevRank[fs[j].Severity] {
			return sevRank[fs[i].Severity] > sevRank[fs[j].Severity]
		}
		return fs[i].ID < fs[j].ID
	})
	if len(fs) == 0 {
		fmt.Println("No problems found.")
	}
	for _, f := range fs {
		fmt.Printf("%-6s %s\n", strings.ToUpper(f.Severity), f.Title)
		if f.Detail != "" {
			fmt.Printf("       %s\n", f.Detail)
		}
		if f.Fix != "" {
			fmt.Printf("       Fix: %s\n", f.Fix)
		}
		fmt.Printf("       (id %s)\n", f.ID)
	}
	for _, e := range s.SourceErrors {
		fmt.Fprintln(os.Stderr, "[yaklite] check failed:", e)
	}
}

// ---- acknowledging and snoozing alerts ----

type ack struct {
	Key   string    `yaml:"key"` // a change key; a trailing * matches any key with that prefix
	Until time.Time `yaml:"until,omitempty"`
	Note  string    `yaml:"note,omitempty"`
}

type acksFile struct {
	Acks []ack `yaml:"acks"`
}

func acksPath() string { return filepath.Join(configDir(), "acks.yaml") }

func loadAcks() *acksFile {
	af := &acksFile{}
	if data, err := os.ReadFile(acksPath()); err == nil {
		yaml.Unmarshal(data, af)
	}
	return af
}

func (af *acksFile) save() error {
	data, err := yaml.Marshal(af)
	if err != nil {
		return err
	}
	return writeFilePrivate(acksPath(), append([]byte("# Alerts you acknowledged (no until) or snoozed (until). Remove a line to hear about it again.\n"), data...))
}

func (af *acksFile) matches(key string, now time.Time) bool {
	for _, a := range af.Acks {
		if !a.Until.IsZero() && now.After(a.Until) {
			continue
		}
		if a.Key == key || (strings.HasSuffix(a.Key, "*") && strings.HasPrefix(key, strings.TrimSuffix(a.Key, "*"))) {
			return true
		}
	}
	return false
}

// dropAcked removes acknowledged and snoozed changes from what is shown and sent.
func dropAcked(changes []Change, now time.Time) []Change {
	af := loadAcks()
	if len(af.Acks) == 0 {
		return changes
	}
	var out []Change
	for _, c := range changes {
		if !af.matches(c.Key(), now) {
			out = append(out, c)
		}
	}
	return out
}

func addAck(key string, d time.Duration, note string) (ack, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return ack{}, errors.New("empty key")
	}
	af := loadAcks()
	a := ack{Key: key, Note: note}
	if d > 0 {
		a.Until = time.Now().Add(d).Truncate(time.Minute)
	}
	kept := af.Acks[:0]
	for _, x := range af.Acks {
		if x.Key != key && (x.Until.IsZero() || time.Now().Before(x.Until)) {
			kept = append(kept, x)
		}
	}
	af.Acks = append(kept, a)
	return a, af.save()
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "forever" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") || strings.HasSuffix(s, "w") {
		var n int
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err != nil || n <= 0 {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		unit := 24 * time.Hour
		if strings.HasSuffix(s, "w") {
			unit *= 7
		}
		return time.Duration(n) * unit, nil
	}
	return time.ParseDuration(s)
}

// cmdAck: yaklite ack KEY [--for 7d] [--note "..."], or --list / --remove.
func cmdAck(args []string) error {
	fs := flag.NewFlagSet("ack", flag.ExitOnError)
	forD := fs.String("for", "forever", `how long to keep quiet: "forever" (I know about this), or 1d, 1w, 12h`)
	note := fs.String("note", "", "why, for your future self")
	list := fs.Bool("list", false, "list acknowledged and snoozed alerts")
	remove := fs.Bool("remove", false, "remove the acknowledgement for KEY")
	fs.Parse(reorderArgs(fs, args))
	if *list {
		af := loadAcks()
		if len(af.Acks) == 0 {
			fmt.Println("Nothing acknowledged or snoozed.")
		}
		for _, a := range af.Acks {
			until := "forever"
			if !a.Until.IsZero() {
				until = "until " + a.Until.Local().Format("2006-01-02 15:04")
			}
			fmt.Printf("  %-40s %s  %s\n", a.Key, until, a.Note)
		}
		return nil
	}
	if fs.NArg() != 1 {
		return errors.New(`usage: yaklite ack KEY [--for 1w] [--note "..."]   (keys are shown by: yaklite alerts)`)
	}
	if *remove {
		af := loadAcks()
		kept := af.Acks[:0]
		for _, a := range af.Acks {
			if a.Key != fs.Arg(0) {
				kept = append(kept, a)
			}
		}
		af.Acks = kept
		return af.save()
	}
	d, err := parseDuration(*forD)
	if err != nil {
		return err
	}
	a, err := addAck(fs.Arg(0), d, *note)
	if err != nil {
		return err
	}
	if a.Until.IsZero() {
		fmt.Printf("OK, %s is acknowledged: it will not be alerted again (yaklite ack --remove %s to undo).\n", a.Key, a.Key)
	} else {
		fmt.Printf("OK, %s is snoozed until %s.\n", a.Key, a.Until.Local().Format("Mon 2 Jan 15:04"))
	}
	return nil
}

// reorderArgs lets flags come after positional arguments.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") {
				if f := fs.Lookup(name); f != nil {
					if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
						if i+1 < len(args) {
							flags = append(flags, args[i+1])
							i++
						}
					}
				}
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

// cmdAlerts lists recent alerts from the change logs, with the keys `ack` takes.
func cmdAlerts(args []string) error {
	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	since := fs.String("since", "7d", "how far back to look")
	minSev := fs.String("min-severity", "low", "lowest severity to list")
	fs.Parse(args)
	d, err := parseDuration(*since)
	if err != nil {
		return err
	}
	min, err := parseSeverity(*minSev)
	if err != nil {
		return err
	}
	r := &stateReader{dir: *stateDir}
	states, err := r.load()
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-d)
	af := loadAcks()
	var all []Change
	for _, st := range states {
		for _, c := range st.Changes {
			if c.Time.After(cutoff) && sevRank[c.Severity] >= sevRank[min] {
				all = append(all, c)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	if len(all) == 0 {
		fmt.Println("No alerts in that period.")
	}
	for _, c := range all {
		mark := ""
		if af.matches(c.Key(), time.Now()) {
			mark = "  (acknowledged)"
		}
		fmt.Printf("%s  %s%s\n      key: %s\n", c.Time.Local().Format("2006-01-02 15:04"), c, mark, c.Key())
	}
	return nil
}
