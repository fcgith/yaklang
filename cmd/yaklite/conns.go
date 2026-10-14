package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The connection watch looks at this computer's own TCP connections, as the
// OS lists them, and flags three things:
//
//   - someone on the internet connected to a port this computer listens on
//   - a connection, either way, with an address on a public list of
//     attackers and malware servers
//   - the first connection to a server in a country not seen before (after
//     a learning week, so normal browsing does not alert)
//
// It sends nothing to the other side; addresses are looked up in the
// built-in owner/country table.

func init() {
	registerCheck(&check{name: "conns", about: "connections to and from this computer: from the internet, with known attackers, to new countries", autoSkip: true, run: connsCheck})
}

type connMemory struct {
	Started   time.Time            `json:"started"`
	Countries map[string]time.Time `json:"countries"` // first seen
}

func loadConnMemory(dir string) (*connMemory, string) {
	p := filepath.Join(dir, "connections-memory.json")
	m := &connMemory{}
	if data, err := os.ReadFile(p); err == nil {
		json.Unmarshal(data, m)
	}
	if m.Countries == nil {
		m.Countries = map[string]time.Time{}
	}
	if m.Started.IsZero() {
		m.Started = time.Now()
	}
	return m, p
}

type connView struct {
	sock
	Inbound bool
	Owner   IPOwner
	Known   bool   // owner known
	Threat  string // feed name, if listed
}

func (c connView) who() string {
	s := c.RemoteIP.String()
	if c.Known {
		s += " (" + c.Owner.String() + ")"
	}
	return s
}

func (c connView) proc() string {
	if c.Process != "" && !strings.HasPrefix(c.Process, "inode:") {
		return c.Process
	}
	return ""
}

// classify turns raw sockets into public connections worth looking at.
func classify(socks []sock, threats *threatSet) []connView {
	listening := map[int]bool{}
	for _, s := range socks {
		if s.State == "LISTEN" {
			listening[s.LocalPort] = true
		}
	}
	seen := map[string]bool{}
	var out []connView
	for _, s := range socks {
		if s.State != "ESTABLISHED" && s.State != "SYN_RECV" && s.State != "SYN_RCVD" && s.State != "SYN_SENT" {
			continue
		}
		if !isPublicAddr(s.RemoteIP) || seen[s.key()] {
			continue
		}
		seen[s.key()] = true
		v := connView{sock: s}
		// inbound when we listen on the local port and the remote side picked
		// its own; an outbound connection's local port is ephemeral
		v.Inbound = listening[s.LocalPort] && s.State != "SYN_SENT" && !(listening[s.RemotePort] && s.LocalPort > s.RemotePort)
		v.Owner, v.Known = lookupIP(s.RemoteIP)
		if f, ok := threats.lookup(s.RemoteIP); ok {
			v.Threat = f
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RemoteIP.String() < out[j].RemoteIP.String() })
	return out
}

func connsCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	socks, err := listSockets(ctx)
	if err != nil {
		return nil, err
	}
	var threats *threatSet
	if env.opts.threatLists {
		var errs []string
		threats, errs = loadThreats(ctx, env.stateDir, true)
		for _, e := range errs {
			env.warn(e)
		}
	}
	mem, memPath := loadConnMemory(env.stateDir)
	now := time.Now()
	learning := now.Sub(mem.Started) < env.opts.learnFor
	var out []*Finding
	views := classify(socks, threats)
	out = append(out, programFindings(ctx, views, now)...)
	for _, c := range views {
		proc := ""
		if p := c.proc(); p != "" {
			proc = " by " + p
		}
		switch {
		case c.Threat != "":
			f := &Finding{ID: "bad-ip:" + c.RemoteIP.String(), Severity: sevHigh, Host: c.RemoteIP.String(), Until: now.Add(24 * time.Hour),
				Detail: "Listed by " + feedAbout(c.Threat) + "."}
			if c.Inbound {
				f.Title = fmt.Sprintf("A known attacker, %s, is connected to this computer on port %d%s", c.who(), c.LocalPort, proc)
				f.Fix = "Turn off or firewall that service, and remove any port forward or UPnP mapping for it on your router (yaklite check --only upnp lists them)."
			} else {
				f.Title = fmt.Sprintf("This computer is talking to a known bad address, %s, port %d%s", c.who(), c.RemotePort, proc)
				f.Fix = "Find the program that made the connection. If you do not recognise it, disconnect from the network and run a malware scan."
			}
			out = append(out, f)
		case c.Inbound:
			out = append(out, &Finding{ID: fmt.Sprintf("inbound:%s:%d", c.RemoteIP, c.LocalPort), Severity: sevHigh, Host: c.RemoteIP.String(), Until: now.Add(24 * time.Hour),
				Title: fmt.Sprintf("Someone on the internet, %s, is connected to this computer on port %d%s", c.who(), c.LocalPort, proc),
				Fix:   "If you did not set this up, turn the service off and remove the port forward or UPnP mapping on your router. yaklite ack this alert if it is expected (a VPN or a game server)."})
		case c.Known && c.Owner.Country != "":
			if _, ok := mem.Countries[c.Owner.Country]; ok {
				continue
			}
			mem.Countries[c.Owner.Country] = now
			if learning {
				continue
			}
			out = append(out, &Finding{ID: "country:" + c.Owner.Country, Severity: env.opts.countrySev, Host: c.RemoteIP.String(), Until: now.Add(7 * 24 * time.Hour),
				Title: fmt.Sprintf("First connection to a server in %s: %s (%s)%s", countryName(c.Owner.Country), c.RemoteIP, c.Owner.Org, proc),
				Fix:   "Usually harmless: a website, app or update server hosted there. If you do not expect it, check which program it was."})
		}
	}
	if data, err := json.MarshalIndent(mem, "", "  "); err == nil {
		writeFilePrivate(memPath, data)
	}
	return out, nil
}

// cmdConns prints this computer's current internet connections.
func cmdConns(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("conns", flag.ExitOnError)
	noThreat := fs.Bool("no-threat-lists", false, "do not download public lists of known bad addresses")
	asJSON := fs.Bool("json", false, "print as JSON")
	fs.Parse(args)
	socks, err := listSockets(ctx)
	if err != nil {
		return err
	}
	threats, errs := loadThreats(ctx, defaultStateDir(), !*noThreat)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "[yaklite]", e)
	}
	views := classify(socks, threats)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(views)
	}
	var listen []string
	for _, s := range socks {
		if s.State == "LISTEN" && !s.LocalIP.IsLoopback() {
			l := fmt.Sprintf("%d", s.LocalPort)
			if p := (connView{sock: s}).proc(); p != "" {
				l += " (" + p + ")"
			}
			if !contains(listen, l) {
				listen = append(listen, l)
			}
		}
	}
	sort.Strings(listen)
	fmt.Printf("Listening for connections from other machines on: %s\n\n", orNone(strings.Join(listen, ", ")))
	if len(views) == 0 {
		fmt.Println("No connections to the internet right now.")
		return nil
	}
	type row struct {
		dir, remote, prog, owner string
		port, n                  int
	}
	var rows []*row
	idx := map[string]*row{}
	for _, v := range views {
		r := &row{dir: "out", remote: v.RemoteIP.String(), port: v.RemotePort, prog: v.proc(), owner: v.Owner.String()}
		if v.Inbound {
			r.dir, r.port = "IN", v.LocalPort
		}
		if v.Threat != "" {
			r.owner = "KNOWN BAD (" + v.Threat + ") " + r.owner
		}
		k := fmt.Sprintf("%s|%s|%d|%s", r.dir, r.remote, r.port, r.prog)
		if idx[k] != nil {
			idx[k].n++
			continue
		}
		r.n = 1
		idx[k] = r
		rows = append(rows, r)
	}
	fmt.Printf("%-4s %-22s %-6s %-3s %-16s %s\n", "DIR", "REMOTE", "PORT", "#", "PROGRAM", "OWNER")
	for _, r := range rows {
		fmt.Printf("%-4s %-22s %-6d %-3d %-16s %s\n", r.dir, r.remote, r.port, r.n, trunc(r.prog, 16), r.owner)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// cmdConnWatch samples connections continuously and alerts on new findings.
func cmdConnWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connwatch", flag.ExitOnError)
	wf := addWatchFlags(fs, 30*time.Second)
	desktop := fs.Bool("notify", false, "show desktop notifications")
	noThreat := fs.Bool("no-threat-lists", false, "do not download public lists of known bad addresses")
	countrySev := fs.String("new-country-severity", sevLow, "severity for a first connection to a new country: info, low, medium, high")
	learn := fs.String("learn", "7d", "learning period before new countries are reported")
	quiet := fs.Bool("q", false, "quiet")
	fs.Parse(args)
	opts := defaultCheckOptions()
	opts.threatLists = !*noThreat
	var err error
	if opts.countrySev, err = parseSeverity(*countrySev); err != nil {
		return err
	}
	if opts.learnFor, err = parseDuration(*learn); err != nil {
		return err
	}
	if *wf.name == "" {
		*wf.name = "connections"
	}
	prog := progress(*quiet)
	stateDir := *wf.stateDir
	scan := func(ctx context.Context) (*Snapshot, error) {
		snap := NewSnapshot("this computer", "", "connections")
		snap.Started = time.Now()
		env := &checkEnv{snap: snap, stateDir: stateDir, prog: func(string, ...any) {}, opts: opts}
		runChecks(ctx, env, map[string]bool{"conns": true})
		if f := trackOutage(stateDir, internetUp(ctx), defaultGateway() != "", time.Now()); f != nil {
			f.Check = "outage"
			snap.addFinding(f)
		}
		snap.Finished = time.Now()
		if len(snap.SourceErrors) > 0 && len(snap.Findings) == 0 && strings.Contains(strings.Join(snap.SourceErrors, ""), "conns:") {
			return nil, errors.New(strings.Join(snap.SourceErrors, "; "))
		}
		return snap, nil
	}
	w, err := wf.build(scan, prog, "connections")
	if err != nil {
		return err
	}
	if *desktop {
		w.ac.desktop = "this computer"
	}
	w.quietErrors = true
	return runWatch(ctx, w)
}
