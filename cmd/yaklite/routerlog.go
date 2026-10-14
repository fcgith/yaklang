package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The router log reader receives the log most routers can send to another
// device ("remote log", "syslog server"). It looks for failed and successful
// admin logins, settings changes, ports being opened and floods of blocked
// connections, and alerts on them with the country of each address.
//
// It only listens on your own trusted network (bound to this computer's
// address there), and only accepts messages from the router.

type routerEvent struct {
	Time time.Time
	Kind string // login-fail, login-ok, portmap, config, blocked
	IP   net.IP // the other side, when the line names one
	Text string
}

var routerLogPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"login-fail", regexp.MustCompile(`(?i)(log ?in|logon|authenticat\w*|auth)\s*(attempt\s*)?(fail\w*|error|denied|incorrect|invalid|rejected)|(invalid|wrong|bad|incorrect) (password|user\w*|login|credentials)|failed (password|login|log in)|login (attempt )?blocked`)},
	{"login-ok", regexp.MustCompile(`(?i)(log ?in|logon)\s*(success\w*|ok\b)|logged in|accepted (password|publickey)|user \S+ (has )?log(ged)? ?in|admin login`)},
	{"portmap", regexp.MustCompile(`(?i)upnp|addportmapping|port ?mapping|port forward\w*`)},
	{"config", regexp.MustCompile(`(?i)(configuration|config|settings?)\s+(was\s+|were\s+|has been\s+)?(changed|saved|updated|modified|restored|applied)|firmware (upgrade|update)|factory (reset|default)|password (was\s+)?(changed|modified)|reboot(ed)? by`)},
	{"blocked", regexp.MustCompile(`(?i)\b(drop(ped)?|block(ed)?|deny|denied|reject(ed)?|dos|flood\w*|attack\w*|port ?scan\w*|intrusion)\b`)},
}

var (
	srcIPRe  = regexp.MustCompile(`(?i)\bSRC=(\d{1,3}(?:\.\d{1,3}){3})`)
	fromIPRe = regexp.MustCompile(`(?i)\b(?:from|src|source|client|remote|ip)[\s:=]+\[?(\d{1,3}(?:\.\d{1,3}){3})`)
	anyIPRe  = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	priRe    = regexp.MustCompile(`^<\d{1,3}>`)
)

// parseRouterLine classifies one log line. router is the router's own
// address, which is never "the other side".
func parseRouterLine(line string, now time.Time, router string) *routerEvent {
	line = strings.TrimSpace(priRe.ReplaceAllString(strings.TrimSpace(line), ""))
	if line == "" {
		return nil
	}
	ev := &routerEvent{Time: now, Text: line}
	for _, p := range routerLogPatterns {
		if p.re.MatchString(line) {
			ev.Kind = p.kind
			break
		}
	}
	if ev.Kind == "" {
		return nil
	}
	for _, re := range []*regexp.Regexp{srcIPRe, fromIPRe} {
		if m := re.FindStringSubmatch(line); m != nil && m[1] != router {
			ev.IP = net.ParseIP(m[1])
			break
		}
	}
	if ev.IP == nil {
		for _, m := range anyIPRe.FindAllStringSubmatch(line, -1) {
			if ip := net.ParseIP(m[1]); ip != nil && m[1] != router && !ip.IsUnspecified() && !ip.Equal(net.IPv4bcast) {
				ev.IP = ip
				break
			}
		}
	}
	return ev
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:5])
}

func ipWho(ip net.IP) string {
	s := ip.String()
	if o, ok := lookupIP(ip); ok && isPublicAddr(ip) {
		s += " (" + o.String() + ")"
	}
	return s
}

// analyzeRouterEvents turns recent router log events into findings.
func analyzeRouterEvents(events []routerEvent, now time.Time, threats *threatSet) []*Finding {
	var out []*Finding
	fails := map[string]int{}
	failIP := map[string]net.IP{}
	blocked := map[string]int{}
	var blockedTotal int
	for _, ev := range events {
		age := now.Sub(ev.Time)
		ipKey := ""
		if ev.IP != nil {
			ipKey = ev.IP.String()
		}
		bad := ""
		if f, ok := threats.lookup(ev.IP); ok {
			bad = " It is on " + feedAbout(f) + "."
		}
		switch ev.Kind {
		case "login-fail":
			if age < time.Hour {
				fails[ipKey]++
				failIP[ipKey] = ev.IP
			}
		case "login-ok":
			if ev.IP != nil && isPublicAddr(ev.IP) {
				out = append(out, &Finding{ID: "routerlog:login-public:" + ipKey, Severity: sevHigh, Host: ipKey, Until: ev.Time.Add(7 * 24 * time.Hour),
					Title:  "Someone on the internet logged in to your router: " + ipWho(ev.IP),
					Detail: "Router log: " + trunc(ev.Text, 200) + bad,
					Fix:    "If it was not you, change the router's admin password now, turn off remote management, and check its port forwarding and DNS settings."})
			}
		case "portmap":
			if age < time.Hour {
				out = append(out, &Finding{ID: "routerlog:portmap:" + shortHash(ev.Text), Severity: sevMedium, Until: ev.Time.Add(24 * time.Hour),
					Title: "Your router logged a port being opened to the internet: " + trunc(ev.Text, 160),
					Fix:   "If you do not know why, remove it in the router's port forwarding / UPnP page (yaklite check --only upnp lists them)."})
			}
		case "config":
			if age < time.Hour {
				out = append(out, &Finding{ID: "routerlog:config:" + shortHash(ev.Text), Severity: sevMedium, Until: ev.Time.Add(24 * time.Hour),
					Title: "Your router logged a settings change: " + trunc(ev.Text, 160),
					Fix:   "If you did not change anything, log in to the router, change its admin password and check its DNS, port forwarding and remote access settings."})
			}
		case "blocked":
			if age < 10*time.Minute {
				blockedTotal++
				blocked[ipKey]++
			}
			if bad != "" && age < time.Hour {
				// blocked, which is good, but worth knowing who is trying
				out = append(out, &Finding{ID: "routerlog:bad-ip:" + ipKey, Severity: sevLow, Host: ipKey, Until: ev.Time.Add(24 * time.Hour),
					Title: "Your router blocked a known attacker, " + ipWho(ev.IP),
					Detail: strings.TrimSpace(bad)})
			}
		}
	}
	for k, n := range fails {
		if n < 3 {
			continue
		}
		ip := failIP[k]
		sev, who := sevMedium, "an unknown address"
		if ip != nil {
			who = ipWho(ip)
			if isPublicAddr(ip) {
				sev = sevHigh
			}
		}
		out = append(out, &Finding{ID: "routerlog:login-fail:" + k, Severity: sev, Host: k, Until: now.Add(24 * time.Hour),
			Title:  fmt.Sprintf("%d failed logins to your router in the last hour from %s", n, who),
			Detail: "Someone is guessing the router's admin password.",
			Fix:    "Make sure the admin password is long and unique, and turn off remote management (WAN access) in the router's settings."})
	}
	total := 0
	for _, n := range fails {
		total += n
	}
	if total >= 10 && len(fails) >= 3 {
		out = append(out, &Finding{ID: "routerlog:login-fail-many", Severity: sevHigh, Until: now.Add(24 * time.Hour),
			Title:  fmt.Sprintf("%d failed logins to your router in the last hour, from %d different addresses", total, len(fails)),
			Detail: "Spreading guesses over many addresses is how attackers avoid lock-outs.",
			Fix:    "Make sure the admin password is long and unique, and turn off remote management (WAN access) in the router's settings."})
	}
	if blockedTotal >= 300 {
		type kv struct {
			ip string
			n  int
		}
		var top []kv
		for k, n := range blocked {
			top = append(top, kv{k, n})
		}
		sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n })
		who := ""
		if len(top) > 0 && top[0].ip != "" {
			who = fmt.Sprintf(", the most from %s (%d)", ipWho(net.ParseIP(top[0].ip)), top[0].n)
		}
		out = append(out, &Finding{ID: "routerlog:flood:" + now.Format("2006010215"), Severity: sevMedium, Until: now.Add(time.Hour),
			Title: fmt.Sprintf("Your router blocked %d connection attempts in the last 10 minutes%s", blockedTotal, who),
			Fix:   "The router is doing its job. If this goes on, ask your internet provider about it, and make sure nothing is forwarded to devices that do not need it."})
	}
	return out
}

// ---- receiving ----

type routerLogReceiver struct {
	mu       sync.Mutex
	events   []routerEvent
	stateDir string
	router   string // current router address
}

func (r *routerLogReceiver) add(line string, from net.IP) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	appendRouterLog(r.stateDir, now, from, line)
	if ev := parseRouterLine(line, now, r.router); ev != nil {
		r.events = append(r.events, *ev)
	}
	// keep a day, at most 50k events
	cut := 0
	for cut < len(r.events) && (now.Sub(r.events[cut].Time) > 24*time.Hour || len(r.events)-cut > 50000) {
		cut++
	}
	r.events = r.events[cut:]
}

func (r *routerLogReceiver) snapshot() []routerEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]routerEvent(nil), r.events...)
}

// appendRouterLog keeps the raw log, owner-only, in two 5 MB files.
func appendRouterLog(dir string, t time.Time, from net.IP, line string) {
	p := filepath.Join(dir, "router.log")
	if st, err := os.Stat(p); err == nil && st.Size() > 5<<20 {
		os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s %s\n", t.Format(time.RFC3339), from, strings.TrimSpace(line))
}

// lanListener keeps a listener open only while this computer is on a
// network you trust, bound to its address there. open is called with the
// address to listen on and returns a closer.
type lanListener struct {
	always bool   // listen whatever the network (an always-on box): bind to all addresses
	port   int    // for messages
	open   func(ip string) (func(), error)
	prog   func(string, ...any)
	cur    string // the address currently bound
	closer func()
	onNet  func(n *networkInfo)
}

func (l *lanListener) refresh(ctx context.Context) {
	want := ""
	var n *networkInfo
	if l.always {
		want = "0.0.0.0"
		n, _ = currentNetwork(ctx)
	} else if cn, err := currentNetwork(ctx); err == nil {
		nf, _ := loadNetworks()
		if k := nf.Networks[cn.ID()]; k != nil && k.Trusted {
			want, n = cn.SelfIP, cn
		}
	}
	if n != nil && l.onNet != nil {
		l.onNet(n)
	}
	if want == l.cur {
		return
	}
	if l.closer != nil {
		l.closer()
		l.closer = nil
		l.prog("stopped listening on %s", l.cur)
	}
	l.cur = ""
	if want == "" {
		return
	}
	c, err := l.open(want)
	if err != nil {
		l.prog("cannot listen on %s: %v", want, err)
		return
	}
	l.cur, l.closer = want, c
	l.prog("listening on %s", want)
}

func (l *lanListener) run(ctx context.Context) {
	for {
		l.refresh(ctx)
		select {
		case <-ctx.Done():
			if l.closer != nil {
				l.closer()
			}
			return
		case <-time.After(time.Minute):
		}
	}
}

func cmdRouterLog(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("routerlog", flag.ExitOnError)
	wf := addWatchFlags(fs, time.Minute)
	port := fs.Int("port", 5514, "UDP port to receive the router's log on (set the same in the router's remote log / syslog settings)")
	from := fs.String("from", "", "also accept logs from these addresses, comma separated (the router is always accepted)")
	always := fs.Bool("always", false, "listen on every network, on all addresses (for an always-on box at home); needs --from or a router to accept from")
	desktop := fs.Bool("notify", false, "show desktop notifications")
	quiet := fs.Bool("q", false, "quiet")
	noThreat := fs.Bool("no-threat-lists", false, "do not download public lists of known bad addresses")
	fs.Parse(args)
	if *port <= 0 || *port > 65535 {
		return errors.New("--port must be 1-65535")
	}
	if *wf.name == "" {
		*wf.name = "router-log"
	}
	prog := progress(*quiet)
	if prog == nil {
		prog = func(string, ...any) {}
	}
	stateDir := *wf.stateDir
	os.MkdirAll(stateDir, 0o700)
	rx := &routerLogReceiver{stateDir: stateDir}
	var allowMu sync.Mutex
	allowed := map[string]bool{}
	for _, s := range strings.Split(*from, ",") {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			allowed[ip.String()] = true
		}
	}
	gateway := ""
	ll := &lanListener{always: *always, port: *port, prog: prog,
		onNet: func(n *networkInfo) {
			allowMu.Lock()
			gateway = n.Gateway
			allowMu.Unlock()
			rx.mu.Lock()
			rx.router = n.Gateway
			rx.mu.Unlock()
		},
		open: func(ip string) (func(), error) {
			pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, fmt.Sprint(*port)))
			if err != nil {
				return nil, err
			}
			go func() {
				buf := make([]byte, 8192)
				for {
					n, addr, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					ua, ok := addr.(*net.UDPAddr)
					if !ok {
						continue
					}
					allowMu.Lock()
					ok = allowed[ua.IP.String()] || ua.IP.String() == gateway
					allowMu.Unlock()
					if !ok {
						continue // only the router may write here
					}
					for _, line := range strings.Split(string(buf[:n]), "\n") {
						if strings.TrimSpace(line) != "" {
							rx.add(line, ua.IP)
						}
					}
				}
			}()
			return func() { pc.Close() }, nil
		}}
	go ll.run(ctx)

	opts := defaultCheckOptions()
	opts.threatLists = !*noThreat
	scan := func(ctx context.Context) (*Snapshot, error) {
		snap := NewSnapshot("router log", "", "router-log")
		snap.Started = time.Now()
		var threats *threatSet
		if opts.threatLists {
			threats, _ = loadThreats(ctx, stateDir, true)
		}
		for _, f := range analyzeRouterEvents(rx.snapshot(), time.Now(), threats) {
			f.Check = "routerlog"
			snap.addFinding(f)
		}
		snap.Finished = time.Now()
		return snap, nil
	}
	w, err := wf.build(scan, prog, "router-log")
	if err != nil {
		return err
	}
	if *desktop {
		w.ac.desktop = "your router"
	}
	return runWatch(ctx, w)
}
