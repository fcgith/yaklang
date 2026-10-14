// Command yaklite is a small network inventory and monitoring tool built from
// yaklang's port scanner and service fingerprinter.
//
// It deliberately leaves out the rest of the yak engine: there is no script
// VM, gRPC server, AI agent, MITM CA, plugin store or self-updater. It only
// listens on a port when asked to (serve, or watch --listen), read-only and on
// localhost by default. Files it writes are owner-only.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kataras/golog"
	_ "github.com/yaklang/yaklang/cmd/yaklite/internal/privhome"
	"github.com/yaklang/yaklang/common/log"
)

const usage = `yaklite: home network monitoring and alerts (built from yaklang)

Set and forget (laptops and desktops):
  yaklite install [--webhook URL]   check in the background, notify on problems
  yaklite status                  current network, trust, last check
  yaklite trust [--name Home]     monitor every device on the current network
  yaklite untrust                 only check this computer on the current network
  yaklite name IP|MAC "Name" [--expect 22,443]   name a device
  yaklite uninstall [--purge]
  yaklite update [--check]        install the latest build (checksum verified)

What it found:
  yaklite alerts [--since 7d]     recent alerts, with the key to acknowledge each
  yaklite ack KEY [--for 1w]      "I know about this" (or snooze it for a while)
  yaklite summary                 the weekly summary, now
  yaklite history                 when each device was first and last seen
  yaklite serve                   dashboard on http://127.0.0.1:9842 + Prometheus metrics

Checks:
  yaklite check [--only upnp,dns] [--list]   router, DNS, Wi-Fi, this computer's settings, ...
  yaklite conns                   this computer's internet connections, with owner and country
  yaklite connwatch               alert on connections from the internet or with known attackers
  yaklite outside -d example.com [--ip 203.0.113.7]   your domains and public IP, seen from outside

By hand:
  yaklite scan  -t TARGETS [-p PORTS] [--udp] [-o snapshot.json]
  yaklite watch -t TARGETS [--every 1h] [--checks] [--inventory FILE] [--webhook URL] [--once]
  yaklite diff  OLD.json NEW.json
  yaklite auto                    one check of the current network (what install schedules)
  yaklite block device IP | site DOMAIN   through AdGuard Home or Pi-hole (yaklite block --help)
  yaklite mcp                     let Claude read the results (Model Context Protocol, read-only)

TARGETS  IPs, CIDRs, ranges or hostnames, comma separated (192.168.1.0/24,10.0.0.5)
PORTS    "top" (default, ~80 common LAN ports), "all", or a list like 22,80,8000-8100

Only scan networks you own or are authorised to test.
`

// version is set at build time: -ldflags "-X main.version=..."
var version = "dev"

func main() {
	log.SetLevel(golog.ErrorLevel)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(ctx, os.Args[2:])
	case "watch":
		err = cmdWatch(ctx, os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "serve":
		err = cmdServe(ctx, os.Args[2:])
	case "outside":
		err = cmdOutside(ctx, os.Args[2:])
	case "auto":
		err = cmdAuto(ctx, os.Args[2:])
	case "install":
		err = cmdInstall(ctx, os.Args[2:])
	case "uninstall":
		err = cmdUninstall(os.Args[2:])
	case "trust":
		err = cmdTrust(ctx, os.Args[2:], true)
	case "untrust":
		err = cmdTrust(ctx, os.Args[2:], false)
	case "name":
		err = cmdName(os.Args[2:])
	case "status":
		err = cmdStatus(ctx, os.Args[2:])
	case "conns":
		err = cmdConns(ctx, os.Args[2:])
	case "connwatch":
		err = cmdConnWatch(ctx, os.Args[2:])
	case "summary":
		err = cmdSummary(ctx, os.Args[2:])
	case "history":
		err = cmdHistory(os.Args[2:])
	case "block":
		err = cmdBlock(ctx, os.Args[2:], true)
	case "unblock":
		err = cmdBlock(ctx, os.Args[2:], false)
	case "mcp":
		err = cmdMCP(ctx, os.Args[2:])
	case "update":
		err = cmdUpdate(ctx, os.Args[2:])
	case "version", "--version":
		fmt.Println("yaklite", version)
	case "check":
		err = cmdCheck(ctx, os.Args[2:])
	case "routerlog":
		err = cmdRouterLog(ctx, os.Args[2:])
	case "tripwire":
		err = cmdTripwire(ctx, os.Args[2:])
	case "firewall":
		err = cmdFirewall(ctx, os.Args[2:])
	case "private-dns":
		err = cmdPrivateDNS(os.Args[2:])
	case "score":
		err = cmdScore(os.Args[2:])
	case "outages":
		err = cmdOutages(os.Args[2:])
	case "router":
		err = cmdRouter(ctx, os.Args[2:])
	case "password-check":
		err = cmdPasswordCheck(ctx, os.Args[2:])
	case "breaches":
		err = cmdBreaches(ctx, os.Args[2:])
	case "quiet":
		err = cmdQuiet(os.Args[2:])
	case "report":
		err = cmdReport(ctx, os.Args[2:])
	case "ack":
		err = cmdAck(os.Args[2:])
	case "alerts":
		err = cmdAlerts(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func scanFlags(fs *flag.FlagSet, opt *ScanOptions) *bool {
	fs.StringVar(&opt.Targets, "t", "", "targets: IPs, CIDRs, ranges or hostnames, comma separated (required)")
	fs.StringVar(&opt.Ports, "p", "top", `ports: "top", "all" or a list like 22,80,8000-8100`)
	fs.StringVar(&opt.Exclude, "exclude", "", "hosts to skip, same syntax as -t")
	fs.BoolVar(&opt.SYN, "syn", false, "use SYN scanning for discovery (faster on subnets, needs root or CAP_NET_RAW)")
	fs.IntVar(&opt.Concurrency, "c", 200, "concurrent connection attempts")
	fs.DurationVar(&opt.DialTimeout, "dial-timeout", 1500*time.Millisecond, "connect timeout per port")
	fs.DurationVar(&opt.ProbeTimeout, "probe-timeout", 5*time.Second, "timeout per fingerprint probe")
	fs.BoolVar(&opt.NoFingerprint, "no-fp", false, "only report open ports, skip service fingerprinting")
	fs.BoolVar(&opt.NoTLS, "no-tls", false, "skip reading TLS certificates on HTTPS and other TLS ports")
	fs.BoolVar(&opt.NoARP, "no-arp", false, "skip finding devices by MAC address on directly attached networks")
	fs.BoolVar(&opt.UDP, "udp", false, "also probe common UDP services (DNS, NTP, SNMP, SSDP/UPnP, mDNS, TFTP, IPMI, ...) on live hosts")
	fs.StringVar(&opt.UDPPorts, "udp-ports", DefaultUDPPorts, "UDP ports for --udp")
	fs.BoolVar(&opt.NoNames, "no-names", false, "skip reverse DNS lookups for device names")
	return fs.Bool("q", false, "quiet: no progress output on stderr")
}

func progress(quiet bool) func(string, ...any) {
	if quiet {
		return nil
	}
	return func(f string, a ...any) { fmt.Fprintf(os.Stderr, "[yaklite] "+f+"\n", a...) }
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var opt ScanOptions
	quiet := scanFlags(fs, &opt)
	out := fs.String("o", "", "write the snapshot as JSON to this file (owner-only permissions)")
	asJSON := fs.Bool("json", false, "print the snapshot as JSON on stdout instead of a table")
	fs.Parse(args)
	if opt.Targets == "" {
		return errors.New("-t is required")
	}
	opt.Progress = progress(*quiet)
	snap, err := Scan(ctx, opt)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := SaveSnapshot(*out, snap); err != nil {
			return err
		}
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	printSnapshot(snap)
	return nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print changes as JSON lines")
	af := alertFlags(fs)
	fs.Parse(args)
	if fs.NArg() != 2 {
		return errors.New("usage: yaklite diff OLD.json NEW.json")
	}
	a, err := LoadSnapshot(fs.Arg(0))
	if err != nil {
		return err
	}
	b, err := LoadSnapshot(fs.Arg(1))
	if err != nil {
		return err
	}
	ac, err := af.load()
	if err != nil {
		return err
	}
	changes := filterSeverity(Annotate(Diff(a, b, DiffOptions{GoneAfter: 1, TLSWarn: ac.tlsWarn}, b.Finished), ac.inv), ac.minSev)
	emit(os.Stdout, changes, *asJSON)
	if len(changes) > 0 {
		os.Exit(3) // like diff(1): non-zero when something changed
	}
	return nil
}

func emit(w io.Writer, changes []Change, asJSON bool) {
	for _, c := range changes {
		if asJSON {
			b, _ := json.Marshal(c)
			fmt.Fprintln(w, string(b))
		} else {
			fmt.Fprintf(w, "%s  %s\n", c.Time.Local().Format("2006-01-02 15:04"), c)
		}
	}
}

func defaultStateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "yaklite")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".yaklite"
	}
	return filepath.Join(home, ".local", "state", "yaklite")
}

func cmdWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	var opt ScanOptions
	quiet := scanFlags(fs, &opt)
	wf := addWatchFlags(fs, time.Hour)
	withChecks := fs.Bool("checks", false, "also run the other checks (yaklite check --list): router UPnP, DNS, connections, ... ; -t must be your own network")
	fs.Parse(args)
	if opt.Targets == "" {
		return errors.New("-t is required")
	}
	opt.Progress = progress(*quiet)
	scan := func(ctx context.Context) (*Snapshot, error) { return Scan(ctx, opt) }
	if *withChecks {
		scan = func(ctx context.Context) (*Snapshot, error) {
			snap, err := Scan(ctx, opt)
			if err != nil {
				return nil, err
			}
			env := &checkEnv{trusted: true, snap: snap, stateDir: *wf.stateDir, prog: func(string, ...any) {}, opts: defaultCheckOptions(), inv: invFor(wf)}
			env.net, _ = currentNetwork(ctx)
			runChecks(ctx, env, nil)
			return snap, nil
		}
	}
	w, err := wf.build(scan, opt.Progress, opt.Targets+"_"+opt.Ports)
	if err != nil {
		return err
	}
	return runWatch(ctx, w)
}

type watchFlags struct {
	every                                   *time.Duration
	stateDir, name, webhook, format, listen *string
	goneAfter                               *int
	once, asJSON                            *bool
	af                                      *alertFlagValues
}

func addWatchFlags(fs *flag.FlagSet, every time.Duration) *watchFlags {
	return &watchFlags{
		every:     fs.Duration("every", every, "time between scans"),
		stateDir:  fs.String("state", defaultStateDir(), "where the last snapshot and the change log are kept (created 0700)"),
		name:      fs.String("name", "", "name for this watch, so several can share one state dir (default: derived from the targets)"),
		webhook:   fs.String("webhook", "", "send changes here: ntfy, Slack, Discord, Telegram, Gotify, Pushover, Home Assistant or any JSON webhook, or smtps://user@host/you@example.com for email; comma separated for several"),
		format:    fs.String("webhook-format", "auto", "webhook body: "+strings.Join(webhookFormats, ", ")+" (auto picks from the URL)"),
		af:        alertFlags(fs),
		goneAfter: fs.Int("gone-after", 2, "report a host or name as gone only after this many scans in a row without it"),
		once:      fs.Bool("once", false, "run one scan, report changes and exit; exit code 3 means something changed (for cron or systemd timers)"),
		asJSON:    fs.Bool("json", false, "print changes as JSON lines"),
		listen:    fs.String("listen", "", "also serve the dashboard and /metrics on this address, e.g. 127.0.0.1:9842"),
	}
}

func (wf *watchFlags) build(scan scanFunc, progress func(string, ...any), defaultName string) (watchRun, error) {
	ac, err := wf.af.load()
	if err != nil {
		return watchRun{}, err
	}
	ac.webhook, ac.webhookFormat = *wf.webhook, *wf.format
	if !contains(webhookFormats, *wf.format) {
		return watchRun{}, fmt.Errorf("unknown --webhook-format %q", *wf.format)
	}
	if err := validateWebhooks(*wf.webhook); err != nil {
		return watchRun{}, err
	}
	name := *wf.name
	if name == "" {
		name = safeName(defaultName)
	}
	return watchRun{
		scan: scan, progress: progress, ac: ac, stateDir: *wf.stateDir, name: name,
		every: *wf.every, once: *wf.once, asJSON: *wf.asJSON, listen: *wf.listen, goneAfter: *wf.goneAfter,
	}, nil
}

func cmdOutside(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("outside", flag.ExitOnError)
	domains := fs.String("d", "", "domains you own, comma separated (required unless --ip is given)")
	ips := fs.String("ip", "", "public IPs or ranges you own to port scan, e.g. your home IP or a VPS")
	scanNames := fs.Bool("scan-resolved", false, "also port scan the IPs your names resolve to (only if you own them: they are often a CDN or host)")
	brute := fs.Bool("brute", false, "also guess names with a DNS brute force wordlist (many DNS queries)")
	noCT := fs.Bool("no-ct", false, "skip certificate transparency lookups (crt.sh and certspotter receive the domain name)")
	dns := fs.String("dns", "1.1.1.1,8.8.8.8", "DNS resolvers to use, comma separated")
	maxNames := fs.Int("max-names", 300, "most names to check per run")
	noDomainChecks := fs.Bool("no-domain-checks", false, "skip the email spoofing, expiry, hijackable subdomain, new certificate and look-alike checks")
	lookalikes := fs.Bool("lookalikes", true, "look for typo and look-alike versions of your domains (a few hundred DNS lookups)")
	noRDAP := fs.Bool("no-rdap", false, "skip the registration expiry lookup (rdap.org receives the domain name)")
	noHIBP := fs.Bool("no-hibp", false, "skip the data leak lookup (haveibeenpwned.com receives the domain name)")
	var opt ScanOptions
	fs.StringVar(&opt.Ports, "p", "top", `ports to scan on public IPs: "top", "all" or a list`)
	fs.IntVar(&opt.Concurrency, "c", 100, "concurrent connection attempts")
	fs.DurationVar(&opt.DialTimeout, "dial-timeout", 3*time.Second, "connect timeout per port")
	fs.DurationVar(&opt.ProbeTimeout, "probe-timeout", 5*time.Second, "timeout per probe and certificate read")
	fs.BoolVar(&opt.NoFingerprint, "no-fp", false, "only report open ports on public IPs")
	quiet := fs.Bool("q", false, "quiet: no progress output on stderr")
	scanOnly := fs.Bool("scan", false, "print the current outside view and exit, without comparing or alerting")
	wf := addWatchFlags(fs, 6*time.Hour)
	fs.Parse(args)
	if *domains == "" && *ips == "" {
		return errors.New("give -d DOMAINS and/or --ip ADDRESSES you own")
	}
	var ds []string
	for _, d := range strings.Split(*domains, ",") {
		if d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, "."))); d != "" {
			ds = append(ds, d)
		}
	}
	var servers []string
	for _, s := range strings.Split(*dns, ",") {
		if s = strings.TrimSpace(s); s != "" {
			servers = append(servers, s)
		}
	}
	oo := OutsideOptions{
		Domains: ds, IPs: *ips, ScanNames: *scanNames, Brute: *brute, NoCT: *noCT,
		DNSServers: servers, Scan: opt, MaxNames: *maxNames, ProgressFor: progress(*quiet),
		NoDomainChecks: *noDomainChecks, Lookalikes: *lookalikes, NoRDAP: *noRDAP, NoHIBP: *noHIBP,
	}
	scan := func(ctx context.Context) (*Snapshot, error) { return ScanOutside(ctx, oo) }
	if *scanOnly {
		snap, err := scan(ctx)
		if err != nil {
			return err
		}
		if *wf.asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(snap)
		}
		printSnapshot(snap)
		return nil
	}
	w, err := wf.build(scan, oo.ProgressFor, "outside_"+*domains+"_"+*ips)
	if err != nil {
		return err
	}
	return runWatch(ctx, w)
}

type watchRun struct {
	scan        scanFunc
	progress    func(string, ...any)
	ac          *alertConfig
	stateDir    string
	name        string
	every       time.Duration
	once        bool
	asJSON      bool
	listen      string
	goneAfter   int
	quietErrors bool // only report a failing scan once until it recovers
}

func runWatch(ctx context.Context, w watchRun) error {
	if err := os.MkdirAll(w.stateDir, 0o700); err != nil {
		return err
	}
	snapPath := filepath.Join(w.stateDir, w.name+".snapshot.json")
	logPath := filepath.Join(w.stateDir, w.name+".changes.jsonl")
	if w.listen != "" && !w.once {
		srv, err := startWeb(w.listen, &stateReader{dir: w.stateDir, inv: w.ac.inv})
		if err != nil {
			return err
		}
		defer srv.Close()
	}
	failing := false
	for {
		for _, u := range splitWebhooks(w.ac.webhook) {
			if pollPhoneActions(ctx, u, w.stateDir) && w.name == "connections" {
				kickAuto() // "Check again" pressed on the phone
			}
		}
		w.ac.goneAfter = w.goneAfter
		if err := watchOnce(ctx, w.scan, w.progress, w.ac, snapPath, logPath, w.asJSON); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !w.quietErrors || !failing {
				fmt.Fprintln(os.Stderr, "[yaklite] scan failed:", err)
			}
			failing = true
			if w.once {
				return err
			}
		} else {
			failing = false
		}
		if w.once {
			if lastChangeCount > 0 {
				os.Exit(3) // lets cron or a systemd unit react to changes
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(w.every):
		}
	}
}

// lastChangeCount is the number of changes the most recent watch cycle reported.
var lastChangeCount int

type scanFunc func(ctx context.Context) (*Snapshot, error)

func watchOnce(ctx context.Context, scan scanFunc, progress func(string, ...any), ac *alertConfig, snapPath, logPath string, asJSON bool) error {
	lastChangeCount = 0
	flushHeld(ctx, filepath.Dir(snapPath))
	prev, err := LoadSnapshot(snapPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cur, err := scan(ctx)
	if err != nil {
		return err
	}
	for _, e := range cur.SourceErrors {
		fmt.Fprintln(os.Stderr, "[yaklite] source failed:", e)
	}
	firstRun := prev == nil
	ac.inv.applyRules(cur)
	all := Annotate(Diff(prev, cur, DiffOptions{GoneAfter: ac.goneAfter, TLSWarn: ac.tlsWarn}, cur.Finished), ac.inv)
	if err := SaveSnapshot(snapPath, cur); err != nil {
		return err
	}
	updateHistory(filepath.Dir(snapPath), strings.TrimSuffix(filepath.Base(snapPath), ".snapshot.json"), cur)
	min := ac.minSev
	if firstRun {
		fmt.Fprintf(os.Stderr, "[yaklite] baseline recorded: %d hosts, %d open ports -> %s\n", len(cur.Hosts), cur.OpenPortCount(), snapPath)
		if !asJSON {
			printSnapshot(cur)
		}
		// Everything is "new" on a first run. Without an inventory only risky
		// exposures are worth an alert; with one, report what doesn't match it.
		if ac.inv == nil && sevRank[min] < sevRank[sevHigh] {
			min = sevHigh
		}
	}
	if len(all) > 0 {
		if err := appendChanges(logPath, all); err != nil {
			fmt.Fprintln(os.Stderr, "[yaklite] could not write change log:", err)
		}
	}
	// findings are not "everything is new" noise, so the baseline exception
	// above does not apply to them
	var changes []Change
	for _, c := range all {
		m := min
		if c.Kind == "finding" {
			m = ac.minSev
		}
		if sevRank[c.Severity] >= sevRank[m] {
			changes = append(changes, c)
		}
	}
	changes = dropAcked(changes, cur.Finished)
	if len(changes) == 0 {
		if progress != nil {
			progress("no changes at or above %s (%d hosts, %d open ports)", min, len(cur.Hosts), cur.OpenPortCount())
		}
		return nil
	}
	lastChangeCount = len(changes)
	if firstRun && !asJSON {
		fmt.Fprintln(os.Stdout, "\nFindings in the baseline:")
	}
	emit(os.Stdout, changes, asJSON)
	deliver(ctx, ac, filepath.Dir(snapPath), changes)
	return nil
}

func appendChanges(path string, changes []Change) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	emit(f, changes, true)
	return nil
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory written by yaklite watch")
	listen := fs.String("listen", "127.0.0.1:9842", "address to listen on; anything but loopback needs YAKLITE_WEB_PASSWORD")
	inventory := fs.String("inventory", "", "inventory YAML, to show device names")
	tailscale := fs.Bool("tailscale", false, "also serve on this computer's Tailscale address, to open the dashboard from your phone (a password is created if none is set)")
	accept := fs.Bool("accept-reports", false, "let other computers send their results here (yaklite report / install --report-to); prints the token they need")
	fs.Parse(args)
	r := &stateReader{dir: *stateDir}
	if *accept {
		tok, err := reportToken()
		if err != nil {
			return err
		}
		r.reportToken = tok
		fmt.Fprintf(os.Stderr, "[yaklite] other computers can report here with: yaklite install --report-to http://THIS-COMPUTER:%s --report-token %s\n", portOf(*listen), tok)
	}
	if *inventory != "" {
		inv, err := LoadInventory(*inventory)
		if err != nil {
			return err
		}
		r.inv = inv
	} else {
		r.invFromConfig = true // names set with yaklite name or on the page
	}
	srv, err := startWeb(*listen, r)
	if err != nil {
		return err
	}
	defer srv.Close()
	if *tailscale {
		pw, created, err := ensureWebPassword()
		if err != nil {
			return err
		}
		if created {
			fmt.Fprintf(os.Stderr, "[yaklite] dashboard password (saved in %s): %s\n", webPasswordPath(), pw)
		}
		go func() {
			// Tailscale may come up after login: keep looking
			for ctx.Err() == nil {
				if ts := tailscaleAddr(); ts != "" {
					tsrv, err := startWeb(net.JoinHostPort(ts, portOf(*listen)), r)
					if err == nil {
						<-ctx.Done()
						tsrv.Close()
						return
					}
					fmt.Fprintln(os.Stderr, "[yaklite] tailscale:", err)
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Minute):
				}
			}
		}()
	}
	<-ctx.Done()
	return nil
}

type alertFlagValues struct {
	inventory *string
	minSev    *string
	tlsDays   *int
}

type alertConfig struct {
	inv           *Inventory
	minSev        string
	tlsWarn       time.Duration
	goneAfter     int
	webhook       string
	webhookFormat string
	desktop       string // network name for desktop notifications (auto mode)
}

func alertFlags(fs *flag.FlagSet) *alertFlagValues {
	return &alertFlagValues{
		inventory: fs.String("inventory", "", "YAML file naming your devices and the ports each may expose; alerts then focus on surprises"),
		minSev:    fs.String("min-severity", "low", "only print and send changes at or above this level: info, low, medium, high (the log keeps everything)"),
		tlsDays:   fs.Int("tls-warn-days", 21, "warn this many days before a certificate expires (0 to disable)"),
	}
}

func (f *alertFlagValues) load() (*alertConfig, error) {
	ac := &alertConfig{tlsWarn: time.Duration(*f.tlsDays) * 24 * time.Hour}
	var err error
	if ac.minSev, err = parseSeverity(*f.minSev); err != nil {
		return nil, err
	}
	if *f.inventory != "" {
		if ac.inv, err = LoadInventory(*f.inventory); err != nil {
			return nil, err
		}
	}
	return ac, nil
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return "9842"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// invFor loads the inventory named on the command line, for checks.
func invFor(wf *watchFlags) *Inventory {
	if *wf.af.inventory == "" {
		return nil
	}
	inv, _ := LoadInventory(*wf.af.inventory)
	return inv
}
