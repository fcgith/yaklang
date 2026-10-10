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

const usage = `yaklite: LAN inventory and change monitoring (built from yaklang)

Usage:
  yaklite scan  -t TARGETS [-p PORTS] [-o snapshot.json] [--syn]
  yaklite watch -t TARGETS [-p PORTS] [--every 1h] [--state DIR] [--webhook URL] [--once]
  yaklite diff  OLD.json NEW.json
  yaklite serve [--state DIR] [--listen 127.0.0.1:9842]   dashboard + Prometheus metrics

TARGETS  IPs, CIDRs, ranges or hostnames, comma separated (192.168.1.0/24,10.0.0.5)
PORTS    "top" (default, ~80 common LAN ports), "all", or a list like 22,80,8000-8100

Only scan networks you own or are authorised to test.
`

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
	every := fs.Duration("every", time.Hour, "time between scans")
	stateDir := fs.String("state", defaultStateDir(), "where the last snapshot and the change log are kept (created 0700)")
	name := fs.String("name", "", "name for this watch, so several networks can share one state dir (default: derived from -t)")
	webhook := fs.String("webhook", "", "POST changes to this URL (Slack, Mattermost, Discord, Telegram, Gotify, ntfy or plain JSON)")
	webhookFormat := fs.String("webhook-format", "auto", "webhook body: "+strings.Join(webhookFormats, ", ")+" (auto picks from the URL)")
	af := alertFlags(fs)
	goneAfter := fs.Int("gone-after", 2, "report a host as gone only after this many scans in a row without it")
	once := fs.Bool("once", false, "run one scan, report changes and exit; exit code 3 means something changed (for cron or systemd timers)")
	asJSON := fs.Bool("json", false, "print changes as JSON lines")
	listen := fs.String("listen", "", "also serve the dashboard and /metrics on this address, e.g. 127.0.0.1:9842")
	fs.Parse(args)
	if opt.Targets == "" {
		return errors.New("-t is required")
	}
	opt.Progress = progress(*quiet)
	ac, err := af.load()
	if err != nil {
		return err
	}
	ac.webhook, ac.webhookFormat = *webhook, *webhookFormat
	if !contains(webhookFormats, *webhookFormat) {
		return fmt.Errorf("unknown --webhook-format %q", *webhookFormat)
	}
	if *webhook != "" && !strings.HasPrefix(*webhook, "https://") && !strings.HasPrefix(*webhook, "http://127.0.0.1") && !strings.HasPrefix(*webhook, "http://localhost") {
		return errors.New("--webhook must use https:// (plain http is only allowed to localhost)")
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	if *name == "" {
		*name = safeName(opt.Targets + "_" + opt.Ports)
	}
	snapPath := filepath.Join(*stateDir, *name+".snapshot.json")
	logPath := filepath.Join(*stateDir, *name+".changes.jsonl")
	if *listen != "" && !*once {
		srv, err := startWeb(*listen, &stateReader{dir: *stateDir, inv: ac.inv})
		if err != nil {
			return err
		}
		defer srv.Close()
	}

	for {
		ac.goneAfter = *goneAfter
		if err := watchOnce(ctx, opt, ac, snapPath, logPath, *asJSON); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "[yaklite] scan failed:", err)
			if *once {
				return err
			}
		}
		if *once {
			if lastChangeCount > 0 {
				os.Exit(3) // lets cron or a systemd unit react to changes
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
	}
}

// lastChangeCount is the number of changes the most recent watch cycle reported.
var lastChangeCount int

func watchOnce(ctx context.Context, opt ScanOptions, ac *alertConfig, snapPath, logPath string, asJSON bool) error {
	lastChangeCount = 0
	prev, err := LoadSnapshot(snapPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cur, err := Scan(ctx, opt)
	if err != nil {
		return err
	}
	firstRun := prev == nil
	all := Annotate(Diff(prev, cur, DiffOptions{GoneAfter: ac.goneAfter, TLSWarn: ac.tlsWarn}, cur.Finished), ac.inv)
	if err := SaveSnapshot(snapPath, cur); err != nil {
		return err
	}
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
	changes := filterSeverity(all, min)
	if len(changes) == 0 {
		if opt.Progress != nil {
			opt.Progress("no changes at or above %s (%d hosts, %d open ports)", min, len(cur.Hosts), cur.OpenPortCount())
		}
		return nil
	}
	lastChangeCount = len(changes)
	if firstRun && !asJSON {
		fmt.Fprintln(os.Stdout, "\nFindings in the baseline:")
	}
	emit(os.Stdout, changes, asJSON)
	if ac.webhook != "" {
		if err := postWebhook(ctx, ac.webhook, ac.webhookFormat, changes); err != nil {
			fmt.Fprintln(os.Stderr, "[yaklite] webhook failed:", err)
		}
	}
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
	fs.Parse(args)
	r := &stateReader{dir: *stateDir}
	if *inventory != "" {
		inv, err := LoadInventory(*inventory)
		if err != nil {
			return err
		}
		r.inv = inv
	}
	srv, err := startWeb(*listen, r)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return srv.Close()
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
