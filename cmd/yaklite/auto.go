package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yaklang/yaklang/common/utils/netutil"
	"gopkg.in/yaml.v3"
)

// "auto" mode is for a laptop or desktop that moves between networks. It
// works out which network it is on, keys its state by the router's MAC
// address, and treats networks differently depending on whether you said
// they are yours:
//
//   - trusted (yours): full monitoring of every device, as `watch` does.
//   - untrusted (cafés, hotels, other people's offices): it does not scan
//     other people's devices. It checks what this machine itself exposes on
//     that network, and watches the neighbour table for someone
//     impersonating the router.

type networkInfo struct {
	Iface   string
	CIDR    string // the network that is scanned (at most a /24 around this machine)
	Gateway string
	GwMAC   string
	SelfIP  string
}

// ID names the network by its router's MAC, which survives DHCP and is
// unique per network in practice.
func (n *networkInfo) ID() string {
	if n.GwMAC != "" {
		return "net-" + strings.ReplaceAll(n.GwMAC, ":", "")
	}
	return "net-" + safeName(n.CIDR+"_"+n.Gateway)
}

func currentNetwork(ctx context.Context) (*networkInfo, error) {
	iface, gw, src, err := netutil.Route(2*time.Second, "8.8.8.8")
	if err != nil || src == nil || src.To4() == nil {
		return nil, errors.New("no IPv4 network with a default route")
	}
	n := &networkInfo{SelfIP: src.String()}
	if iface != nil {
		n.Iface = iface.Name
	}
	if gw != nil && !gw.IsUnspecified() {
		n.Gateway = gw.String()
	}
	for _, ln := range localNets() {
		if ln.ip.Equal(src.To4()) {
			ipn := ln.net
			if ones, _ := ipn.Mask.Size(); ones < 24 {
				// big networks: only the /24 this machine is in
				ipn = &net.IPNet{IP: src.To4().Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
			}
			n.CIDR = ipn.String()
			break
		}
	}
	if n.CIDR == "" {
		return nil, fmt.Errorf("could not find the network for %s", src)
	}
	if n.Gateway != "" {
		if devs := discoverNeighbours(ctx, []string{n.Gateway}, false); devs[n.Gateway] != nil {
			n.GwMAC = devs[n.Gateway].MAC
		}
	}
	return n, nil
}

// ---- trusted networks ----

type knownNetwork struct {
	Name    string `yaml:"name"`
	CIDR    string `yaml:"cidr"`
	Gateway string `yaml:"gateway"`
	Trusted bool   `yaml:"trusted"`
	Seen    string `yaml:"first_seen,omitempty"`
}

type networksFile struct {
	Networks map[string]*knownNetwork `yaml:"networks"`
}

func configDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "yaklite")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "yaklite")
}

func loadNetworks() (*networksFile, string) {
	p := filepath.Join(configDir(), "networks.yaml")
	nf := &networksFile{Networks: map[string]*knownNetwork{}}
	if data, err := os.ReadFile(p); err == nil {
		yaml.Unmarshal(data, nf)
		if nf.Networks == nil {
			nf.Networks = map[string]*knownNetwork{}
		}
	}
	return nf, p
}

func (nf *networksFile) save(p string) error {
	data, err := yaml.Marshal(nf)
	if err != nil {
		return err
	}
	header := "# Networks yaklite has seen. trusted: true means \"this is mine, monitor every device\".\n"
	return writeFilePrivate(p, append([]byte(header), data...))
}

// ---- desktop notifications ----

// notifyDesktop shows a system notification. It never goes through a shell.
func notifyDesktop(title, body string) {
	switch runtime.GOOS {
	case "darwin":
		esc := func(s string) string {
			s = strings.ReplaceAll(s, `\`, `\\`)
			return strings.ReplaceAll(s, `"`, `\"`)
		}
		script := fmt.Sprintf(`display notification "%s" with title "%s"`, esc(body), esc(title))
		exec.Command("osascript", "-e", script).Run()
	case "linux":
		if p, err := exec.LookPath("notify-send"); err == nil {
			exec.Command(p, "--app-name=yaklite", title, body).Run()
		}
	}
}

func notifyChanges(network string, changes []Change) {
	if len(changes) == 0 {
		return
	}
	title := fmt.Sprintf("yaklite: %d alert(s) on %s", len(changes), network)
	var lines []string
	for i, c := range changes {
		if i == 3 {
			lines = append(lines, fmt.Sprintf("...and %d more", len(changes)-3))
			break
		}
		lines = append(lines, strings.Join(strings.Fields(c.String()), " "))
	}
	notifyDesktop(title, strings.Join(lines, "\n"))
}

// ---- the auto command ----

type autoOptions struct {
	minInterval time.Duration
	udp         bool
	webhook     string
	format      string
	minSev      string
	stateDir    string
	quiet       bool
	asJSON      bool
}

func autoFlags(fs *flag.FlagSet) *autoOptions {
	o := &autoOptions{}
	fs.DurationVar(&o.minInterval, "min-interval", 15*time.Minute, "skip a run when this network was checked more recently than this")
	fs.BoolVar(&o.udp, "udp", true, "probe common UDP services on trusted networks")
	fs.StringVar(&o.webhook, "webhook", "", "also POST alerts to this URL (ntfy, Discord, Telegram, Slack, Gotify or JSON)")
	fs.StringVar(&o.format, "webhook-format", "auto", "webhook body format")
	fs.StringVar(&o.minSev, "min-severity", "medium", "alert at or above this level: info, low, medium, high")
	fs.StringVar(&o.stateDir, "state", defaultStateDir(), "state directory")
	fs.BoolVar(&o.quiet, "q", false, "quiet")
	fs.BoolVar(&o.asJSON, "json", false, "print changes as JSON lines")
	return o
}

func cmdAuto(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("auto", flag.ExitOnError)
	o := autoFlags(fs)
	fs.Parse(args)
	prog := progress(o.quiet)
	if prog == nil {
		prog = func(string, ...any) {}
	}
	if !contains(webhookFormats, o.format) {
		return fmt.Errorf("unknown --webhook-format %q", o.format)
	}
	if o.webhook != "" && !strings.HasPrefix(o.webhook, "https://") {
		return errors.New("--webhook must use https://")
	}

	release, ok := lockState(o.stateDir)
	if !ok {
		prog("another run is in progress, skipping")
		return nil
	}
	defer release()

	n, err := currentNetwork(ctx)
	if err != nil {
		prog("%v; nothing to check", err)
		return nil
	}
	nf, nfPath := loadNetworks()
	known := nf.Networks[n.ID()]
	if known == nil {
		known = &knownNetwork{Name: n.CIDR, CIDR: n.CIDR, Gateway: n.Gateway, Seen: time.Now().Format("2006-01-02")}
		if n.GwMAC != "" {
			if v, _ := macVendor(n.GwMAC); v != "" {
				known.Name = n.CIDR + " (" + v + " router)"
			}
		}
		nf.Networks[n.ID()] = known
		if err := nf.save(nfPath); err != nil {
			prog("could not save %s: %v", nfPath, err)
		}
		notifyDesktop("yaklite: new network "+known.Name,
			"Only checking what this computer exposes here. If this network is yours, run: yaklite trust --name Home")
	}
	prog("network %s (%s), gateway %s %s, trusted=%v", known.Name, n.CIDR, n.Gateway, n.GwMAC, known.Trusted)

	ac := &alertConfig{tlsWarn: 21 * 24 * time.Hour, goneAfter: 3, webhook: o.webhook, webhookFormat: o.format, desktop: known.Name}
	if ac.minSev, err = parseSeverity(o.minSev); err != nil {
		return err
	}
	invPath := filepath.Join(configDir(), "inventory.yaml")
	if _, err := os.Stat(invPath); err == nil {
		if ac.inv, err = LoadInventory(invPath); err != nil {
			prog("ignoring %s: %v", invPath, err)
		}
	}

	var scan scanFunc
	var name string
	if known.Trusted {
		name = n.ID()
		opt := ScanOptions{Targets: n.CIDR, Ports: "top", UDP: o.udp, Progress: prog, Concurrency: 200,
			DialTimeout: 1500 * time.Millisecond, ProbeTimeout: 5 * time.Second}
		scan = func(ctx context.Context) (*Snapshot, error) { return Scan(ctx, opt) }
	} else {
		name = n.ID() + "-self"
		scan = func(ctx context.Context) (*Snapshot, error) { return guardScan(ctx, n, prog) }
	}

	if o.minInterval > 0 {
		if s, err := LoadSnapshot(filepath.Join(o.stateDir, name+".snapshot.json")); err == nil && time.Since(s.Finished) < o.minInterval {
			prog("checked %s ago, skipping (--min-interval)", time.Since(s.Finished).Round(time.Second))
			return nil
		}
	}
	return runWatch(ctx, watchRun{scan: scan, progress: prog, ac: ac, stateDir: o.stateDir, name: name, once: true, asJSON: o.asJSON, goneAfter: 3})
}

// guardScan is the untrusted-network check: this machine's own open ports,
// plus the neighbour table as the OS already has it (nothing is sent to
// other devices) to spot someone answering with the router's MAC.
func guardScan(ctx context.Context, n *networkInfo, prog func(string, ...any)) (*Snapshot, error) {
	opt := ScanOptions{Targets: n.SelfIP, Ports: "top", NoARP: true, Progress: prog, Concurrency: 100,
		DialTimeout: time.Second, ProbeTimeout: 4 * time.Second}
	snap, err := Scan(ctx, opt)
	if err != nil {
		return nil, err
	}
	snap.Method = "self"
	snap.Gateway = n.Gateway
	_, ipn, _ := net.ParseCIDR(n.CIDR)
	for ip, mac := range readNeighbours() {
		if p := net.ParseIP(ip); p != nil && ipn != nil && ipn.Contains(p) {
			d := &Device{MAC: mac}
			d.Vendor, d.Randomized = macVendor(mac)
			snap.Devices[ip] = d
		}
	}
	return snap, nil
}

// lockState stops two runs (a timer and a network change) overlapping.
func lockState(dir string) (func(), bool) {
	os.MkdirAll(dir, 0o700)
	p := filepath.Join(dir, ".auto.lock")
	if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) > 30*time.Minute {
		os.Remove(p) // left behind by a crash
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, false
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()
	return func() { os.Remove(p) }, true
}

func cmdTrust(ctx context.Context, args []string, trusted bool) error {
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	name := fs.String("name", "", "a name for this network, e.g. Home or Office")
	fs.Parse(args)
	n, err := currentNetwork(ctx)
	if err != nil {
		return err
	}
	nf, p := loadNetworks()
	k := nf.Networks[n.ID()]
	if k == nil {
		k = &knownNetwork{Name: n.CIDR, CIDR: n.CIDR, Gateway: n.Gateway, Seen: time.Now().Format("2006-01-02")}
		nf.Networks[n.ID()] = k
	}
	if *name != "" {
		k.Name = *name
	}
	k.Trusted = trusted
	if err := nf.save(p); err != nil {
		return err
	}
	if trusted {
		fmt.Printf("%s (%s, router %s %s) is now trusted: every device on it will be monitored.\n", k.Name, n.CIDR, n.Gateway, n.GwMAC)
		fmt.Println("Only do this for networks you own or are allowed to scan.")
	} else {
		fmt.Printf("%s is no longer trusted: only this computer's own exposure will be checked there.\n", k.Name)
	}
	return nil
}

// cmdName adds or updates a device in the inventory file used by auto.
func cmdName(args []string) error {
	fs := flag.NewFlagSet("name", flag.ExitOnError)
	expect := fs.String("expect", "", "ports this device may expose, e.g. 22,443")
	ignore := fs.Bool("ignore", false, "never alert about this device")
	fs.Parse(args)
	pos := fs.Args()
	if len(pos) > 2 { // flags after the positional arguments
		rest := append([]string(nil), pos[2:]...)
		pos = pos[:2]
		fs.Parse(rest)
		pos = append(pos, fs.Args()...)
	}
	if len(pos) != 2 {
		return errors.New(`usage: yaklite name IP-or-MAC "Name" [--expect 22,443] [--ignore]`)
	}
	key := pos[0]
	if m := normalizeMAC(key); m != "" {
		key = m
	} else if net.ParseIP(key) == nil {
		return fmt.Errorf("%q is not an IP or MAC address", key)
	}
	p := filepath.Join(configDir(), "inventory.yaml")
	inv := &Inventory{Hosts: map[string]*HostEntry{}}
	if _, err := os.Stat(p); err == nil {
		loaded, err := LoadInventory(p)
		if err != nil {
			return err
		}
		inv = loaded
	}
	e := &HostEntry{Name: pos[1], Ignore: *ignore}
	for _, s := range strings.Split(*expect, ",") {
		var port int
		if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &port); err == nil && port > 0 {
			e.Expect = append(e.Expect, port)
		}
	}
	inv.Hosts[key] = e
	data, err := yaml.Marshal(inv)
	if err != nil {
		return err
	}
	if err := writeFilePrivate(p, data); err != nil {
		return err
	}
	fmt.Printf("saved %s as %q in %s\n", key, e.Name, p)
	return nil
}

func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	fs.Parse(args)
	nf, p := loadNetworks()
	n, err := currentNetwork(ctx)
	if err != nil {
		fmt.Println("Not connected to an IPv4 network.")
	} else {
		k := nf.Networks[n.ID()]
		trust := "not seen yet"
		if k != nil {
			trust = map[bool]string{true: "trusted: all devices monitored", false: "untrusted: only this computer is checked"}[k.Trusted]
		}
		fmt.Printf("Network:  %s via %s, router %s %s (%s)\n", n.CIDR, n.Iface, n.Gateway, n.GwMAC, trust)
		for _, suffix := range []string{"", "-self"} {
			if s, err := LoadSnapshot(filepath.Join(*stateDir, n.ID()+suffix+".snapshot.json")); err == nil {
				fmt.Printf("Last run: %s ago, %d hosts, %d open ports\n", time.Since(s.Finished).Round(time.Minute), len(s.Hosts), s.OpenPortCount())
			}
		}
	}
	fmt.Printf("Networks: %d known (%s)\n", len(nf.Networks), p)
	for id, k := range nf.Networks {
		fmt.Printf("  %-22s %-30s trusted=%v\n", id, k.Name, k.Trusted)
	}
	if installedAgent() != "" {
		fmt.Println("Background checks: installed (" + installedAgent() + ")")
	} else {
		fmt.Println("Background checks: not installed (run: yaklite install)")
	}
	return nil
}

func askYesNo(question string, def bool) bool {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return def
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Printf("%s %s ", question, hint)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	}
	return def
}

func askLine(question, def string) string {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return def
	}
	fmt.Printf("%s [%s] ", question, def)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if line = strings.TrimSpace(line); line != "" {
		return line
	}
	return def
}
