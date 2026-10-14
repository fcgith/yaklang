package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The tripwire pretends to be a device worth breaking into: it listens on
// ports such as Telnet, file sharing and remote desktop and never answers.
// Nothing legitimate on a home network connects to it, so any connection
// means someone is looking around inside your network, and you get a high
// alert at once. It only listens on networks you trust.

const defaultTripwirePorts = "23,445,2323,3389,5900,8080,8443,9100"

type tripHit struct {
	Time time.Time
	IP   string
	Port int
}

type tripwireState struct {
	SelfIP string `json:"self_ip"`
	Ports  []int  `json:"ports"`
}

func tripwireStatePath(dir string) string { return filepath.Join(dir, "tripwire.json") }

// dropTripwirePorts removes the tripwire's own ports from a scan of this
// computer, so the hourly scan does not report them as risky open ports.
func dropTripwirePorts(snap *Snapshot, stateDir string) {
	data, err := os.ReadFile(tripwireStatePath(stateDir))
	if err != nil {
		return
	}
	var st tripwireState
	if json.Unmarshal(data, &st) != nil || st.SelfIP == "" {
		return
	}
	h := snap.Hosts[st.SelfIP]
	if h == nil {
		return
	}
	ports := map[int]bool{}
	for _, p := range st.Ports {
		ports[p] = true
	}
	var kept []*Service
	for _, s := range h {
		if s.Proto == "tcp" && ports[s.Port] {
			continue
		}
		kept = append(kept, s)
	}
	if len(kept) == 0 && snap.Devices[st.SelfIP] == nil {
		delete(snap.Hosts, st.SelfIP)
	} else {
		snap.Hosts[st.SelfIP] = kept
	}
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func tripFindings(hits []tripHit, selfIPs map[string]bool, now time.Time) []*Finding {
	byIP := map[string][]tripHit{}
	for _, h := range hits {
		if selfIPs[h.IP] || now.Sub(h.Time) > 24*time.Hour || net.ParseIP(h.IP).IsLoopback() {
			continue
		}
		byIP[h.IP] = append(byIP[h.IP], h)
	}
	neigh := readNeighbours()
	var out []*Finding
	for ip, hs := range byIP {
		ports := map[int]bool{}
		for _, h := range hs {
			ports[h.Port] = true
		}
		var pl []string
		for p := range ports {
			pl = append(pl, strconv.Itoa(p))
		}
		sort.Strings(pl)
		who := ip
		pip := net.ParseIP(ip)
		if mac := neigh[ip]; mac != "" {
			if v, rnd := macVendor(mac); v != "" {
				who += " (" + v + ", " + mac + ")"
			} else if rnd {
				who += " (a device with a private MAC address, " + mac + ")"
			} else {
				who += " (" + mac + ")"
			}
		}
		f := &Finding{ID: "tripwire:" + ip, Severity: sevHigh, Host: ip, Until: hs[len(hs)-1].Time.Add(24 * time.Hour),
			Title:  fmt.Sprintf("Something on your network touched the tripwire: %s connected to port %s", who, strings.Join(pl, ", ")),
			Detail: "Nothing normal connects to the tripwire, so this device is scanning or trying to break into your network.",
			Fix:    "Find the device (yaklite scan shows its name and maker). If you do not know it, unplug it or block it on the router and change your Wi-Fi password. If it is a tool you run on purpose (Fing, a NAS search), yaklite ack this alert."}
		if pip != nil && isPublicAddr(pip) {
			f.Title = fmt.Sprintf("Someone on the internet reached the tripwire: %s connected to port %s", ipWho(pip), strings.Join(pl, ", "))
			f.Detail = "A port on your router forwards to this computer."
			f.Fix = "Remove the port forward or UPnP mapping that points at this computer (yaklite check --only upnp)."
		}
		out = append(out, f)
	}
	return out
}

func cmdTripwire(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tripwire", flag.ExitOnError)
	wf := addWatchFlags(fs, 30*time.Second)
	portList := fs.String("ports", defaultTripwirePorts, "ports to pretend to offer (ports below 1024 may need admin rights on Linux; busy ones are skipped)")
	always := fs.Bool("always", false, "listen on every network (for an always-on box at home)")
	desktop := fs.Bool("notify", false, "show desktop notifications")
	quiet := fs.Bool("q", false, "quiet")
	fs.Parse(args)
	ports, err := parsePorts(*portList)
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return errors.New("no --ports")
	}
	if *wf.name == "" {
		*wf.name = "tripwire"
	}
	prog := progress(*quiet)
	if prog == nil {
		prog = func(string, ...any) {}
	}
	stateDir := *wf.stateDir
	os.MkdirAll(stateDir, 0o700)
	var mu sync.Mutex
	var hits []tripHit
	selfIPs := map[string]bool{}
	for _, ln := range localNets() {
		selfIPs[ln.ip.String()] = true
	}
	ll := &lanListener{always: *always, prog: prog}
	ll.open = func(ip string) (func(), error) {
		var lns []net.Listener
		var bound []int
		for _, p := range ports {
			l, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
			if err != nil && ip != "0.0.0.0" {
				// binding a low port to one address can need root where
				// binding it to all addresses does not (macOS)
				l, err = net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(p)))
			}
			if err != nil {
				prog("tripwire port %d skipped: %v", p, err)
				continue
			}
			lns = append(lns, l)
			bound = append(bound, p)
			go func(l net.Listener, p int) {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					ra, _ := c.RemoteAddr().(*net.TCPAddr)
					la, _ := c.LocalAddr().(*net.TCPAddr)
					c.SetDeadline(time.Now().Add(2 * time.Second))
					buf := make([]byte, 64)
					c.Read(buf) // let a scanner finish its handshake, then hang up
					c.Close()
					if ra == nil || (ip != "0.0.0.0" && la != nil && la.IP.String() != ip) {
						continue // reached us on another network than the trusted one
					}
					mu.Lock()
					hits = append(hits, tripHit{Time: time.Now(), IP: ra.IP.String(), Port: p})
					if len(hits) > 10000 {
						hits = hits[len(hits)-10000:]
					}
					mu.Unlock()
				}
			}(l, p)
		}
		if len(lns) == 0 {
			return nil, errors.New("could not open any tripwire port")
		}
		st, _ := json.Marshal(tripwireState{SelfIP: ip, Ports: bound})
		writeFilePrivate(tripwireStatePath(stateDir), st)
		return func() {
			for _, l := range lns {
				l.Close()
			}
			os.Remove(tripwireStatePath(stateDir))
		}, nil
	}
	ll.onNet = func(n *networkInfo) {
		mu.Lock()
		selfIPs[n.SelfIP] = true
		mu.Unlock()
	}
	go ll.run(ctx)

	scan := func(ctx context.Context) (*Snapshot, error) {
		snap := NewSnapshot("tripwire", "", "tripwire")
		snap.Started = time.Now()
		mu.Lock()
		hs := append([]tripHit(nil), hits...)
		self := map[string]bool{}
		for k := range selfIPs {
			self[k] = true
		}
		mu.Unlock()
		for _, f := range tripFindings(hs, self, time.Now()) {
			f.Check = "tripwire"
			snap.addFinding(f)
		}
		snap.Finished = time.Now()
		return snap, nil
	}
	w, err := wf.build(scan, prog, "tripwire")
	if err != nil {
		return err
	}
	if *desktop {
		w.ac.desktop = "the tripwire"
	}
	return runWatch(ctx, w)
}
