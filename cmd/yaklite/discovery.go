package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/yaklang/yaklang/common/fp"
	"github.com/yaklang/yaklang/common/utils/netutil"
)

// Device is what yaklite knows about a host beyond its open ports.
type Device struct {
	MAC        string `json:"mac,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Randomized bool   `json:"randomized_mac,omitempty"` // locally administered MAC, as phones use for privacy
	Hostname   string `json:"hostname,omitempty"`       // from reverse DNS, usually the router's DHCP name
	Self       bool   `json:"self,omitempty"`           // the machine running yaklite
	Kind       string `json:"kind,omitempty"`           // from your own rules in the inventory, e.g. "camera"
}

func (d *Device) describe() string {
	if d == nil {
		return ""
	}
	var parts []string
	if d.Kind != "" {
		parts = append(parts, d.Kind)
	}
	if d.Hostname != "" {
		parts = append(parts, d.Hostname)
	}
	switch {
	case d.Randomized:
		parts = append(parts, "private MAC")
	case d.Vendor != "":
		parts = append(parts, d.Vendor)
	}
	if d.Self {
		parts = append(parts, "this machine")
	}
	return strings.Join(parts, ", ")
}

// ---- MAC vendors ----

//go:embed data/oui.txt.gz
var ouiGz []byte

var (
	ouiOnce sync.Once
	ouiMap  map[string]string
)

func macVendor(mac string) (vendor string, randomized bool) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 3 {
		return "", false
	}
	if hw[0]&0x02 != 0 {
		return "", true
	}
	ouiOnce.Do(func() {
		ouiMap = map[string]string{}
		zr, err := gzip.NewReader(bytes.NewReader(ouiGz))
		if err != nil {
			return
		}
		sc := bufio.NewScanner(zr)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), "\t"); ok {
				ouiMap[k] = v
			}
		}
	})
	return ouiMap[strings.ToUpper(strings.ReplaceAll(hw[:3].String(), ":", ""))], false
}

func normalizeMAC(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "-", ":")
	// macOS prints 0:1a:2b:3:4:5; pad each octet
	parts := strings.Split(s, ":")
	if len(parts) == 6 {
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		s = strings.Join(parts, ":")
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	if bytes.Equal(hw, make([]byte, 6)) || bytes.Equal(hw, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		return ""
	}
	return hw.String()
}

// ---- neighbour (ARP) table ----

// parseProcNetARP reads Linux /proc/net/arp; only complete entries count.
func parseProcNetARP(data string) map[string]string {
	out := map[string]string{}
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 {
			continue
		}
		if f[2] == "0x0" { // incomplete
			continue
		}
		if mac := normalizeMAC(f[3]); mac != "" {
			out[f[0]] = mac
		}
	}
	return out
}

// parseArpA reads `arp -an` (macOS, BSD) and `arp -a` (Windows) output.
func parseArpA(data string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var ip, mac string
		if len(f) >= 4 && strings.HasPrefix(f[1], "(") && f[2] == "at" { // ? (192.168.1.1) at aa:bb:... on en0
			ip, mac = strings.Trim(f[1], "()"), f[3]
		} else if net.ParseIP(f[0]) != nil { // 192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic
			ip, mac = f[0], f[1]
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		if m := normalizeMAC(mac); m != "" {
			out[ip] = m
		}
	}
	return out
}

func readNeighbours() map[string]string {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/net/arp")
		if err != nil {
			return nil
		}
		return parseProcNetARP(string(data))
	}
	args := []string{"-an"}
	if runtime.GOOS == "windows" {
		args = []string{"-a"}
	}
	data, err := exec.Command("arp", args...).Output()
	if err != nil {
		return nil
	}
	return parseArpA(string(data))
}

// localNets returns the IPv4 networks this machine is directly attached to,
// and this machine's own address and MAC on each.
type localNet struct {
	net *net.IPNet
	ip  net.IP
	mac string
}

func localNets() []localNet {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []localNet
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, _ := ipn.Mask.Size()
			if ones >= 31 { // point-to-point links have no neighbours to find
				continue
			}
			out = append(out, localNet{
				net: &net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask},
				ip:  ipn.IP.To4(), mac: ifc.HardwareAddr.String(),
			})
		}
	}
	return out
}

// defaultGateway asks the OS routing table; no packet is sent.
func defaultGateway() string {
	_, gw, _, err := netutil.Route(2*time.Second, "8.8.8.8")
	if err != nil || gw == nil || gw.IsUnspecified() {
		return ""
	}
	return gw.String()
}

// discoverNeighbours finds devices on directly attached networks, including
// ones with no open ports. It sends one tiny UDP datagram to each address
// (to the discard port), which makes the OS resolve its MAC address, then
// reads the OS neighbour table. No privileges are needed.
func discoverNeighbours(ctx context.Context, hosts []string, lookupNames bool) map[string]*Device {
	nets := localNets()
	if len(nets) == 0 {
		return nil
	}
	self := map[string]string{}
	var local []string
	for _, h := range hosts {
		ip := net.ParseIP(h).To4()
		if ip == nil {
			continue
		}
		for _, ln := range nets {
			if ln.ip.Equal(ip) {
				self[h] = ln.mac
				break
			}
			if ln.net.Contains(ip) && !ip.Equal(ln.net.IP) && !isBroadcast(ip, ln.net) {
				local = append(local, h)
				break
			}
		}
	}
	if len(local) == 0 && len(self) == 0 {
		return nil
	}

	poke := func(list []string) {
		swg := make(chan struct{}, 64)
		var wg sync.WaitGroup
		for _, h := range list {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			swg <- struct{}{}
			go func(h string) {
				defer wg.Done()
				defer func() { <-swg }()
				c, err := net.DialTimeout("udp4", net.JoinHostPort(h, "9"), time.Second)
				if err != nil {
					return
				}
				c.Write([]byte{0})
				c.Close()
			}(h)
		}
		wg.Wait()
	}
	sleep := func(d time.Duration) {
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
	}

	poke(local)
	sleep(1500 * time.Millisecond)
	table := readNeighbours()
	// a second pass catches devices that were asleep or slow to answer
	var missing []string
	for _, h := range local {
		if table[h] == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		poke(missing)
		sleep(2 * time.Second)
		for k, v := range readNeighbours() {
			table[k] = v
		}
	}

	out := map[string]*Device{}
	for _, h := range local {
		if mac := table[h]; mac != "" {
			d := &Device{MAC: mac}
			d.Vendor, d.Randomized = macVendor(mac)
			out[h] = d
		}
	}
	for h, mac := range self {
		d := &Device{MAC: normalizeMAC(mac), Self: true}
		d.Vendor, d.Randomized = macVendor(d.MAC)
		if name, err := os.Hostname(); err == nil {
			d.Hostname = name
		}
		out[h] = d
	}
	if lookupNames {
		reverseNames(ctx, out)
		announcedNames(ctx, out)
	}
	return out
}

func isBroadcast(ip net.IP, n *net.IPNet) bool {
	b := make(net.IP, 4)
	for i := range b {
		b[i] = n.IP.To4()[i] | ^n.Mask[i]
	}
	return ip.Equal(b)
}

// reverseNames fills Hostname from reverse DNS. Home routers answer these
// with the names devices gave over DHCP.
func reverseNames(ctx context.Context, devices map[string]*Device) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 16)
	for h, d := range devices {
		if d.Hostname != "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string, d *Device) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(cctx, h)
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			d.Hostname = strings.TrimSuffix(names[0], ".")
			mu.Unlock()
		}(h, d)
	}
	wg.Wait()
}

// ---- UDP services ----

// DefaultUDPPorts are UDP services worth knowing about on a LAN. A port is
// only reported when the service answers a probe.
const DefaultUDPPorts = "53,69,123,137,161,500,623,1900,3478,5060,5353,5683,10001,11211"

var udpServiceNames = map[int]string{
	53: "dns", 69: "tftp", 123: "ntp", 137: "netbios-ns", 161: "snmp", 500: "ike (IPsec VPN)", 623: "ipmi",
	1900: "ssdp (UPnP)", 3478: "stun", 5060: "sip", 5353: "mdns", 5683: "coap", 10001: "ubiquiti-discovery", 11211: "memcached",
}

// probeUDP asks the fingerprinter's UDP probes about each port on each host.
// Silence is not reported: UDP has no handshake, so only an answer proves a
// service is there.
func probeUDP(ctx context.Context, opt ScanOptions, hosts []string, ports []int, add func(host string, svc *Service)) error {
	matcher, err := newMatcher(opt)
	if err != nil {
		return err
	}
	timeout := opt.ProbeTimeout
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	sem := make(chan struct{}, min(opt.Concurrency, 64))
	var wg sync.WaitGroup
	for _, h := range hosts {
		for _, p := range ports {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(h string, p int) {
				defer wg.Done()
				defer func() { <-sem }()
				// passing an option makes the matcher use a private copy of its
				// config, so the UDP switch does not leak into TCP matching
				r, err := matcher.MatchWithContext(ctx, h, p<<12, fp.WithProbeTimeout(timeout))
				if err != nil || r == nil || r.State != fp.OPEN {
					return
				}
				svc := toService(p, r)
				svc.Proto = "udp"
				svc.Verified = true // it answered
				if svc.Service == "" || svc.Service == "udp" {
					svc.Service = udpServiceNames[p]
				}
				add(h, svc)
			}(h, p)
		}
	}
	wg.Wait()
	return nil
}
