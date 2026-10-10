package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yaklang/yaklang/common/fp"
	"github.com/yaklang/yaklang/common/synscan"
	"github.com/yaklang/yaklang/common/synscanx"
	"github.com/yaklang/yaklang/common/utils"
)

// TopPorts covers common services on home and office networks, including
// self-hosted apps, IoT, printers, NAS and remote-access ports.
const TopPorts = "21,22,23,25,53,80,81,88,110,111,135,139,143,161,389,443,445,465,500,515,548,554,587,631,636,873,993,995,1080,1194,1433,1521,1723,1883,1900,2049,2375,2376,3000,3128,3306,3389,3478,4443,5000,5001,5060,5353,5357,5432,5601,5900,5985,6379,6443,7000,7443,8000,8008,8009,8080,8081,8088,8096,8123,8200,8443,8554,8883,8888,9000,9090,9091,9100,9200,9443,10000,11211,27017,32400,51820"

type ScanOptions struct {
	Targets       string
	Ports         string
	Exclude       string
	SYN           bool
	Concurrency   int
	DialTimeout   time.Duration
	ProbeTimeout  time.Duration
	NoFingerprint bool
	NoTLS         bool
	// NoARP turns off finding devices on directly attached networks by their
	// MAC address (which also finds devices with no open ports).
	NoARP    bool
	UDP      bool   // also probe common UDP services on live hosts
	UDPPorts string // default DefaultUDPPorts
	NoNames  bool   // skip reverse DNS lookups for device names
	Progress func(format string, args ...any)
}

func resolvePorts(spec string) string {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "", "top":
		return TopPorts
	case "all":
		return "1-65535"
	}
	return spec
}

type hostPort struct {
	host string
	port int
}

// discoverConnect finds open TCP ports with plain connect() calls. It needs no
// privileges and is what most home users will run.
func discoverConnect(ctx context.Context, hosts []string, ports []int, opt ScanOptions) []hostPort {
	var (
		mu   sync.Mutex
		open []hostPort
	)
	swg := utils.NewSizedWaitGroup(opt.Concurrency)
	dialer := net.Dialer{Timeout: opt.DialTimeout}
	for _, h := range hosts {
		for _, p := range ports {
			if ctx.Err() != nil {
				break
			}
			h, p := h, p
			swg.Add()
			go func() {
				defer swg.Done()
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(h, strconv.Itoa(p)))
				if err != nil {
					return
				}
				conn.Close()
				mu.Lock()
				open = append(open, hostPort{h, p})
				mu.Unlock()
			}()
		}
	}
	swg.Wait()
	return open
}

// discoverSYN uses yaklang's SYN scanner. It is much faster across a subnet
// but needs root or CAP_NET_RAW.
func discoverSYN(ctx context.Context, opt ScanOptions, ports string) ([]hostPort, error) {
	var (
		mu   sync.Mutex
		open []hostPort
	)
	ch, err := synscanx.Scan(ctx, opt.Targets, ports,
		synscanx.WithWaiting(5),
		synscanx.WithExcludeHosts(opt.Exclude),
		synscanx.WithCallback(func(r *synscan.SynScanResult) {
			mu.Lock()
			open = append(open, hostPort{r.Host, r.Port})
			mu.Unlock()
		}))
	if err != nil {
		return nil, err
	}
	for range ch {
	}
	return open, nil
}

func newMatcher(opt ScanOptions) (*fp.Matcher, error) {
	webRules, _ := fp.GetDefaultWebFingerprintRules()
	cfg := fp.NewConfig(
		fp.WithActiveMode(true),
		fp.WithProbeTimeout(opt.ProbeTimeout),
		fp.WithWebFingerprintUseAllRules(true),
		fp.WithWebFingerprintRule(webRules),
		fp.WithForceEnableAllFingerprint(true),
		fp.WithTransportProtos(fp.TCP),
	)
	return fp.NewDefaultFingerprintMatcher(cfg)
}

func toService(port int, r *fp.MatchResult) *Service {
	s := &Service{Port: port, Proto: "tcp"}
	if r == nil || r.Fingerprint == nil {
		return s
	}
	f := r.Fingerprint
	s.Service = strings.Trim(f.ServiceName, "/")
	s.Product = strings.TrimSpace(f.ProductVerbose)
	s.Version = strings.TrimSpace(f.Version)
	s.CPEs = r.GetCPEs()
	banner := f.Banner
	if len(banner) > 200 {
		banner = banner[:200]
	}
	s.Banner = strings.ToValidUTF8(banner, "?")
	// the fingerprinter falls back to the IANA port name when nothing matched;
	// only call it verified when a probe or rule actually said something
	s.Verified = s.Product != "" || s.Version != "" || len(s.CPEs) > 0 || f.Raw != ""
	return s
}

// Scan discovers open ports and fingerprints them.
func Scan(ctx context.Context, opt ScanOptions) (*Snapshot, error) {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 200
	}
	if opt.DialTimeout <= 0 {
		opt.DialTimeout = 1500 * time.Millisecond
	}
	if opt.ProbeTimeout <= 0 {
		opt.ProbeTimeout = 5 * time.Second
	}
	if opt.Progress == nil {
		opt.Progress = func(string, ...any) {}
	}
	ports := resolvePorts(opt.Ports)
	method := "connect"
	if opt.SYN {
		method = "syn"
	}
	snap := NewSnapshot(opt.Targets, ports, method)
	snap.Started = time.Now().UTC()

	hosts := utils.ParseStringToHosts(opt.Targets)
	if opt.Exclude != "" {
		ex := map[string]bool{}
		for _, h := range utils.ParseStringToHosts(opt.Exclude) {
			ex[h] = true
		}
		kept := hosts[:0]
		for _, h := range hosts {
			if !ex[h] {
				kept = append(kept, h)
			}
		}
		hosts = kept
	}
	portList := utils.ParseStringToPorts(ports)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no targets parsed from %q", opt.Targets)
	}
	if len(portList) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", ports)
	}
	opt.Progress("scanning %d hosts x %d ports (%s)", len(hosts), len(portList), method)

	var open []hostPort
	var err error
	if opt.SYN {
		open, err = discoverSYN(ctx, opt, ports)
		if err != nil {
			return nil, fmt.Errorf("syn scan failed (needs root or CAP_NET_RAW; drop --syn to use connect scan): %w", err)
		}
	} else {
		open = discoverConnect(ctx, hosts, portList, opt)
	}
	opt.Progress("%d open ports found", len(open))

	if opt.NoFingerprint {
		for _, hp := range open {
			snap.Add(hp.host, &Service{Port: hp.port, Proto: "tcp"})
		}
	} else {
		matcher, err := newMatcher(opt)
		if err != nil {
			return nil, err
		}
		var mu sync.Mutex
		swg := utils.NewSizedWaitGroup(min(opt.Concurrency, 50))
		for _, hp := range open {
			hp := hp
			swg.Add()
			go func() {
				defer swg.Done()
				r, err := matcher.MatchWithContext(ctx, hp.host, hp.port)
				if err != nil {
					r = nil
				}
				svc := toService(hp.port, r)
				if !opt.NoTLS && wantsTLSCheck(svc) {
					svc.TLS = inspectTLS(ctx, hp.host, hp.port, opt.ProbeTimeout)
				}
				mu.Lock()
				snap.Add(hp.host, svc)
				mu.Unlock()
			}()
		}
		swg.Wait()
	}

	if !opt.NoARP {
		if devices := discoverNeighbours(ctx, hosts, !opt.NoNames); len(devices) > 0 {
			snap.Devices = devices
			snap.Gateway = defaultGateway()
			for h := range devices {
				if _, ok := snap.Hosts[h]; !ok {
					snap.Hosts[h] = []*Service{}
				}
			}
			opt.Progress("%d devices found on the local network", len(devices))
		}
	}

	if opt.UDP && len(snap.Hosts) > 0 {
		udpPorts := utils.ParseStringToPorts(opt.UDPPorts)
		if opt.UDPPorts == "" {
			udpPorts = utils.ParseStringToPorts(DefaultUDPPorts)
		}
		alive := make([]string, 0, len(snap.Hosts))
		for h := range snap.Hosts {
			alive = append(alive, h)
		}
		opt.Progress("probing %d UDP ports on %d live hosts", len(udpPorts), len(alive))
		var mu sync.Mutex
		err := probeUDP(ctx, opt, alive, udpPorts, func(h string, svc *Service) {
			mu.Lock()
			snap.Add(h, svc)
			mu.Unlock()
		})
		if err != nil {
			return nil, err
		}
	}

	snap.Finished = time.Now().UTC()
	snap.Sort()
	return snap, ctx.Err()
}

func printSnapshot(s *Snapshot) {
	fmt.Fprintf(os.Stdout, "%d hosts, %d open ports (%s scan, %s)\n", len(s.Hosts), s.OpenPortCount(), s.Method, s.Finished.Sub(s.Started).Round(time.Millisecond))
	if len(s.Devices) > 0 {
		fmt.Fprintf(os.Stdout, "%d devices found by MAC address on the local network\n", len(s.Devices))
	}
	hosts := make([]string, 0, len(s.Hosts))
	for h := range s.Hosts {
		hosts = append(hosts, h)
	}
	sortHosts(hosts)
	for _, h := range hosts {
		line := h
		if d := s.Devices[h]; d != nil {
			line += "  " + d.MAC
			if desc := d.describe(); desc != "" {
				line += "  " + desc
			}
		}
		if h == s.Gateway {
			line += "  [gateway]"
		}
		fmt.Fprintf(os.Stdout, "\n%s\n", line)
		if len(s.Hosts[h]) == 0 {
			fmt.Fprintln(os.Stdout, "  (no open ports)")
		}
		for _, svc := range s.Hosts[h] {
			mark := ""
			if !svc.Verified {
				mark = " (unconfirmed)"
			}
			if svc.TLS != nil {
				mark += fmt.Sprintf("  [cert %s, %s", svc.TLS.Version, daysLeft(svc.TLS, time.Now()))
				if svc.TLS.SelfSigned {
					mark += ", self-signed"
				}
				mark += "]"
			}
			fmt.Fprintf(os.Stdout, "  %-10s %s%s\n", svc.Key(), svc.Label(), mark)
		}
	}
}

func sortHosts(hosts []string) {
	key := func(h string) string {
		ip := net.ParseIP(h)
		if ip4 := ip.To4(); ip4 != nil {
			return fmt.Sprintf("%03d.%03d.%03d.%03d", ip4[0], ip4[1], ip4[2], ip4[3])
		}
		return h
	}
	for i := 1; i < len(hosts); i++ {
		for j := i; j > 0 && key(hosts[j]) < key(hosts[j-1]); j-- {
			hosts[j], hosts[j-1] = hosts[j-1], hosts[j]
		}
	}
}
