package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPv6 devices get public addresses with no NAT in front of them, so the
// router's IPv6 firewall is the only thing between them and the internet.
// This check lists devices with public IPv6 addresses from the neighbour
// table and looks for risky services open on them.

func init() {
	registerCheck(&check{name: "ipv6", about: "devices with public IPv6 addresses and risky services open on them", trustedOnly: true, run: ipv6Check})
}

func ipv6Neighbours(ctx context.Context) map[string]string {
	switch runtime.GOOS {
	case "linux":
		return parseIPNeigh6(cmdOut(ctx, "ip", "-6", "neigh"))
	case "darwin":
		return parseNDP(cmdOut(ctx, "ndp", "-an"))
	}
	return nil
}

func globalV6(s string) net.IP {
	ip := net.ParseIP(strings.SplitN(s, "%", 2)[0])
	if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return nil
	}
	return ip
}

func parseIPNeigh6(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || globalV6(f[0]) == nil {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				if m := normalizeMAC(f[i+1]); m != "" {
					res[globalV6(f[0]).String()] = m
				}
			}
		}
	}
	return res
}

func parseNDP(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || globalV6(f[0]) == nil {
			continue
		}
		if m := normalizeMAC(f[1]); m != "" {
			res[globalV6(f[0]).String()] = m
		}
	}
	return res
}

func ipv6Check(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	neigh := ipv6Neighbours(ctx)
	if len(neigh) == 0 {
		return nil, nil
	}
	byMAC := map[string]string{} // MAC -> IPv4 host from the scan
	for h, d := range env.snap.Devices {
		if d != nil && d.MAC != "" {
			byMAC[d.MAC] = h
		}
	}
	ports := []int{}
	for p := range riskyPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	type hit struct {
		ip, who string
		port    int
	}
	var mu sync.Mutex
	var hits []hit
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for ip, mac := range neigh {
		who := ip
		if h := byMAC[mac]; h != "" {
			who = h
			if desc := env.snap.Devices[h].describe(); desc != "" {
				who += " (" + desc + ")"
			}
		}
		for _, p := range ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip, who string, p int) {
				defer wg.Done()
				defer func() { <-sem }()
				d := net.Dialer{Timeout: time.Second}
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
				if err != nil {
					return
				}
				c.Close()
				mu.Lock()
				hits = append(hits, hit{ip, who, p})
				mu.Unlock()
			}(ip, who, p)
		}
	}
	wg.Wait()
	var out []*Finding
	for _, h := range hits {
		out = append(out, &Finding{ID: fmt.Sprintf("ipv6:%s:%d", h.ip, h.port), Severity: sevMedium, Host: h.ip,
			Title:  fmt.Sprintf("%s has %s open on its public IPv6 address %s", h.who, riskyPorts[h.port], h.ip),
			Detail: "IPv6 addresses are not hidden behind the router's NAT; only its IPv6 firewall stops the internet reaching this.",
			Fix:    "Check that the router's IPv6 firewall blocks incoming connections (often called \"IPv6 firewall\" or \"inbound IPv6\"), or turn the service off."})
	}
	return out, nil
}
