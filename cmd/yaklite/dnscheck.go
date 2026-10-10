package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/yaklang/yaklang/common/utils"
)

// The DNS check looks for a network quietly changing name lookups, a common
// trick on hacked routers and fake Wi-Fi:
//
//   - well-known sites must resolve to addresses owned by the same company
//     as an encrypted lookup (DNS over HTTPS to Cloudflare) says
//   - a made-up name must not resolve (some networks redirect failed lookups)
//   - on your own networks, the DNS servers handed out must not change
//
// The DHCP check remembers which device hands out network settings on each
// of your networks and alerts when another one starts doing it.

func init() {
	registerCheck(&check{name: "dns", about: "whether this network tampers with name lookups (DNS)", run: dnsCheck})
	registerCheck(&check{name: "dhcp", about: "which device hands out network settings (DHCP), and a second one appearing", run: dhcpCheck})
}

var dnsProbeNames = []string{"github.com", "www.google.com", "www.wikipedia.org", "www.apple.com", "www.microsoft.com"}

func systemDNSServers(ctx context.Context) []string {
	servers, _ := utils.GetSystemDnsServers()
	var out []string
	for _, s := range servers {
		if s == "127.0.0.53" && runtime.GOOS == "linux" { // systemd-resolved: ask it for the real ones
			for _, ip := range regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`).FindAllString(cmdOut(ctx, "resolvectl", "dns"), -1) {
				if !contains(out, ip) {
					out = append(out, ip)
				}
			}
			continue
		}
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	if runtime.GOOS == "darwin" {
		for _, ip := range regexp.MustCompile(`nameserver\[\d+\] : (\S+)`).FindAllStringSubmatch(cmdOut(ctx, "scutil", "--dns"), -1) {
			if !contains(out, ip[1]) {
				out = append(out, ip[1])
			}
		}
	}
	sort.Strings(out)
	return out
}

type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func dohLookup(ctx context.Context, name string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudflare-dns.com/dns-query?type=A&name="+url.QueryEscape(name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var a dohAnswer
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return nil, err
	}
	var out []net.IP
	for _, r := range a.Answer {
		if ip := net.ParseIP(r.Data); r.Type == 1 && ip != nil {
			out = append(out, ip)
		}
	}
	return out, nil
}

func lookupA(ctx context.Context, name string) []net.IP {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		return nil
	}
	return addrs
}

// sameOwner is true when the two answers share a network owner. CDNs give
// different addresses in different places, but the owner stays the same.
func sameOwner(a, b []net.IP) bool {
	owners := map[uint32]bool{}
	for _, ip := range b {
		if o, ok := lookupIP(ip); ok {
			owners[o.ASN] = true
		}
	}
	for _, ip := range a {
		for _, x := range b {
			if ip.Equal(x) {
				return true
			}
		}
		if o, ok := lookupIP(ip); ok && owners[o.ASN] {
			return true
		}
	}
	return false
}

func ipList(ips []net.IP) string {
	var s []string
	for _, ip := range ips {
		s = append(s, ip.String())
	}
	return strings.Join(s, ", ")
}

func dnsCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	var out []*Finding
	servers := systemDNSServers(ctx)
	srv := strings.Join(servers, ", ")

	// a made-up name under a domain with no wildcard must not resolve
	b := make([]byte, 6)
	rand.Read(b)
	if ips := lookupA(ctx, "yaklite-"+hex.EncodeToString(b)+".example.com"); len(ips) > 0 {
		out = append(out, &Finding{ID: "dns:nxdomain-redirect", Severity: sevLow,
			Title:  "This network answers lookups for names that do not exist, sending you to " + ipList(ips),
			Detail: "DNS servers: " + srv,
			Fix:    "Usually an internet provider showing ads on typo pages. If it is your own router, turn off \"DNS assist\" or similar, or use another DNS server."})
	}

	var bad []string
	for _, name := range dnsProbeNames {
		sys := lookupA(ctx, name)
		if len(sys) == 0 {
			continue
		}
		for _, ip := range sys {
			if !isPublicAddr(ip) {
				bad = append(bad, fmt.Sprintf("%s -> %s (a private address)", name, ip))
				sys = nil
				break
			}
		}
		if sys == nil || !env.opts.publicLookup {
			continue
		}
		doh, err := dohLookup(ctx, name)
		if err != nil || len(doh) == 0 {
			continue
		}
		if !sameOwner(sys, doh) {
			o, _ := lookupIP(sys[0])
			bad = append(bad, fmt.Sprintf("%s -> %s (%s), expected %s", name, ipList(sys), o.String(), ipList(doh)))
		}
	}
	if len(bad) > 0 {
		out = append(out, &Finding{ID: "dns:tampered", Severity: sevHigh,
			Title:  "This network sends lookups for well-known sites to the wrong place",
			Detail: strings.Join(bad, "; ") + ". DNS servers: " + srv,
			Fix:    "Do not log in to anything on this network. On your own network, check the router's DNS settings and change its admin password; if they were changed, reset the router."})
	}

	// on your own networks, DNS servers should not change behind your back
	if env.trusted && env.net != nil && len(servers) > 0 {
		if prev := rememberPerNetwork(env.stateDir, "dns-servers", env.net.ID(), srv); prev != "" && prev != srv {
			out = append(out, &Finding{ID: "dns:servers-changed:" + srv, Severity: sevHigh, Until: time.Now().Add(72 * time.Hour),
				Title:  "The DNS servers on this network changed from " + prev + " to " + srv,
				Detail: "Changing DNS is a common first step of a router takeover.",
				Fix:    "If you did not change them, check the router's DNS and DHCP settings and its admin password. yaklite ack this alert if the change was yours."})
		}
	}
	return out, nil
}

// rememberPerNetwork stores value for a network and returns what was stored before.
func rememberPerNetwork(stateDir, what, netID, value string) string {
	p := filepath.Join(stateDir, what+".json")
	m := map[string]string{}
	if data, err := os.ReadFile(p); err == nil {
		json.Unmarshal(data, &m)
	}
	prev := m[netID]
	if prev != value {
		m[netID] = value
		if data, err := json.MarshalIndent(m, "", "  "); err == nil {
			writeFilePrivate(p, data)
		}
	}
	return prev
}

// ---- DHCP ----

// dhcpServer returns the DHCP server that gave this machine its address.
func dhcpServer(ctx context.Context, iface string) string {
	switch runtime.GOOS {
	case "darwin":
		if iface == "" {
			return ""
		}
		return parseIPConfigPacket(cmdOut(ctx, "ipconfig", "getpacket", iface))
	case "linux":
		if s := regexp.MustCompile(`dhcp_server_identifier = (\S+)`).FindStringSubmatch(cmdOut(ctx, "nmcli", "-t", "-f", "DHCP4", "device", "show", iface)); s != nil {
			return s[1]
		}
		if ifi, err := net.InterfaceByName(iface); err == nil {
			if data, err := os.ReadFile(fmt.Sprintf("/run/systemd/netif/leases/%d", ifi.Index)); err == nil {
				if s := regexp.MustCompile(`(?m)^SERVER_ADDRESS=(\S+)`).FindStringSubmatch(string(data)); s != nil {
					return s[1]
				}
			}
		}
		files, _ := filepath.Glob("/var/lib/dhcp/dhclient*.leases")
		more, _ := filepath.Glob("/var/lib/NetworkManager/*.lease")
		for _, f := range append(files, more...) {
			data, _ := os.ReadFile(f)
			if m := regexp.MustCompile(`dhcp-server-identifier (\S+);`).FindAllStringSubmatch(string(data), -1); m != nil {
				return m[len(m)-1][1]
			}
			if m := regexp.MustCompile(`(?m)^SERVER_ADDRESS=(\S+)`).FindStringSubmatch(string(data)); m != nil {
				return m[1]
			}
		}
	}
	return ""
}

func parseIPConfigPacket(s string) string {
	if m := regexp.MustCompile(`server_identifier \(ip\): (\S+)`).FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func dhcpCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	if env.net == nil {
		return nil, nil
	}
	var out []*Finding
	server := dhcpServer(ctx, env.net.Iface)
	if server != "" && env.trusted {
		if prev := rememberPerNetwork(env.stateDir, "dhcp-servers", env.net.ID(), server); prev != "" && prev != server {
			out = append(out, &Finding{ID: "dhcp:server-changed:" + server, Severity: sevHigh, Host: server, Until: time.Now().Add(72 * time.Hour),
				Title:  fmt.Sprintf("A different device is now handing out network settings (DHCP): %s instead of %s", server, prev),
				Detail: "A rogue DHCP server can quietly send everyone's traffic through itself.",
				Fix:    "Find the device at " + server + " (yaklite scan lists it). If it is not your router or a server you set up, unplug it. yaklite ack this alert if the change was yours."})
		}
	}
	// with root, also ask the whole network and count who answers
	if env.trusted && os.Geteuid() == 0 {
		offers, err := dhcpDiscover(ctx, env.net.Iface)
		if err == nil && len(offers) > 1 {
			out = append(out, &Finding{ID: "dhcp:multiple-servers", Severity: sevHigh,
				Title: "More than one device answers requests for network settings (DHCP): " + strings.Join(offers, ", "),
				Fix:   "A network should have one DHCP server, normally the router. Find and unplug the other one, or turn off its DHCP server."})
		}
	}
	return out, nil
}
