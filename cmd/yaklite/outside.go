package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yaklang/yaklang/common/subdomain"
	"github.com/yaklang/yaklang/common/utils"
)

// The outside view watches what the internet can see of domains and public
// IPs you own: which names exist (from certificate transparency logs, and
// optionally DNS brute force), where they point, their certificates and
// websites, whether your DNS servers allow zone transfers, and which ports
// are open on public IPs you list.

type OutsideOptions struct {
	Domains     []string
	IPs         string // public IPs to port scan, same syntax as -t
	ScanNames   bool   // also port scan the IPs that names resolve to
	Brute       bool   // guess names with yaklang's DNS brute force wordlist
	NoCT        bool   // skip certificate transparency lookups
	DNSServers  []string
	Scan        ScanOptions // ports, timeouts and fingerprinting for the port scan
	MaxNames    int
	MaxScanIPs  int
	ProgressFor func(format string, args ...any)
}

// NameInfo is one DNS name under a watched domain.
type NameInfo struct {
	IPs     []string `json:"ips"`
	Sources []string `json:"sources,omitempty"` // ct, brute, axfr, given
	HTTPS   *Service `json:"https,omitempty"`   // what answers on 443 for this name, with its certificate
	Web     *WebInfo `json:"web,omitempty"`
	// CertMismatch is set when the certificate on 443 does not cover this name.
	CertMismatch bool `json:"cert_mismatch,omitempty"`
}

type WebInfo struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Title  string `json:"title,omitempty"`
	Server string `json:"server,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (w *WebInfo) Short() string {
	if w == nil {
		return "no web server"
	}
	if w.Error != "" {
		return "unreachable"
	}
	s := fmt.Sprintf("%d", w.Status)
	if w.Server != "" {
		s += " " + w.Server
	}
	if w.Title != "" {
		s += fmt.Sprintf(" %q", w.Title)
	}
	return s
}

var ctClient = &http.Client{Timeout: 60 * time.Second}

// ctNames asks two certificate transparency search services for names
// under domain. Only the domain name is sent to them.
func ctNames(ctx context.Context, domain string) ([]string, []string) {
	var names, errs []string
	get := func(u string, v any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "yaklite (certificate transparency lookup)")
		resp, err := ctClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
	}

	var crt []struct {
		NameValue string `json:"name_value"`
	}
	if err := get("https://crt.sh/?output=json&q="+url.QueryEscape("%."+domain), &crt); err != nil {
		errs = append(errs, "crt.sh: "+err.Error())
	}
	for _, e := range crt {
		names = append(names, strings.Split(e.NameValue, "\n")...)
	}

	var cs []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := get("https://api.certspotter.com/v1/issuances?include_subdomains=true&expand=dns_names&domain="+url.QueryEscape(domain), &cs); err != nil {
		errs = append(errs, "certspotter: "+err.Error())
	}
	for _, e := range cs {
		names = append(names, e.DNSNames...)
	}
	return names, errs
}

func cleanName(n, domain string) string {
	n = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(n, ".")))
	n = strings.TrimPrefix(n, "*.")
	if n == domain || strings.HasSuffix(n, "."+domain) {
		if strings.ContainsAny(n, " /@*") {
			return ""
		}
		return n
	}
	return ""
}

// dnsLookups finds names by zone transfer (and brute force when asked) using
// yaklang's subdomain scanner. It reports which name servers allowed a
// zone transfer.
func dnsLookups(ctx context.Context, opt OutsideOptions, domain string) (names []string, axfrFrom []string) {
	modes := []int{subdomain.ZONE_TRANSFER}
	if opt.Brute {
		modes = append(modes, subdomain.BRUTE)
	}
	cfg := subdomain.NewSubdomainScannerConfig(
		subdomain.WithModes(modes...),
		subdomain.WithDNSServers(opt.DNSServers),
		subdomain.WithAllowToRecursive(false),
		subdomain.WithTimeoutForEachTarget(5*time.Minute),
	)
	sc, err := subdomain.NewSubdomainScanner(cfg, domain)
	if err != nil {
		return nil, nil
	}
	resolvers := map[string]bool{}
	for _, s := range opt.DNSServers {
		resolvers[s] = true
	}
	var mu sync.Mutex
	seenNS := map[string]bool{}
	sc.OnResult(func(r *subdomain.SubdomainResult) {
		if r.Aborted {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		names = append(names, r.Domain)
		if r.FromModeRaw == subdomain.ZONE_TRANSFER && !resolvers[r.FromDNSServer] && !seenNS[r.FromDNSServer] {
			seenNS[r.FromDNSServer] = true
			axfrFrom = append(axfrFrom, r.FromDNSServer)
		}
	})
	_ = sc.RunWithContext(ctx)
	sort.Strings(axfrFrom)
	return names, axfrFrom
}

func resolveName(ctx context.Context, r *net.Resolver, name string) []string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(cctx, name)
	if err != nil {
		return nil
	}
	sort.Strings(addrs)
	return addrs
}

func resolverFor(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	var i int
	var mu sync.Mutex
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		mu.Lock()
		s := servers[i%len(servers)]
		i++
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(s, "53"))
	}}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// fetchWeb loads the home page of name, preferring HTTPS. Certificate
// problems are reported separately, so verification is off here.
func fetchWeb(ctx context.Context, name string, timeout time.Duration) *WebInfo {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: timeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	var last error
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + name + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "yaklite (monitoring your own site)")
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		w := &WebInfo{URL: u, Status: resp.StatusCode, Server: resp.Header.Get("Server")}
		if m := titleRe.FindSubmatch(body); m != nil {
			w.Title = strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
			if len(w.Title) > 80 {
				w.Title = w.Title[:80]
			}
		}
		return w
	}
	if last == nil {
		return nil
	}
	return &WebInfo{URL: "https://" + name + "/", Error: shortErr(last)}
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

// certCovers reports whether a certificate's names cover name.
func certCovers(t *TLSInfo, name string) bool {
	for _, n := range t.DNSNames {
		n = strings.ToLower(n)
		if n == name {
			return true
		}
		if strings.HasPrefix(n, "*.") {
			if i := strings.IndexByte(name, '.'); i > 0 && name[i+1:] == n[2:] {
				return true
			}
		}
	}
	return false
}

func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

// ScanOutside builds a snapshot of the outside view.
func ScanOutside(ctx context.Context, opt OutsideOptions) (*Snapshot, error) {
	progress := opt.ProgressFor
	if progress == nil {
		progress = func(string, ...any) {}
	}
	if opt.MaxNames <= 0 {
		opt.MaxNames = 300
	}
	if opt.MaxScanIPs <= 0 {
		opt.MaxScanIPs = 32
	}
	snap := NewSnapshot(strings.Join(opt.Domains, ","), resolvePorts(opt.Scan.Ports), "outside")
	snap.Started = time.Now().UTC()
	snap.Domains = opt.Domains
	snap.Names = map[string]*NameInfo{}
	snap.ZoneTransfer = map[string][]string{}

	sources := map[string]map[string]bool{}
	addName := func(n, domain, src string) {
		if n = cleanName(n, domain); n == "" {
			return
		}
		if sources[n] == nil {
			sources[n] = map[string]bool{}
		}
		sources[n][src] = true
	}
	for _, d := range opt.Domains {
		addName(d, d, "given")
		addName("www."+d, d, "given")
		if !opt.NoCT {
			names, errs := ctNames(ctx, d)
			snap.SourceErrors = append(snap.SourceErrors, errs...)
			for _, n := range names {
				addName(n, d, "ct")
			}
		}
		names, axfr := dnsLookups(ctx, opt, d)
		for _, n := range names {
			addName(n, d, "dns")
		}
		if len(axfr) > 0 {
			snap.ZoneTransfer[d] = axfr
		}
	}
	all := make([]string, 0, len(sources))
	for n := range sources {
		all = append(all, n)
	}
	sort.Strings(all)
	if len(all) > opt.MaxNames {
		progress("found %d names, checking the first %d (raise --max-names to see more)", len(all), opt.MaxNames)
		all = all[:opt.MaxNames]
	}
	progress("%d candidate names, resolving", len(all))

	resolver := resolverFor(opt.DNSServers)
	var mu sync.Mutex
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, n := range all {
		wg.Add(1)
		sem <- struct{}{}
		go func(n string) {
			defer wg.Done()
			defer func() { <-sem }()
			ips := resolveName(ctx, resolver, n)
			if len(ips) == 0 {
				return // names in old certificates often no longer exist
			}
			src := make([]string, 0, len(sources[n]))
			for s := range sources[n] {
				src = append(src, s)
			}
			sort.Strings(src)
			ni := &NameInfo{IPs: ips, Sources: src}
			if !opt.Scan.NoTLS {
				if t := inspectTLS(ctx, n, 443, opt.Scan.ProbeTimeout); t != nil {
					ni.HTTPS = &Service{Port: 443, Proto: "tcp", Service: "https", Verified: true, TLS: t}
					ni.CertMismatch = !certCovers(t, n)
				}
			}
			ni.Web = fetchWeb(ctx, n, opt.Scan.ProbeTimeout+5*time.Second)
			mu.Lock()
			snap.Names[n] = ni
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	progress("%d names resolve", len(snap.Names))

	// Port scan: IPs the user listed, plus resolved IPs when asked. Resolved
	// IPs often belong to a CDN or hosting provider rather than to you, so
	// they are not scanned by default.
	var targets []string
	if strings.TrimSpace(opt.IPs) != "" {
		targets = utils.ParseStringToHosts(opt.IPs)
	}
	if opt.ScanNames {
		seen := map[string]bool{}
		for _, t := range targets {
			seen[t] = true
		}
		for _, ni := range snap.Names {
			for _, ip := range ni.IPs {
				if isPublicIP(ip) && !seen[ip] && net.ParseIP(ip).To4() != nil {
					seen[ip] = true
					targets = append(targets, ip)
				}
			}
		}
	}
	if len(targets) > opt.MaxScanIPs {
		progress("limiting the port scan to %d of %d IPs (--max-ips)", opt.MaxScanIPs, len(targets))
		targets = targets[:opt.MaxScanIPs]
	}
	if len(targets) > 0 {
		so := opt.Scan
		so.Targets = strings.Join(targets, ",")
		so.NoARP = true
		so.Progress = progress
		ps, err := Scan(ctx, so)
		if err != nil {
			return nil, err
		}
		snap.Hosts = ps.Hosts
	}
	snap.Finished = time.Now().UTC()
	snap.Sort()
	return snap, ctx.Err()
}

// diffNames reports changes to names, DNS answers, certificates, websites and
// zone transfers between two outside snapshots.
func diffNames(prev, cur *Snapshot, opt DiffOptions, now time.Time) []Change {
	var out []Change
	goneAfter := max(opt.GoneAfter, 1)
	prevNames := map[string]*NameInfo{}
	if prev != nil && prev.Names != nil {
		prevNames = prev.Names
	}
	names := map[string]bool{}
	for n := range cur.Names {
		names[n] = true
	}
	for n := range prevNames {
		names[n] = true
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	for _, n := range ordered {
		p, c := prevNames[n], cur.Names[n]
		key := "name:" + n
		switch {
		case c != nil && p == nil:
			out = append(out, Change{Time: now, Kind: "name_new", Host: n, Outside: true, After: strings.Join(c.IPs, ","), Detail: "from " + strings.Join(c.Sources, ", ")})
			if c.CertMismatch {
				out = append(out, Change{Time: now, Kind: "cert_mismatch", Host: n, Port: 443, Proto: "tcp", Outside: true, After: c.HTTPS.TLS.Short()})
			}
			out = append(out, tlsChanges(n, nil, c.HTTPS, opt.TLSWarn, now)...)
		case c == nil && p != nil:
			misses := prev.Misses[key] + 1
			if misses >= goneAfter {
				out = append(out, Change{Time: now, Kind: "name_gone", Host: n, Outside: true, Before: strings.Join(p.IPs, ",")})
				continue
			}
			cur.Names[n] = p
			cur.Misses[key] = misses
		default:
			if strings.Join(p.IPs, ",") != strings.Join(c.IPs, ",") {
				out = append(out, Change{Time: now, Kind: "dns_changed", Host: n, Outside: true, Before: strings.Join(p.IPs, ","), After: strings.Join(c.IPs, ",")})
			}
			if c.CertMismatch && !p.CertMismatch {
				out = append(out, Change{Time: now, Kind: "cert_mismatch", Host: n, Port: 443, Proto: "tcp", Outside: true, After: c.HTTPS.TLS.Short()})
			}
			out = append(out, tlsChanges(n, p.HTTPS, c.HTTPS, opt.TLSWarn, now)...)
			if webChanged(p.Web, c.Web) {
				out = append(out, Change{Time: now, Kind: "web_changed", Host: n, Outside: true, Before: p.Web.Short(), After: c.Web.Short()})
			}
		}
	}
	for d, ns := range cur.ZoneTransfer {
		if prev == nil || len(prev.ZoneTransfer[d]) == 0 {
			out = append(out, Change{Time: now, Kind: "zone_transfer_open", Host: d, Outside: true, After: strings.Join(ns, ",")})
		}
	}
	for i := range out {
		out[i].Outside = true
	}
	return out
}

func webChanged(p, c *WebInfo) bool {
	if (p == nil) != (c == nil) {
		return true
	}
	if p == nil {
		return false
	}
	if (p.Error == "") != (c.Error == "") {
		return true
	}
	return p.Status/100 != c.Status/100 || p.Server != c.Server
}
