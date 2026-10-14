package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Checks on domains you own, run by `yaklite outside`:
//
//   - email spoofing: SPF and DMARC records that stop others sending mail
//     as you
//   - expiry: the registration running out, so someone else can buy it
//   - hijackable subdomains: names pointing at a cloud service you no
//     longer use, which anyone can claim and serve pages from
//   - new certificates: someone getting an HTTPS certificate for your names
//   - look-alike domains: typo versions of your domain that exist
//   - data leaks: through Have I Been Pwned (breaches.go)

type domainCheckOptions struct {
	resolver   *net.Resolver
	lookalikes bool
	noRDAP     bool
	noHIBP     bool
}

func domainChecks(ctx context.Context, snap *Snapshot, domains, candidates []string, certs []ctCert, o domainCheckOptions, progress func(string, ...any)) {
	var mu sync.Mutex
	add := func(fs ...*Finding) {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fs {
			f.Check = "domain"
			snap.addFinding(f)
		}
	}
	var wg sync.WaitGroup
	for _, d := range domains {
		d := d
		wg.Add(2)
		go func() {
			defer wg.Done()
			fs, err := emailAuthFindings(ctx, o.resolver, d)
			if err != nil {
				mu.Lock()
				snap.SourceErrors = append(snap.SourceErrors, d+": "+err.Error())
				mu.Unlock()
			}
			add(fs...)
		}()
		go func() {
			defer wg.Done()
			if o.noRDAP {
				return
			}
			f, err := expiryFinding(ctx, d, time.Now())
			if err != nil {
				mu.Lock()
				snap.SourceErrors = append(snap.SourceErrors, "registration lookup for "+d+": "+err.Error())
				mu.Unlock()
			}
			if f != nil {
				add(f)
			}
		}()
		if o.lookalikes {
			wg.Add(1)
			go func() { defer wg.Done(); add(lookalikeFindings(ctx, o.resolver, d)...) }()
		}
	}
	wg.Add(1)
	go func() { defer wg.Done(); add(takeoverFindings(ctx, o.resolver, candidates)...) }()
	if !o.noHIBP && len(domains) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fs, errs := breachFindings(ctx, domains)
			mu.Lock()
			snap.SourceErrors = append(snap.SourceErrors, errs...)
			mu.Unlock()
			add(fs...)
		}()
	}
	wg.Wait()
	add(newCertFindings(certs, time.Now())...)
	add(websiteFindings(snap.Names)...)
	progress("domain checks done")
}

// ---- email spoofing ----

// txtRecords returns the TXT records of name. ok is false when the lookup
// failed for a reason other than the records not existing.
func txtRecords(ctx context.Context, r *net.Resolver, name string) (txt []string, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	txt, err := r.LookupTXT(ctx, name)
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		return nil, false
	}
	return txt, true
}

func emailAuthFindings(ctx context.Context, r *net.Resolver, domain string) ([]*Finding, error) {
	var spf, dmarc string
	recs, ok1 := txtRecords(ctx, r, domain)
	for _, t := range recs {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
		}
	}
	recs, ok2 := txtRecords(ctx, r, "_dmarc."+domain)
	for _, t := range recs {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			dmarc = t
		}
	}
	if !ok1 || !ok2 {
		return nil, errors.New("could not look up the SPF and DMARC records")
	}
	return judgeEmailAuth(domain, spf, dmarc), nil
}

func judgeEmailAuth(domain, spf, dmarc string) []*Finding {
	var out []*Finding
	l := strings.ToLower(spf)
	switch {
	case spf == "":
		out = append(out, &Finding{ID: "email:no-spf:" + domain, Severity: sevMedium, Host: domain,
			Title: "No SPF record: anyone can send email that claims to come from @" + domain,
			Fix:   `Add a TXT record on ` + domain + ` listing who may send your mail, e.g. "v=spf1 include:_spf.google.com -all", or "v=spf1 -all" if the domain sends no email.`})
	case strings.Contains(l, "+all"):
		out = append(out, &Finding{ID: "email:spf-allows-all:" + domain, Severity: sevHigh, Host: domain,
			Title: "The SPF record for " + domain + " allows every server in the world to send as you (+all)", Detail: spf,
			Fix: "End the SPF record with -all (or ~all) instead of +all."})
	case !strings.Contains(l, "-all") && !strings.Contains(l, "~all") && !strings.Contains(l, "redirect="):
		out = append(out, &Finding{ID: "email:spf-weak:" + domain, Severity: sevLow, Host: domain,
			Title: "The SPF record for " + domain + " does not tell receivers to reject other senders", Detail: spf,
			Fix: "End the SPF record with -all (or ~all)."})
	}
	p := ""
	for _, kv := range strings.Split(strings.ToLower(dmarc), ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && strings.TrimSpace(k) == "p" {
			p = strings.TrimSpace(v)
		}
	}
	switch {
	case dmarc == "":
		out = append(out, &Finding{ID: "email:no-dmarc:" + domain, Severity: sevMedium, Host: domain,
			Title: "No DMARC record, so mail providers do not know to reject fake email from @" + domain,
			Fix:   `Add a TXT record on _dmarc.` + domain + `, e.g. "v=DMARC1; p=quarantine; rua=mailto:you@` + domain + `". Use p=reject once reports look clean.`})
	case p == "none":
		out = append(out, &Finding{ID: "email:dmarc-none:" + domain, Severity: sevLow, Host: domain,
			Title: "DMARC for " + domain + " only monitors (p=none): fake email is still delivered", Detail: dmarc,
			Fix: "Change p=none to p=quarantine, then p=reject, once the reports show your real mail passes."})
	}
	return out
}

// ---- registration expiry (RDAP) ----

type rdapDomain struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

func registrable(domain string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return d
	}
	return domain
}

func expiryFinding(ctx context.Context, domain string, now time.Time) (*Finding, error) {
	reg := registrable(domain)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/domain/"+url.PathEscape(reg), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return &Finding{ID: "domain:unregistered:" + reg, Severity: sevHigh, Host: reg,
			Title: "The domain " + reg + " does not appear to be registered: anyone can buy it",
			Fix:   "Register or renew it now with your registrar."}, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	var d rdapDomain
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	return judgeExpiry(reg, d, now), nil
}

func judgeExpiry(reg string, d rdapDomain, now time.Time) *Finding {
	for _, e := range d.Events {
		if e.Action != "expiration" {
			continue
		}
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			continue
		}
		days := int(t.Sub(now).Hours() / 24)
		f := &Finding{Host: reg, Fix: "Renew it with your registrar and turn on auto-renew."}
		switch {
		case days < 0:
			f.ID, f.Severity = "domain:expired:"+reg, sevHigh
			f.Title = fmt.Sprintf("The domain %s expired on %s", reg, t.Format("2 Jan 2006"))
		case days <= 14:
			f.ID, f.Severity = "domain:expiring-soon:"+reg, sevHigh
			f.Title = fmt.Sprintf("The domain %s expires in %d days (%s)", reg, days, t.Format("2 Jan 2006"))
		case days <= 45:
			f.ID, f.Severity = "domain:expiring:"+reg, sevMedium
			f.Title = fmt.Sprintf("The domain %s expires in %d days (%s)", reg, days, t.Format("2 Jan 2006"))
		default:
			return nil
		}
		return f
	}
	return nil
}

// ---- hijackable subdomains ----

// takeoverServices are hosting services where a name pointing at a deleted
// site can be claimed by anyone. body is text the service shows for an
// unclaimed site; nxdomain means the target name no longer existing is enough.
var takeoverServices = []struct {
	suffix, service, body string
	nxdomain              bool
}{
	{".s3.amazonaws.com", "Amazon S3", "NoSuchBucket", false},
	{".s3-website", "Amazon S3", "NoSuchBucket", false},
	{".cloudfront.net", "Amazon CloudFront", "The request could not be satisfied", false},
	{".elasticbeanstalk.com", "AWS Elastic Beanstalk", "", true},
	{".github.io", "GitHub Pages", "There isn't a GitHub Pages site here", false},
	{".herokuapp.com", "Heroku", "no-such-app", false},
	{".herokudns.com", "Heroku", "no-such-app", false},
	{".azurewebsites.net", "Azure App Service", "", true},
	{".cloudapp.net", "Azure", "", true},
	{".cloudapp.azure.com", "Azure", "", true},
	{".trafficmanager.net", "Azure Traffic Manager", "", true},
	{".blob.core.windows.net", "Azure Storage", "", true},
	{".azureedge.net", "Azure CDN", "", true},
	{".azurefd.net", "Azure Front Door", "", true},
	{".bitbucket.io", "Bitbucket", "Repository not found", false},
	{".ghost.io", "Ghost", "Domain error", false},
	{".myshopify.com", "Shopify", "Sorry, this shop is currently unavailable", false},
	{".surge.sh", "Surge", "project not found", false},
	{".pantheonsite.io", "Pantheon", "The gods are wise", false},
	{".wordpress.com", "WordPress.com", "Do you want to register", false},
	{".netlify.app", "Netlify", "Not Found - Request ID", false},
	{".fly.dev", "Fly.io", "", true},
	{".readme.io", "ReadMe", "Project doesnt exist", false},
	{".helpscoutdocs.com", "Help Scout", "No settings were found for this company", false},
	{".zendesk.com", "Zendesk", "Help Center Closed", false},
	{".uservoice.com", "UserVoice", "This UserVoice subdomain is currently available", false},
	{".webflow.io", "Webflow", "The page you are looking for doesn't exist or has been moved", false},
	{".tumblr.com", "Tumblr", "Whatever you were looking for doesn't currently exist at this address", false},
}

func takeoverFindings(ctx context.Context, r *net.Resolver, names []string) []*Finding {
	var mu sync.Mutex
	var out []*Finding
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(n string) {
			defer wg.Done()
			defer func() { <-sem }()
			if f := takeoverCheck(ctx, r, n); f != nil {
				mu.Lock()
				out = append(out, f)
				mu.Unlock()
			}
		}(n)
	}
	wg.Wait()
	return out
}

func takeoverCheck(ctx context.Context, r *net.Resolver, name string) *Finding {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cname, err := r.LookupCNAME(cctx, name)
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	if err != nil || cname == "" || cname == name {
		return nil
	}
	for _, s := range takeoverServices {
		if !strings.Contains(cname+".", s.suffix+".") && !strings.HasSuffix(cname, s.suffix) {
			continue
		}
		_, lerr := r.LookupHost(cctx, cname)
		var dnsErr *net.DNSError
		dangling := errors.As(lerr, &dnsErr) && dnsErr.IsNotFound
		claimed := false
		if !dangling && s.body != "" {
			if w := fetchWebBody(ctx, name); strings.Contains(w, s.body) {
				claimed = true
			}
		}
		if (dangling && (s.nxdomain || s.body != "")) || claimed {
			return &Finding{ID: "takeover:" + name, Severity: sevHigh, Host: name,
				Title:  fmt.Sprintf("%s points at an unclaimed %s site (%s): anyone could take it over and serve pages under your name", name, s.service, cname),
				Detail: "The site it points to was deleted, but the DNS record was not.",
				Fix:    "Delete the DNS record for " + name + ", or re-create the " + s.service + " site so you own it again."}
		}
		return nil
	}
	return nil
}

func fetchWebBody(ctx context.Context, name string) string {
	for _, scheme := range []string{"https://", "http://"} {
		b, err := httpGetBody(ctx, scheme+name+"/", 256<<10)
		if err == nil || len(b) > 0 {
			return string(b)
		}
	}
	return ""
}

// httpGetBody returns the body whatever the status code (error pages matter here).
func httpGetBody(ctx context.Context, u string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for int64(len(buf)) < limit {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}

// ---- new certificates ----

type ctCert struct {
	ID        int64  `json:"id"`
	Issuer    string `json:"issuer_name"`
	Names     string `json:"name_value"`
	NotBefore string `json:"not_before"`
}

// newCertFindings reports certificates issued in the last two weeks. Each
// is reported once (the finding stays in the snapshot for 30 days).
func newCertFindings(certs []ctCert, now time.Time) []*Finding {
	byID := map[int64]ctCert{}
	for _, c := range certs {
		byID[c.ID] = c
	}
	var out []*Finding
	for id, c := range byID {
		t, err := time.Parse("2006-01-02T15:04:05", c.NotBefore)
		if err != nil || now.Sub(t) > 14*24*time.Hour {
			continue
		}
		names := strings.Fields(strings.ReplaceAll(c.Names, "\n", " "))
		sort.Strings(names)
		issuer := c.Issuer
		if i := strings.Index(issuer, "O="); i >= 0 {
			issuer = strings.SplitN(issuer[i+2:], ",", 2)[0]
		}
		out = append(out, &Finding{ID: fmt.Sprintf("new-cert:%d", id), Severity: sevLow, Host: strings.Join(names, " "), Until: t.Add(30 * 24 * time.Hour),
			Title:  fmt.Sprintf("A new HTTPS certificate was issued for %s by %s on %s", strings.Join(names, ", "), strings.Trim(issuer, `"`), t.Format("2 Jan 2006")),
			Detail: fmt.Sprintf("https://crt.sh/?id=%d", id),
			Fix:    "Normal if you or your web host renewed it. If not, someone may be preparing to impersonate your site: check your DNS and hosting accounts."})
	}
	return out
}

// ---- look-alike domains ----

var lookalikeTLDs = []string{"com", "net", "org", "co", "io", "info", "biz", "app", "online", "site", "xyz", "eu", "bg", "de", "uk", "us"}

var homoglyphs = map[rune][]string{
	'o': {"0"}, '0': {"o"}, 'l': {"1", "i"}, 'i': {"1", "l"}, '1': {"l"}, 'm': {"rn"}, 'e': {"3"}, 'a': {"4"}, 's': {"5"}, 'g': {"q"}, 'w': {"vv"},
}

// lookalikes returns typo and look-alike versions of a registrable domain.
func lookalikes(domain string) []string {
	reg := registrable(domain)
	suffix, _ := publicsuffix.PublicSuffix(reg)
	label := strings.TrimSuffix(reg, "."+suffix)
	if label == "" || strings.Contains(label, ".") {
		return nil
	}
	set := map[string]bool{}
	add := func(l, tld string) {
		if l != "" && !strings.HasPrefix(l, "-") && !strings.HasSuffix(l, "-") && l+"."+tld != reg {
			set[l+"."+tld] = true
		}
	}
	r := []rune(label)
	for i := range r {
		add(string(r[:i])+string(r[i+1:]), suffix) // missing letter
		add(string(r[:i+1])+string(r[i:]), suffix) // doubled letter
		if i+1 < len(r) {
			s := append([]rune{}, r...)
			s[i], s[i+1] = s[i+1], s[i]
			add(string(s), suffix) // swapped letters
			add(string(r[:i+1])+"-"+string(r[i+1:]), suffix)
		}
		for _, h := range homoglyphs[r[i]] {
			add(string(r[:i])+h+string(r[i+1:]), suffix)
		}
	}
	for _, t := range lookalikeTLDs {
		add(label, t)
	}
	add(label+"-login", suffix)
	add(label+"-secure", suffix)
	add("my"+label, suffix)
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func lookalikeFindings(ctx context.Context, r *net.Resolver, domain string) []*Finding {
	var mu sync.Mutex
	var out []*Finding
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, d := range lookalikes(domain) {
		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			ips, _ := r.LookupHost(cctx, d)
			mx, _ := r.LookupMX(cctx, d)
			if len(ips) == 0 && len(mx) == 0 {
				return
			}
			detail := "points to " + strings.Join(ips, ", ")
			sev := sevLow
			if len(mx) > 0 {
				detail += "; it can receive email"
			}
			mu.Lock()
			out = append(out, &Finding{ID: "lookalike:" + d, Severity: sev, Host: d,
				Title: fmt.Sprintf("A look-alike of %s exists: %s", registrable(domain), d), Detail: detail,
				Fix: "Often harmless (someone else's site, or parked). If it copies your site or emails your contacts, report it to the registrar's abuse address."})
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	return out
}
