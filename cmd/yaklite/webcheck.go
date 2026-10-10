package main

import (
	"context"
	"fmt"
	"sort"
)

// Encryption and browser-protection checks on what the scans found: devices
// and sites that still accept outdated TLS, weak keys, and (for your own
// websites) missing standard protections.

func init() {
	registerCheck(&check{name: "tls", about: "devices and sites using outdated encryption or weak keys", run: tlsCheck})
}

func tlsFindings(where string, port int, t *TLSInfo, sev string) []*Finding {
	var out []*Finding
	if t == nil {
		return nil
	}
	if t.OldTLS {
		out = append(out, &Finding{ID: fmt.Sprintf("tls:old:%s:%d", where, port), Severity: sev, Host: where,
			Title: fmt.Sprintf("%s port %d still accepts outdated encryption (%s)", where, port, map[bool]string{true: "TLS 1.0/1.1", false: t.Version}[t.Version == "TLS 1.2" || t.Version == "TLS 1.3"]),
			Fix:   "Update the device or server, or turn off TLS 1.0 and 1.1 in its settings."})
	}
	if t.KeyBits > 0 && t.KeyBits < 2048 {
		out = append(out, &Finding{ID: fmt.Sprintf("tls:weak-key:%s:%d", where, port), Severity: sev, Host: where,
			Title: fmt.Sprintf("%s port %d uses a weak %d-bit key", where, port, t.KeyBits),
			Fix:   "Replace the certificate with one using at least a 2048-bit RSA or an ECDSA key."})
	}
	return out
}

func tlsCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	var out []*Finding
	for host, svcs := range env.snap.Hosts {
		for _, s := range svcs {
			out = append(out, tlsFindings(host, s.Port, s.TLS, sevLow)...)
		}
	}
	return out, nil
}

// websiteFindings checks your own websites (outside view).
func websiteFindings(names map[string]*NameInfo) []*Finding {
	var out []*Finding
	keys := make([]string, 0, len(names))
	for n := range names {
		keys = append(keys, n)
	}
	sort.Strings(keys)
	for _, n := range keys {
		ni := names[n]
		if ni.HTTPS != nil {
			out = append(out, tlsFindings(n, 443, ni.HTTPS.TLS, sevMedium)...)
		}
		w := ni.Web
		if w == nil || w.Error != "" || w.Status >= 400 {
			continue
		}
		if len(w.URL) > 8 && w.URL[:8] == "https://" && !w.HSTS {
			out = append(out, &Finding{ID: "web:no-hsts:" + n, Severity: sevLow, Host: n,
				Title: n + " does not tell browsers to always use HTTPS (no HSTS header)",
				Fix:   "Add the header Strict-Transport-Security: max-age=31536000 in your web server or hosting settings."})
		}
		if len(w.URL) > 7 && w.URL[:7] == "http://" {
			out = append(out, &Finding{ID: "web:no-https:" + n, Severity: sevMedium, Host: n,
				Title: n + " only works over plain HTTP, so visitors' traffic can be read and changed",
				Fix:   "Turn on HTTPS (free certificates from Let's Encrypt, or your host's HTTPS option)."})
		}
	}
	return out
}
