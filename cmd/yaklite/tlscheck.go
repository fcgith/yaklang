package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// TLSInfo is what yaklite records about a TLS certificate on an open port.
type TLSInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	NotAfter   time.Time `json:"not_after"`
	SHA256     string    `json:"sha256"`
	SelfSigned bool      `json:"self_signed"`
	Version    string    `json:"version"`
}

func (t *TLSInfo) Short() string {
	if t == nil {
		return "none"
	}
	return fmt.Sprintf("%s, expires %s", t.Subject, t.NotAfter.Format("2006-01-02"))
}

// tlsPorts are checked for a certificate even when the fingerprint does not say TLS.
var tlsPorts = map[int]bool{443: true, 465: true, 636: true, 853: true, 993: true, 995: true, 4443: true, 5001: true, 5986: true, 6443: true, 7443: true, 8443: true, 8883: true, 9443: true}

func wantsTLSCheck(s *Service) bool {
	if tlsPorts[s.Port] {
		return true
	}
	name := strings.ToLower(s.Service + " " + s.Product)
	return strings.Contains(name, "ssl") || strings.Contains(name, "https") || strings.Contains(name, "tls")
}

var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0", tls.VersionTLS11: "TLS 1.1", tls.VersionTLS12: "TLS 1.2", tls.VersionTLS13: "TLS 1.3",
}

// inspectTLS reads the certificate a service presents. Verification is
// skipped on purpose: this only looks at the certificate and sends no data.
func inspectTLS(ctx context.Context, host string, port int, timeout time.Duration) *TLSInfo {
	dialer := &net.Dialer{Timeout: timeout}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	d := tls.Dialer{NetDialer: dialer, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	return certInfo(st.PeerCertificates[0], st.Version)
}

func certInfo(cert *x509.Certificate, version uint16) *TLSInfo {
	sum := sha256.Sum256(cert.Raw)
	v := tlsVersionNames[version]
	if v == "" {
		v = fmt.Sprintf("0x%04x", version)
	}
	return &TLSInfo{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		DNSNames:   cert.DNSNames,
		NotAfter:   cert.NotAfter.UTC(),
		SHA256:     hex.EncodeToString(sum[:]),
		SelfSigned: cert.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(cert) == nil,
		Version:    v,
	}
}

func expiryState(t *TLSInfo, warn time.Duration, now time.Time) string {
	if t == nil || warn <= 0 {
		return ""
	}
	if now.After(t.NotAfter) {
		return "expired"
	}
	if t.NotAfter.Sub(now) <= warn {
		return "expiring"
	}
	return ""
}

func daysLeft(t *TLSInfo, now time.Time) string {
	d := int(t.NotAfter.Sub(now).Hours() / 24)
	switch {
	case d < 0:
		return fmt.Sprintf("expired %d days ago", -d)
	case d == 0:
		return "expires today"
	}
	return fmt.Sprintf("%d days left", d)
}

// tlsChanges reports certificate events for one service. Expiry is reported
// when a certificate first enters the warning window or expires, not on every
// scan, so an hourly watch does not repeat itself.
func tlsChanges(host string, prev, cur *Service, warn time.Duration, now time.Time) []Change {
	if cur == nil || cur.TLS == nil {
		return nil
	}
	var out []Change
	base := Change{Time: now, Host: host, Port: cur.Port, Proto: cur.Proto}
	var prevTLS *TLSInfo
	if prev != nil {
		prevTLS = prev.TLS
	}
	sameCert := prevTLS != nil && prevTLS.SHA256 == cur.TLS.SHA256

	if prevTLS != nil && !sameCert {
		c := base
		c.Kind = "tls_cert_changed"
		c.Before = prevTLS.Short()
		c.After = cur.TLS.Short()
		if prevTLS.Issuer != cur.TLS.Issuer {
			c.Detail = "issuer changed: " + cur.TLS.Issuer
		}
		out = append(out, c)
	}

	state := expiryState(cur.TLS, warn, now)
	prevState := ""
	if sameCert {
		// the state the previous scan recorded for this same certificate
		prevState = prev.TLSState
	}
	if state != "" && state != prevState {
		c := base
		c.Kind = "tls_" + state
		c.After = cur.TLS.Short()
		c.Detail = daysLeft(cur.TLS, now)
		out = append(out, c)
	}
	cur.TLSState = state
	return out
}
