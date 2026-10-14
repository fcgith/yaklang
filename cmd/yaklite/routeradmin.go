package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// The router admin check asks whether the router's own management pages
// can be reached from the internet, and whether logging in to it at home
// sends the password unencrypted.

func init() {
	registerCheck(&check{name: "routeradmin", about: "whether your router's admin page can be reached from the internet, and whether it uses encryption (trusted networks only)", trustedOnly: true, last: true, run: routerAdminCheck})
}

// routerAdminPorts are ports routers use for remote management.
var routerAdminPorts = map[int]string{
	80: "web admin page", 443: "web admin page", 8080: "web admin page", 8443: "web admin page", 8000: "web admin page", 8888: "web admin page",
	23: "Telnet", 22: "SSH", 7547: "the internet provider's remote management (TR-069)", 8291: "MikroTik Winbox", 8728: "MikroTik API",
	4567: "the internet provider's remote management", 161: "SNMP",
}

func routerAdminCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	var out []*Finding
	// ports internet scanners see on the public address that no UPnP
	// mapping explains are most likely the router itself (or a manual
	// forward), so remote management may be on
	for id, f := range env.snap.Findings {
		var port int
		if _, err := fmt.Sscanf(id, "public-port:%d", &port); err != nil {
			continue
		}
		what, ok := routerAdminPorts[port]
		if !ok || env.snap.Findings[fmt.Sprintf("upnp:tcp/%d", port)] != nil {
			continue
		}
		sev := sevHigh
		if port == 7547 || port == 4567 {
			sev = sevMedium // usually the provider's own, but it has been attacked at scale before
		}
		out = append(out, &Finding{ID: fmt.Sprintf("routeradmin:public:%d", port), Severity: sev, Host: f.Host,
			Title:  fmt.Sprintf("Port %d (%s) is open on your public address and is not a UPnP forward, so it is most likely your router itself", port, what),
			Detail: "Router admin pages open to the internet are one of the most common ways home networks get taken over.",
			Fix:    "In the router's settings, turn off remote management / remote access / WAN access, and change the admin password. If it is the provider's management port, ask them whether it can be closed."})
	}
	if env.net != nil && env.net.Gateway != "" {
		gw := env.net.Gateway
		if f := plainHTTPAdmin(ctx, gw); f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

func tcpOpen(ctx context.Context, host string, port int) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// plainHTTPAdmin reports a router whose admin page is only on plain HTTP.
func plainHTTPAdmin(ctx context.Context, gw string) *Finding {
	if !tcpOpen(ctx, gw, 80) || tcpOpen(ctx, gw, 443) || tcpOpen(ctx, gw, 8443) {
		return nil
	}
	return &Finding{ID: "routeradmin:plain-http", Severity: sevLow, Host: gw,
		Title: "Your router's admin page only uses plain HTTP, so its password crosses the network unencrypted when you log in",
		Fix:   "Turn on HTTPS for the admin page if the router offers it, use a long unique admin password, and only log in over a cable or your own Wi-Fi."}
}
