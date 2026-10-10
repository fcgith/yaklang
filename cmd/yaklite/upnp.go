package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The router check asks the router, over UPnP, which ports it is forwarding
// from the internet. Many routers let any device on the network open such
// "holes" by itself, which is how a hacked camera or a careless app becomes
// reachable from the whole internet. It also looks the public address up in
// Shodan's free InternetDB, which shows what internet-wide scanners
// (which attackers use too) have already recorded about it.

func init() {
	registerCheck(&check{name: "upnp", about: "ports your router forwards from the internet (UPnP), and whether devices may open more", trustedOnly: true, run: upnpCheck})
	registerCheck(&check{name: "exposure", about: "what internet scanners have recorded about your public address (Shodan InternetDB)", trustedOnly: true, after: true, run: exposureCheck})
}

type portMapping struct {
	Proto        string
	ExternalPort int
	InternalHost string
	InternalPort int
	Description  string
	Enabled      bool
	Lease        int
	Remote       string
}

type igd struct {
	controlURL string
	service    string
}

// findIGDs sends an SSDP search and returns the WAN connection services of
// internet gateways that answer from the local network.
func findIGDs(ctx context.Context, gateway string) ([]igd, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2", "urn:schemas-upnp-org:service:WANIPConnection:1"} {
		msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
		conn.WriteTo([]byte(msg), dst)
		if gateway != "" { // some routers only answer unicast
			conn.WriteTo([]byte(msg), &net.UDPAddr{IP: net.ParseIP(gateway), Port: 1900})
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetReadDeadline(deadline)
	locations := map[string]bool{}
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if !from.IP.IsPrivate() && !from.IP.IsLinkLocalUnicast() {
			continue
		}
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "location") {
				u, err := url.Parse(strings.TrimSpace(v))
				// only follow descriptions served by the device that answered
				if err == nil && u.Hostname() == from.IP.String() && (u.Scheme == "http" || u.Scheme == "https") {
					locations[u.String()] = true
				}
			}
		}
	}
	var out []igd
	seen := map[string]bool{}
	for loc := range locations {
		svcs, err := wanServices(ctx, loc)
		if err != nil {
			continue
		}
		for _, s := range svcs {
			if !seen[s.controlURL] {
				seen[s.controlURL] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}

type upnpDesc struct {
	URLBase string     `xml:"URLBase"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	Services []struct {
		Type       string `xml:"serviceType"`
		ControlURL string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []upnpDevice `xml:"deviceList>device"`
}

func (d upnpDevice) walk(f func(typ, ctl string)) {
	for _, s := range d.Services {
		f(s.Type, s.ControlURL)
	}
	for _, c := range d.Devices {
		c.walk(f)
	}
}

func wanServices(ctx context.Context, loc string) ([]igd, error) {
	body, err := httpGetSmall(ctx, loc, 1<<20)
	if err != nil {
		return nil, err
	}
	return parseIGDDescription(loc, body)
}

func parseIGDDescription(loc string, body []byte) ([]igd, error) {
	var d upnpDesc
	if err := xml.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	base, err := url.Parse(loc)
	if err != nil {
		return nil, err
	}
	if d.URLBase != "" {
		if b, err := url.Parse(d.URLBase); err == nil && b.Hostname() == base.Hostname() {
			base = b
		}
	}
	var out []igd
	d.Device.walk(func(typ, ctl string) {
		if !strings.Contains(typ, ":WANIPConnection:") && !strings.Contains(typ, ":WANPPPConnection:") {
			return
		}
		u, err := base.Parse(strings.TrimSpace(ctl))
		if err != nil || u.Hostname() != base.Hostname() {
			return
		}
		out = append(out, igd{controlURL: u.String(), service: strings.TrimSpace(typ)})
	})
	return out, nil
}

func httpGetSmall(ctx context.Context, u string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
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
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// soapCall runs a UPnP action and returns the response's argument values.
func soapCall(ctx context.Context, g igd, action string, args [][2]string) (map[string]string, error) {
	var b strings.Builder
	for _, a := range args {
		b.WriteString("<" + a[0] + ">")
		xml.EscapeText(&b, []byte(a[1]))
		b.WriteString("</" + a[0] + ">")
	}
	env := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>` +
		`<u:` + action + ` xmlns:u="` + g.service + `">` + b.String() + `</u:` + action + `></s:Body></s:Envelope>`
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.controlURL, strings.NewReader(env))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.service+"#"+action+`"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", action, resp.Status)
	}
	return soapValues(data), nil
}

// soapValues collects the leaf elements of a SOAP response by local name.
func soapValues(data []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(data))
	var name string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name = t.Name.Local
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if t.Name.Local == name {
				out[name] = strings.TrimSpace(text.String())
			}
			name = ""
		}
	}
	return out
}

func listMappings(ctx context.Context, g igd) ([]portMapping, error) {
	var out []portMapping
	for i := 0; i < 512; i++ {
		v, err := soapCall(ctx, g, "GetGenericPortMappingEntry", [][2]string{{"NewPortMappingIndex", strconv.Itoa(i)}})
		if err != nil {
			if i == 0 && !errors.Is(err, context.DeadlineExceeded) && strings.Contains(err.Error(), "500") {
				return nil, nil // 500 on index 0 is "no entries"
			}
			if i == 0 {
				return nil, err
			}
			break
		}
		ext, _ := strconv.Atoi(v["NewExternalPort"])
		in, _ := strconv.Atoi(v["NewInternalPort"])
		lease, _ := strconv.Atoi(v["NewLeaseDuration"])
		out = append(out, portMapping{
			Proto: strings.ToLower(v["NewProtocol"]), ExternalPort: ext, InternalHost: v["NewInternalClient"], InternalPort: in,
			Description: v["NewPortMappingDescription"], Enabled: v["NewEnabled"] != "0", Lease: lease, Remote: v["NewRemoteHost"],
		})
	}
	return out, nil
}

// routerPublicIP asks the router for its WAN address.
func routerPublicIP(ctx context.Context, gs []igd) string {
	for _, g := range gs {
		if v, err := soapCall(ctx, g, "GetExternalIPAddress", nil); err == nil {
			if ip := net.ParseIP(v["NewExternalIPAddress"]); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func upnpCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	gw := ""
	if env.net != nil {
		gw = env.net.Gateway
	}
	gs, err := findIGDs(ctx, gw)
	if err != nil {
		return nil, err
	}
	if len(gs) == 0 {
		return nil, nil // UPnP is off, or the router does not offer it: good
	}
	var out []*Finding
	if ip := routerPublicIP(ctx, gs); ip != "" {
		env.snap.PublicIP = ip
	}
	all := map[string]portMapping{}
	writable := false
	for _, g := range gs {
		ms, err := listMappings(ctx, g)
		if err != nil {
			continue
		}
		writable = true // it answered port-mapping queries without any login
		for _, m := range ms {
			all[fmt.Sprintf("%s/%d", m.Proto, m.ExternalPort)] = m
		}
	}
	if writable {
		out = append(out, &Finding{ID: "upnp:enabled", Severity: sevMedium, Host: gw,
			Title: "Your router lets any device on the network open ports to the internet by itself (UPnP is on)",
			Fix:   "Turn UPnP off in the router's settings unless a game console or similar needs it. Then nothing can be opened to the internet without you."})
	}
	for k, m := range all {
		if !m.Enabled {
			continue
		}
		label := fmt.Sprintf("port %d", m.InternalPort)
		why, risky := env.inv.risky(m.InternalPort, "")
		if risky {
			label += " (" + why + ")"
		}
		f := &Finding{ID: "upnp:" + k, Severity: sevMedium, Host: m.InternalHost,
			Title: fmt.Sprintf("Your router forwards internet port %s %d to %s %s", strings.ToUpper(m.Proto), m.ExternalPort, m.InternalHost, label),
			Fix:   "If you do not know why, remove it in the router's port forwarding / UPnP page and find out which device asked for it."}
		if m.Description != "" {
			f.Detail = "Opened by UPnP, labelled " + strconv.Quote(m.Description)
		}
		if risky {
			f.Severity = sevHigh
		}
		out = append(out, f)
	}
	return out, nil
}

// ---- public exposure ----

type internetDB struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Vulns     []string `json:"vulns"`
	Tags      []string `json:"tags"`
	CPEs      []string `json:"cpes"`
}

func publicIP(ctx context.Context, env *checkEnv) string {
	if ip := net.ParseIP(env.snap.PublicIP); ip != nil && isPublicAddr(ip) {
		return ip.String()
	}
	if !env.opts.publicLookup {
		return ""
	}
	body, err := httpGetSmall(ctx, "https://api.ipify.org", 64)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil && isPublicAddr(ip) {
		env.snap.PublicIP = ip.String()
		return ip.String()
	}
	return ""
}

func exposureCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	if !env.opts.publicLookup {
		return nil, nil
	}
	ip := publicIP(ctx, env)
	if ip == "" {
		return nil, nil
	}
	body, err := httpGetSmall(ctx, "https://internetdb.shodan.io/"+ip, 1<<20)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil // nothing recorded: the best answer
		}
		return nil, err
	}
	var db internetDB
	if err := json.Unmarshal(body, &db); err != nil {
		return nil, err
	}
	var out []*Finding
	for _, p := range db.Ports {
		f := &Finding{ID: fmt.Sprintf("public-port:%d", p), Severity: sevMedium, Host: ip,
			Title: fmt.Sprintf("Internet scanners have seen port %d open on your public address %s", p, ip),
			Fix:   "Check the router's port forwarding and UPnP pages and close it if you do not need it. Scanner data can be a few days old."}
		if why, risky := env.inv.risky(p, ""); risky {
			f.Severity, f.Detail = sevHigh, why
		}
		out = append(out, f)
	}
	if len(db.Vulns) > 0 {
		v := db.Vulns
		if len(v) > 10 {
			v = append(v[:10:10], fmt.Sprintf("and %d more", len(db.Vulns)-10))
		}
		out = append(out, &Finding{ID: "public-vulns", Severity: sevHigh, Host: ip,
			Title:  fmt.Sprintf("Internet scanners list %d known vulnerabilities for software on your public address %s", len(db.Vulns), ip),
			Detail: strings.Join(v, ", "),
			Fix:    "Update the router's firmware and whatever is behind the open ports above, or close those ports."})
	}
	for _, t := range db.Tags {
		if t == "compromised" || t == "malware" || t == "c2" || t == "honeypot" {
			out = append(out, &Finding{ID: "public-tag:" + t, Severity: sevHigh, Host: ip,
				Title: fmt.Sprintf("Internet scanners tag your public address %s as %q", ip, t),
				Fix:   "Something on your network may be infected. Check devices with open ports first, and reset the router if in doubt."})
		}
	}
	return out, nil
}
