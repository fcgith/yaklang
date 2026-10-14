package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Router support: with the router's admin login, yaklite reads its device
// list, its log and a few of its settings. It only reads; it never changes
// the router. It talks to the router only on the network where it was set
// up, and for HTTPS it pins the router's certificate the first time, since
// home routers use self-signed ones.

func init() {
	registerCheck(&check{name: "router", trustedOnly: true, run: routerCheck,
		about: "your router's device list, log and settings, with its admin login (yaklite router setup)"})
}

var routerTypes = map[string]string{
	"openwrt":  "OpenWrt (and routers built on it, like GL.iNet and Turris)",
	"mikrotik": "MikroTik RouterOS 7 (the REST API, needs www-ssl on)",
	"fritzbox": "AVM Fritz!Box (TR-064, on by default)",
	"unifi":    "Ubiquiti UniFi (a UniFi OS console or a Network controller)",
}

type routerConfig struct {
	Type       string `yaml:"type"`
	Address    string `yaml:"address"` // host, host:port or a URL
	User       string `yaml:"user"`
	Site       string `yaml:"site,omitempty"`        // UniFi site, "default"
	Network    string `yaml:"network"`               // only used on this network (router MAC)
	CertSHA256 string `yaml:"cert_sha256,omitempty"` // pinned HTTPS certificate
}

func routerConfigPath() string   { return filepath.Join(configDir(), "router.yaml") }
func routerPasswordPath() string { return filepath.Join(configDir(), "router-password") }

func loadRouterConfig() (*routerConfig, string, error) {
	data, err := os.ReadFile(routerConfigPath())
	if err != nil {
		return nil, "", err
	}
	var c routerConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, "", err
	}
	if routerTypes[c.Type] == "" {
		return nil, "", fmt.Errorf("unknown router type %q in %s", c.Type, routerConfigPath())
	}
	pw, err := os.ReadFile(routerPasswordPath())
	if err != nil {
		return nil, "", errors.New("router password missing: run yaklite router setup again")
	}
	return &c, strings.TrimRight(string(pw), "\r\n"), nil
}

type routerDevice struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type routerAPI interface {
	devices(ctx context.Context) ([]routerDevice, error)
	logs(ctx context.Context) ([]string, error)
	settings(ctx context.Context) ([]*Finding, error)
}

// routerBase turns the configured address into a base URL.
func routerBase(c *routerConfig) (*url.URL, error) {
	addr := c.Address
	if !strings.Contains(addr, "://") {
		switch c.Type {
		case "fritzbox":
			if !strings.Contains(addr, ":") {
				addr += ":49000"
			}
			addr = "http://" + addr
		default:
			addr = "https://" + addr
		}
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("bad router address %q", c.Address)
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		ips, err := net.LookupIP(u.Hostname())
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("cannot find the router %q: %v", u.Hostname(), err)
		}
		ip = ips[0]
	}
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return nil, fmt.Errorf("the router address %s is not on your home network; yaklite only logs in to a router on your own network", ip)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// routerHTTP is a client that only accepts the pinned certificate (or a
// normally valid one when nothing is pinned) and never uses a proxy.
func routerHTTP(pin string) *http.Client {
	tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
	if pin != "" {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // replaced by the pin check below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("router sent no certificate")
				}
				sum := sha256.Sum256(raw[0])
				if hex.EncodeToString(sum[:]) != pin {
					return errors.New("the router's certificate changed since setup; if you did not reset or replace the router, someone may be intercepting. Run yaklite router setup again to accept the new one")
				}
				return nil
			},
		}
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: tr, Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func newRouterAPI(c *routerConfig, password string) (routerAPI, error) {
	base, err := routerBase(c)
	if err != nil {
		return nil, err
	}
	hc := routerHTTP(c.CertSHA256)
	switch c.Type {
	case "openwrt":
		return &openwrtAPI{hc: hc, base: base.String(), user: orStr(c.User, "root"), pass: password}, nil
	case "mikrotik":
		return &mikrotikAPI{hc: hc, base: base.String(), user: orStr(c.User, "admin"), pass: password}, nil
	case "fritzbox":
		return &fritzAPI{hc: hc, base: base.String(), user: c.User, pass: password}, nil
	case "unifi":
		return &unifiAPI{hc: hc, base: base.String(), user: c.User, pass: password, site: orStr(c.Site, "default")}, nil
	}
	return nil, fmt.Errorf("unknown router type %q", c.Type)
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func readLimited(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("the router refused the login (check the user name and password: yaklite router setup)")
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("router answered %s", resp.Status)
	}
	return data, nil
}

// ---- OpenWrt (ubus over HTTP) ----

type openwrtAPI struct {
	hc               *http.Client
	base, user, pass string
	sid              string
}

func (o *openwrtAPI) rawCall(ctx context.Context, sid, obj, method string, args any) (json.RawMessage, error) {
	if args == nil {
		args = map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "call", "params": []any{sid, obj, method, args}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/ubus", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.hc.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := readLimited(resp)
	if err != nil {
		return nil, err
	}
	return parseUbus(data)
}

// parseUbus unwraps {"result":[0,{...}]}.
func parseUbus(data []byte) (json.RawMessage, error) {
	var r struct {
		Result []json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unexpected answer from the router: %v", err)
	}
	if r.Error != nil {
		return nil, errors.New("router: " + r.Error.Message)
	}
	if len(r.Result) == 0 {
		return nil, errors.New("router: empty answer")
	}
	var code int
	json.Unmarshal(r.Result[0], &code)
	switch code {
	case 0:
	case 6:
		return nil, errors.New("router: permission denied (log in as root, or give this user access)")
	default:
		return nil, fmt.Errorf("router: ubus error %d", code)
	}
	if len(r.Result) < 2 {
		return json.RawMessage("{}"), nil
	}
	return r.Result[1], nil
}

func (o *openwrtAPI) call(ctx context.Context, obj, method string, args any) (json.RawMessage, error) {
	if o.sid == "" {
		res, err := o.rawCall(ctx, "00000000000000000000000000000000", "session", "login", map[string]string{"username": o.user, "password": o.pass})
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				return nil, errors.New("the router refused the login (check the user name and password: yaklite router setup)")
			}
			return nil, err
		}
		var s struct {
			SID string `json:"ubus_rpc_session"`
		}
		json.Unmarshal(res, &s)
		if s.SID == "" {
			return nil, errors.New("the router refused the login")
		}
		o.sid = s.SID
	}
	return o.rawCall(ctx, o.sid, obj, method, args)
}

func (o *openwrtAPI) devices(ctx context.Context) ([]routerDevice, error) {
	res, err := o.call(ctx, "luci-rpc", "getDHCPLeases", nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		Leases []struct {
			Hostname string `json:"hostname"`
			IP       string `json:"ipaddr"`
			MAC      string `json:"macaddr"`
		} `json:"dhcp_leases"`
	}
	json.Unmarshal(res, &r)
	var out []routerDevice
	for _, l := range r.Leases {
		out = append(out, routerDevice{IP: l.IP, MAC: strings.ToLower(l.MAC), Name: l.Hostname, Active: true})
	}
	return out, nil
}

func (o *openwrtAPI) logs(ctx context.Context) ([]string, error) {
	res, err := o.call(ctx, "log", "read", map[string]any{"lines": 300, "stream": false, "oneshot": true})
	if err == nil {
		var r struct {
			Log []struct {
				Msg string `json:"msg"`
			} `json:"log"`
		}
		json.Unmarshal(res, &r)
		var out []string
		for _, l := range r.Log {
			out = append(out, l.Msg)
		}
		return out, nil
	}
	res, err2 := o.call(ctx, "file", "exec", map[string]any{"command": "/sbin/logread", "params": []string{"-l", "300"}})
	if err2 != nil {
		return nil, err
	}
	var r struct {
		Stdout string `json:"stdout"`
	}
	json.Unmarshal(res, &r)
	return strings.Split(strings.TrimSpace(r.Stdout), "\n"), nil
}

func (o *openwrtAPI) settings(ctx context.Context) ([]*Finding, error) {
	var out []*Finding
	if res, err := o.call(ctx, "uci", "get", map[string]string{"config": "firewall"}); err == nil {
		out = append(out, openwrtFirewallFindings(res)...)
	}
	if res, err := o.call(ctx, "uci", "get", map[string]string{"config": "upnpd"}); err == nil {
		var r struct {
			Values map[string]map[string]any `json:"values"`
		}
		json.Unmarshal(res, &r)
		for _, sec := range r.Values {
			if fmt.Sprint(sec["enabled"]) == "1" || fmt.Sprint(sec["enable_upnp"]) == "1" {
				out = append(out, &Finding{ID: "router:upnp-on", Severity: sevLow,
					Title: "UPnP is on in the router, so any device at home can open ports to the internet",
					Fix:   "Turn it off in LuCI under Services > UPnP unless a game console or app needs it."})
				break
			}
		}
	}
	return out, nil
}

// openwrtFirewallFindings flags a WAN zone that accepts incoming connections.
func openwrtFirewallFindings(res json.RawMessage) []*Finding {
	var r struct {
		Values map[string]map[string]any `json:"values"`
	}
	json.Unmarshal(res, &r)
	for _, sec := range r.Values {
		if fmt.Sprint(sec[".type"]) != "zone" || fmt.Sprint(sec["name"]) != "wan" {
			continue
		}
		if in := strings.ToUpper(fmt.Sprint(sec["input"])); in == "ACCEPT" {
			return []*Finding{{ID: "router:wan-accept", Severity: sevHigh,
				Title: "The router's firewall accepts connections from the internet to the router itself",
				Fix:   "In LuCI, Network > Firewall, set the wan zone's Input to reject."}}
		}
	}
	return nil
}

// ---- MikroTik (RouterOS 7 REST) ----

type mikrotikAPI struct {
	hc               *http.Client
	base, user, pass string
}

func (m *mikrotikAPI) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+"/rest"+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(m.user, m.pass)
	resp, err := m.hc.Do(req)
	if err != nil {
		return err
	}
	data, err := readLimited(resp)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (m *mikrotikAPI) devices(ctx context.Context) ([]routerDevice, error) {
	var leases []map[string]string
	if err := m.get(ctx, "/ip/dhcp-server/lease", &leases); err != nil {
		return nil, err
	}
	var out []routerDevice
	for _, l := range leases {
		out = append(out, routerDevice{IP: l["address"], MAC: strings.ToLower(l["mac-address"]), Name: orStr(l["comment"], l["host-name"]), Active: l["status"] == "bound"})
	}
	return out, nil
}

func (m *mikrotikAPI) logs(ctx context.Context) ([]string, error) {
	var entries []map[string]string
	if err := m.get(ctx, "/log", &entries); err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		out = append(out, e["topics"]+" "+e["message"])
	}
	if len(out) > 500 {
		out = out[len(out)-500:]
	}
	return out, nil
}

func (m *mikrotikAPI) settings(ctx context.Context) ([]*Finding, error) {
	var services []map[string]string
	if err := m.get(ctx, "/ip/service", &services); err != nil {
		return nil, err
	}
	out := mikrotikServiceFindings(services)
	var upnp map[string]string
	if m.get(ctx, "/ip/upnp", &upnp) == nil && upnp["enabled"] == "true" {
		out = append(out, &Finding{ID: "router:upnp-on", Severity: sevLow,
			Title: "UPnP is on in the router, so any device at home can open ports to the internet",
			Fix:   "Turn it off under IP > UPnP unless a game console or app needs it."})
	}
	return out, nil
}

func mikrotikServiceFindings(services []map[string]string) []*Finding {
	var out []*Finding
	var plain []string
	for _, s := range services {
		if s["disabled"] == "true" {
			continue
		}
		switch s["name"] {
		case "telnet", "ftp", "www", "api":
			if s["address"] == "" {
				plain = append(plain, s["name"])
			}
		}
	}
	if len(plain) > 0 {
		sort.Strings(plain)
		out = append(out, &Finding{ID: "router:mikrotik-plain-services", Severity: sevMedium,
			Title:  "The router offers admin services without encryption, open to any address: " + strings.Join(plain, ", "),
			Detail: "These send the admin password readably over the network.",
			Fix:    "Under IP > Services, disable telnet, ftp, www and api (keep ssh, www-ssl and api-ssl), or limit them to your home network in \"Available From\"."})
	}
	return out
}

// ---- Fritz!Box (TR-064) ----

type fritzAPI struct {
	hc               *http.Client
	base, user, pass string
	digest           *digestChallenge
}

type digestChallenge struct {
	realm, nonce, qop, opaque string
	nc                        int
}

func parseDigest(h string) *digestChallenge {
	if !strings.HasPrefix(strings.ToLower(h), "digest ") {
		return nil
	}
	d := &digestChallenge{}
	for _, part := range splitAuthParams(h[7:]) {
		k, v, _ := strings.Cut(part, "=")
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "realm":
			d.realm = v
		case "nonce":
			d.nonce = v
		case "qop":
			d.qop = v
		case "opaque":
			d.opaque = v
		}
	}
	if d.nonce == "" {
		return nil
	}
	return d
}

// splitAuthParams splits on commas outside quotes.
func splitAuthParams(s string) []string {
	var out []string
	inQ := false
	start := 0
	for i, r := range s {
		switch r {
		case '"':
			inQ = !inQ
		case ',':
			if !inQ {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (d *digestChallenge) header(user, pass, method, uri string) string {
	d.nc++
	ha1 := md5hex(user + ":" + d.realm + ":" + pass)
	ha2 := md5hex(method + ":" + uri)
	b := make([]byte, 8)
	rand.Read(b)
	cnonce := hex.EncodeToString(b)
	nc := fmt.Sprintf("%08x", d.nc)
	h := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s"`, user, d.realm, d.nonce, uri)
	if strings.Contains(d.qop, "auth") {
		resp := md5hex(ha1 + ":" + d.nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
		h += fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s", response="%s"`, nc, cnonce, resp)
	} else {
		h += fmt.Sprintf(`, response="%s"`, md5hex(ha1+":"+d.nonce+":"+ha2))
	}
	if d.opaque != "" {
		h += fmt.Sprintf(`, opaque="%s"`, d.opaque)
	}
	return h
}

func (f *fritzAPI) soap(ctx context.Context, control, service, action string) (map[string]string, error) {
	body := `<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + service + `"></u:` + action + `></s:Body></s:Envelope>`
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.base+control, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
		req.Header.Set("SOAPAction", service+"#"+action)
		if f.digest != nil {
			req.Header.Set("Authorization", f.digest.header(f.user, f.pass, http.MethodPost, control))
		}
		resp, err := f.hc.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			d := parseDigest(resp.Header.Get("WWW-Authenticate"))
			resp.Body.Close()
			if d == nil {
				return nil, errors.New("the Fritz!Box asked for a login yaklite does not understand")
			}
			f.digest = d
			continue
		}
		data, err := readLimited(resp)
		if err != nil {
			return nil, err
		}
		return soapValues(data), nil
	}
	return nil, errors.New("the router refused the login (check the user name and password: yaklite router setup)")
}

func (f *fritzAPI) devices(ctx context.Context) ([]routerDevice, error) {
	v, err := f.soap(ctx, "/upnp/control/hosts", "urn:dslforum-org:service:Hosts:1", "X_AVM-DE_GetHostListPath")
	if err != nil {
		return nil, err
	}
	p := v["NewX_AVM-DE_HostListPath"]
	if !strings.HasPrefix(p, "/") {
		return nil, errors.New("the Fritz!Box did not give a device list")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+p, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := readLimited(resp)
	if err != nil {
		return nil, err
	}
	return parseFritzHosts(data)
}

func parseFritzHosts(data []byte) ([]routerDevice, error) {
	var l struct {
		Items []struct {
			IP     string `xml:"IPAddress"`
			MAC    string `xml:"MACAddress"`
			Name   string `xml:"HostName"`
			Active string `xml:"Active"`
		} `xml:"Item"`
	}
	if err := xml.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	var out []routerDevice
	for _, it := range l.Items {
		if it.MAC == "" {
			continue
		}
		out = append(out, routerDevice{IP: it.IP, MAC: strings.ToLower(it.MAC), Name: it.Name, Active: it.Active == "1"})
	}
	return out, nil
}

func (f *fritzAPI) logs(ctx context.Context) ([]string, error) {
	v, err := f.soap(ctx, "/upnp/control/deviceinfo", "urn:dslforum-org:service:DeviceInfo:1", "GetDeviceLog")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(v["NewDeviceLog"]), "\n")
	// newest first on a Fritz!Box; analysis does not care about order
	return lines, nil
}

func (f *fritzAPI) settings(ctx context.Context) ([]*Finding, error) {
	var out []*Finding
	if v, err := f.soap(ctx, "/upnp/control/x_remote", "urn:dslforum-org:service:X_AVM-DE_RemoteAccess:1", "GetInfo"); err == nil && v["NewEnabled"] == "1" {
		out = append(out, &Finding{ID: "router:fritz-remote", Severity: sevMedium,
			Title: "The Fritz!Box can be managed from the internet",
			Fix:   "If you do not use it, turn it off under Internet > Permit Access > FRITZ!Box Services. If you do, use a long password and two-factor confirmation."})
	}
	return out, nil
}

// ---- UniFi ----

type unifiAPI struct {
	hc                     *http.Client
	base, user, pass, site string
	prefix, csrf           string
	loggedIn               bool
}

func (u *unifiAPI) login(ctx context.Context) error {
	if u.loggedIn {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"username": u.user, "password": u.pass, "remember": false})
	try := func(path, prefix string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.base+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := u.hc.Do(req)
		if err != nil {
			return err
		}
		if _, err := readLimited(resp); err != nil {
			return err
		}
		u.prefix, u.csrf, u.loggedIn = prefix, resp.Header.Get("X-Csrf-Token"), true
		return nil
	}
	if err := try("/api/auth/login", "/proxy/network"); err == nil {
		return nil
	}
	return try("/api/login", "")
}

func (u *unifiAPI) get(ctx context.Context, path string) ([]map[string]any, error) {
	if err := u.login(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.base+u.prefix+"/api/s/"+url.PathEscape(u.site)+path, nil)
	if err != nil {
		return nil, err
	}
	if u.csrf != "" {
		req.Header.Set("X-Csrf-Token", u.csrf)
	}
	resp, err := u.hc.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := readLimited(resp)
	if err != nil {
		return nil, err
	}
	var r struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return r.Data, nil
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func (u *unifiAPI) devices(ctx context.Context) ([]routerDevice, error) {
	rows, err := u.get(ctx, "/stat/sta")
	if err != nil {
		return nil, err
	}
	var out []routerDevice
	for _, r := range rows {
		out = append(out, routerDevice{IP: str(r, "ip"), MAC: strings.ToLower(str(r, "mac")), Name: orStr(str(r, "name"), str(r, "hostname")), Active: true})
	}
	return out, nil
}

func (u *unifiAPI) logs(ctx context.Context) ([]string, error) {
	rows, err := u.get(ctx, "/stat/event?_limit=300")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		out = append(out, str(r, "key")+" "+str(r, "msg"))
	}
	return out, nil
}

func (u *unifiAPI) settings(ctx context.Context) ([]*Finding, error) {
	rows, err := u.get(ctx, "/stat/alarm?archived=false")
	if err != nil {
		return nil, err
	}
	var out []*Finding
	for _, r := range rows {
		msg := str(r, "msg")
		if msg == "" {
			continue
		}
		sev := sevMedium
		if strings.Contains(strings.ToLower(str(r, "key")), "ips") || strings.Contains(strings.ToLower(msg), "threat") {
			sev = sevHigh
		}
		out = append(out, &Finding{ID: "router:unifi-alarm:" + shortHash(str(r, "_id")+msg), Severity: sev,
			Title: "UniFi alarm: " + trunc(msg, 200),
			Fix:   "Open the UniFi app to see the details, then archive the alarm once handled."})
	}
	return out, nil
}

// ---- the check ----

type routerDeviceState struct {
	Devices map[string]routerDeviceSeen `json:"devices"` // by MAC
	Lines   map[string]time.Time        `json:"lines"`   // log lines already read, by hash
	Events  []routerEvent               `json:"events"`  // the last day's events
}

type routerDeviceSeen struct {
	Name  string    `json:"name"`
	IP    string    `json:"ip"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

func routerCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	cfg, pass, err := loadRouterConfig()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // not set up
	}
	if err != nil {
		return nil, err
	}
	if env.net == nil || env.net.ID() != cfg.Network {
		return nil, nil // set up on another network
	}
	api, err := newRouterAPI(cfg, pass)
	if err != nil {
		return nil, err
	}
	var threats *threatSet
	if env.opts == nil || env.opts.threatLists {
		threats, _ = loadThreats(ctx, env.stateDir, false)
	}
	return routerFindings(ctx, api, env.stateDir, threats, time.Now(), env.warn)
}

func routerFindings(ctx context.Context, api routerAPI, stateDir string, threats *threatSet, now time.Time, warn func(string)) ([]*Finding, error) {
	p := filepath.Join(stateDir, "router-api.json")
	st := routerDeviceState{Devices: map[string]routerDeviceSeen{}, Lines: map[string]time.Time{}}
	first := true
	if data, err := os.ReadFile(p); err == nil && json.Unmarshal(data, &st) == nil {
		first = false
		if st.Devices == nil {
			st.Devices = map[string]routerDeviceSeen{}
		}
		if st.Lines == nil {
			st.Lines = map[string]time.Time{}
		}
	}
	var out []*Finding
	ok := false
	if devs, err := api.devices(ctx); err != nil {
		warn("router device list: " + err.Error())
	} else {
		ok = true
		for _, d := range devs {
			if d.MAC == "" {
				continue
			}
			seen, known := st.Devices[d.MAC]
			if !known {
				seen.First = now
				if !first {
					name := orStr(d.Name, "a device with no name")
					out = append(out, &Finding{ID: "router:new-device:" + d.MAC, Severity: sevLow, Host: d.IP, Until: now.Add(24 * time.Hour),
						Title:  fmt.Sprintf("New device joined your network: %s (%s, %s)", name, d.IP, d.MAC),
						Detail: "Your router's device list has a device it has not had before.",
						Fix:    fmt.Sprintf("If you know it, name it (yaklite name %s \"Name\"). If not, block it in the router and change the Wi-Fi password.", d.MAC)})
				}
			}
			seen.Name, seen.IP, seen.Last = orStr(d.Name, seen.Name), d.IP, now
			st.Devices[d.MAC] = seen
		}
	}
	if lines, err := api.logs(ctx); err != nil {
		warn("router log: " + err.Error())
	} else {
		ok = true
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			h := shortHash(line)
			if _, done := st.Lines[h]; done {
				continue
			}
			st.Lines[h] = now
			if ev := parseRouterLine(line, now, ""); ev != nil {
				st.Events = append(st.Events, *ev)
			}
		}
	}
	// keep a day of events and a week of line hashes
	var keep []routerEvent
	for _, ev := range st.Events {
		if now.Sub(ev.Time) < 24*time.Hour {
			keep = append(keep, ev)
		}
	}
	st.Events = keep
	for h, t := range st.Lines {
		if now.Sub(t) > 7*24*time.Hour {
			delete(st.Lines, h)
		}
	}
	if !first {
		out = append(out, analyzeRouterEvents(st.Events, now, threats)...)
	}
	if fs, err := api.settings(ctx); err != nil {
		warn("router settings: " + err.Error())
	} else {
		ok = true
		out = append(out, fs...)
	}
	if data, err := json.Marshal(st); err == nil {
		writeFilePrivate(p, data)
	}
	if !ok {
		return out, errors.New("could not read anything from the router")
	}
	return out, nil
}

// ---- yaklite router ----

func cmdRouter(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: yaklite router setup --type openwrt|mikrotik|fritzbox|unifi [--address 192.168.1.1] [--user NAME] | test | forget")
	}
	switch args[0] {
	case "setup":
		return routerSetup(ctx, args[1:])
	case "test":
		return routerTest(ctx)
	case "forget":
		os.Remove(routerConfigPath())
		os.Remove(routerPasswordPath())
		fmt.Println("Router login removed.")
		return nil
	}
	return fmt.Errorf("unknown router command %q (setup, test, forget)", args[0])
}

func routerSetup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("router setup", flag.ExitOnError)
	typ := fs.String("type", "", "router type: openwrt, mikrotik, fritzbox or unifi")
	addr := fs.String("address", "", "the router's address (default: this network's router)")
	user := fs.String("user", "", "admin user name (OpenWrt: root, MikroTik: admin, Fritz!Box: leave empty unless you set one)")
	site := fs.String("site", "default", "UniFi site name")
	fs.Parse(args)
	if routerTypes[*typ] == "" {
		var names []string
		for k, v := range routerTypes {
			names = append(names, "  "+k+": "+v)
		}
		sort.Strings(names)
		return fmt.Errorf("--type must be one of:\n%s", strings.Join(names, "\n"))
	}
	n, err := currentNetwork(ctx)
	if err != nil {
		return fmt.Errorf("cannot tell which network this is: %w", err)
	}
	nf, _ := loadNetworks()
	if k := nf.Networks[n.ID()]; k == nil || !k.Trusted {
		return errors.New("set up the router from your own network: run yaklite trust first")
	}
	if *addr == "" {
		*addr = n.Gateway
	}
	cfg := &routerConfig{Type: *typ, Address: *addr, User: *user, Network: n.ID()}
	if *typ == "unifi" {
		cfg.Site = *site
		if cfg.User == "" {
			return errors.New("UniFi needs --user (a local account on the console)")
		}
	}
	base, err := routerBase(cfg)
	if err != nil {
		return err
	}
	if base.Scheme == "https" {
		fp, err := fetchCertFingerprint(ctx, base.Host)
		if err != nil {
			return fmt.Errorf("cannot reach the router over HTTPS at %s: %w", base.Host, err)
		}
		cfg.CertSHA256 = fp
		fmt.Printf("The router's certificate fingerprint is %s…; yaklite will only talk to this certificate.\n", fp[:16])
	}
	fmt.Fprint(os.Stderr, "Router admin password (not shown): ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		// not a terminal: read a line
		r := bufio.NewReader(os.Stdin)
		line, _ := r.ReadString('\n')
		pw = []byte(strings.TrimRight(line, "\r\n"))
	}
	if len(pw) == 0 {
		return errors.New("no password given")
	}
	api, err := newRouterAPI(cfg, string(pw))
	if err != nil {
		return err
	}
	tctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	devs, err := api.devices(tctx)
	if err != nil {
		return fmt.Errorf("could not log in to the router: %w", err)
	}
	os.MkdirAll(configDir(), 0o700)
	data, _ := yaml.Marshal(cfg)
	if err := writeFilePrivate(routerConfigPath(), append([]byte("# yaklite router login (the password is in router-password)\n"), data...)); err != nil {
		return err
	}
	if err := writeFilePrivate(routerPasswordPath(), append(pw, '\n')); err != nil {
		return err
	}
	fmt.Printf("Connected: the router lists %d device(s). yaklite now reads its device list, log and settings with each check.\n", len(devs))
	fmt.Println("Tip: a separate admin account with read-only rights is safer than the main one, where the router supports it.")
	return nil
}

func fetchCertFingerprint(ctx context.Context, host string) (string, error) {
	if !strings.Contains(host, ":") || strings.HasSuffix(host, "]") {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true}} // only to read the certificate to pin
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate")
	}
	return certFingerprint(certs[0]), nil
}

func routerTest(ctx context.Context) error {
	cfg, pass, err := loadRouterConfig()
	if err != nil {
		return fmt.Errorf("no router set up (yaklite router setup): %w", err)
	}
	api, err := newRouterAPI(cfg, pass)
	if err != nil {
		return err
	}
	devs, err := api.devices(ctx)
	if err != nil {
		fmt.Println("Device list: failed:", err)
	} else {
		fmt.Printf("Device list: %d device(s)\n", len(devs))
		for _, d := range devs {
			fmt.Printf("  %-15s %-17s %s\n", d.IP, d.MAC, d.Name)
		}
	}
	lines, err := api.logs(ctx)
	if err != nil {
		fmt.Println("Log: failed:", err)
	} else {
		n := 0
		for _, l := range lines {
			if parseRouterLine(l, time.Now(), "") != nil {
				n++
			}
		}
		fmt.Printf("Log: %d line(s), %d worth looking at\n", len(lines), n)
	}
	fs, err := api.settings(ctx)
	if err != nil {
		fmt.Println("Settings: failed:", err)
	} else if len(fs) == 0 {
		fmt.Println("Settings: nothing to fix")
	} else {
		for _, f := range fs {
			fmt.Printf("Settings: [%s] %s\n", strings.ToUpper(f.Severity), f.Title)
		}
	}
	return nil
}
