package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRouterLogLines(t *testing.T) {
	now := time.Now()
	ev := parseRouterLine("<30>Oct 14 10:00:01 router httpd: login failed for user admin from 203.0.113.9", now, "192.168.1.1")
	if ev == nil || ev.Kind != "login-fail" || ev.IP.String() != "203.0.113.9" {
		t.Fatalf("login failure: %+v", ev)
	}
	if parseRouterLine("dnsmasq-dhcp: DHCPACK(br-lan) 192.168.1.20 aa:bb:cc:dd:ee:ff phone", now, "") != nil {
		t.Error("an ordinary line was flagged")
	}
	var evs []routerEvent
	for i := 0; i < 4; i++ {
		evs = append(evs, *parseRouterLine("login failed from 203.0.113.9", now, ""))
	}
	evs = append(evs, *parseRouterLine("admin login success from 198.51.100.7", now, ""))
	fs := analyzeRouterEvents(evs, now, nil)
	var fail, pub bool
	for _, f := range fs {
		fail = fail || strings.Contains(f.ID, "203.0.113.9")
		pub = pub || (f.Severity == sevHigh && strings.Contains(f.Title, "logged in"))
	}
	if !fail || !pub {
		t.Errorf("router events: %+v", fs)
	}
}

func TestTripwire(t *testing.T) {
	ports, err := parsePorts("23, 445,8080")
	if err != nil || len(ports) != 3 || ports[1] != 445 {
		t.Fatalf("parsePorts: %v %v", ports, err)
	}
	if _, err := parsePorts("70000"); err == nil {
		t.Error("a port above 65535 was accepted")
	}
	now := time.Now()
	hits := []tripHit{{now, "192.168.1.50", 23}, {now, "192.168.1.50", 445}, {now, "192.168.1.10", 23}, {now, "127.0.0.1", 23}}
	fs := tripFindings(hits, map[string]bool{"192.168.1.10": true}, now)
	if len(fs) != 1 || fs[0].Host != "192.168.1.50" {
		t.Fatalf("tripwire findings should only name the stranger: %+v", fs)
	}
}

func TestFirewallRules(t *testing.T) {
	ts := &threatSet{ips: map[string]string{"203.0.113.9": "x", "1.1.1.1": "x", "2001:db8::1": "x"}}
	v4, v6 := blockEntries(ts)
	for _, a := range v4 {
		if a == "1.1.1.1" {
			t.Error("a public DNS server must never be blocked")
		}
	}
	if len(v4) != 1 || len(v6) != 1 {
		t.Errorf("entries: %v %v", v4, v6)
	}
	nft := nftScript(v4, v6)
	if !strings.Contains(nft, "table inet yaklite") || !strings.Contains(nft, "203.0.113.9") {
		t.Errorf("nft:\n%s", nft)
	}
	if !strings.Contains(pfRules("yaklite_bad"), "<yaklite_bad>") {
		t.Error("pf rules")
	}
	many := make([]string, 2500)
	for i := range many {
		many[i] = "203.0.113.1"
	}
	if w := windowsRules(many); strings.Count(w, "New-NetFirewallRule")+strings.Count(w, "netsh") < 3 {
		t.Errorf("windows rules should be split into groups of 1000:\n%.300s", w)
	}
}

func TestPrivateDNSProfile(t *testing.T) {
	p := dnsProviders["quad9"]
	mc := mobileConfig("quad9", p)
	if !strings.Contains(mc, "com.apple.dnsSettings.managed") || !strings.Contains(mc, p.url) {
		t.Errorf("profile:\n%s", mc)
	}
	if uuidFrom("a") == uuidFrom("b") || len(uuidFrom("a")) != 36 {
		t.Error("uuid")
	}
	if !strings.Contains(resolvedDropIn(p), "DNSOverTLS=yes") {
		t.Errorf("resolved:\n%s", resolvedDropIn(p))
	}
}

func TestHostWatchParsers(t *testing.T) {
	px := parseScutilProxy("<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 10.0.0.5\n  HTTPPort : 8080\n  HTTPSEnable : 0\n}")
	if len(px) != 1 || !strings.Contains(px[0], "10.0.0.5") {
		t.Errorf("proxy: %v", px)
	}
	if !suspiciousPath("/tmp/x") || suspiciousPath("/Applications/Safari.app/Contents/MacOS/Safari") {
		t.Error("suspiciousPath")
	}
	log := strings.Repeat("sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n", 6) + "sshd[1]: Failed password for root from 192.168.1.4 port 22 ssh2\n"
	fs := failedLoginsFrom(log, time.Now())
	if len(fs) != 1 || fs[0].Severity != sevHigh {
		t.Errorf("failed logins: %+v", fs)
	}
	items := []hostItem{{Cat: "startup", Key: "a", Label: "A"}, {Cat: "cert", Key: "c", Label: "Root CA"}}
	base := &hostBaseline{Items: map[string]bool{items[0].id(): true}, Review: map[string]bool{}}
	fs = hostFindings(items, base)
	if len(fs) != 1 || !strings.Contains(fs[0].ID, "host:cert") {
		t.Errorf("only the new certificate should be reported: %+v", fs)
	}
}

func TestWindowsParsers(t *testing.T) {
	ns := "  Proto  Local Address          Foreign Address        State           PID\r\n  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\r\n  TCP    192.168.1.5:50000      203.0.113.9:443        ESTABLISHED     1234\r\n"
	socks := parseWindowsNetstat(ns)
	if len(socks) != 2 || socks[0].LocalPort != 445 || socks[1].PID != 1234 {
		t.Errorf("netstat: %+v", socks)
	}
	tl := parseTasklist(`"System","4","Services","0","144 K"` + "\r\n" + `"chrome.exe","1234","Console","1","200,000 K"` + "\r\n")
	if tl[1234] != "chrome.exe" {
		t.Errorf("tasklist: %v", tl)
	}
	if winArg(`C:\Program Files\yaklite\yaklite.exe`) != `"C:\Program Files\yaklite\yaklite.exe"` || winArg("auto") != "auto" || winArg(`a"b`) != `"a\"b"` {
		t.Error("winArg")
	}
	if psQuote("it's") != "'it''s'" {
		t.Error("psQuote")
	}
	j := jobArgs{auto: []string{"auto", "-q"}, web: []string{"serve"}, conn: []string{"connwatch"}, summary: []string{"summary", "--send"}}
	tasks := windowsTasks(j, map[string]bool{agentLabel: true, webLabel: true, summaryLabel: true}, time.Hour)
	script := windowsInstallScript(`C:\Users\a b\yaklite.exe`, tasks)
	if !strings.Contains(script, `'--headless "C:\Users\a b\yaklite.exe" auto -q'`) || !strings.Contains(script, "-Minutes 60") || !strings.Contains(script, "-DaysOfWeek Monday") {
		t.Errorf("install script:\n%s", script)
	}
	if strings.Contains(script, "connwatch") {
		t.Error("an unwanted job was registered")
	}
	run := func(_ context.Context, name string, args ...string) string {
		switch {
		case name == "netsh":
			return "Domain Profile Settings:\r\n----\r\nState                                 ON\r\n\r\nPublic Profile Settings:\r\nState                                 OFF\r\n"
		case name == "powershell" && strings.Contains(strings.Join(args, " "), "Get-MpComputerStatus"):
			return "False|Normal|1"
		case name == "reg" && strings.Contains(strings.Join(args, " "), "EnableLUA"):
			return "\r\nHKEY_LOCAL_MACHINE\\...\r\n    EnableLUA    REG_DWORD    0x0\r\n"
		}
		return ""
	}
	ids := map[string]bool{}
	for _, f := range windowsSelfCheck(context.Background(), run) {
		ids[f.ID] = true
	}
	if !ids["self:firewall-off"] || !ids["self:defender-off"] || !ids["self:uac-off"] || ids["self:rdp-on"] {
		t.Errorf("windows self check: %v", ids)
	}
	if _, mode, _, ok := parseDefender("True|Passive|0"); !ok || mode != "Passive" {
		t.Error("parseDefender")
	}
}

func TestSecurityScore(t *testing.T) {
	snap := NewSnapshot("home", "", "auto")
	snap.addFinding(&Finding{ID: "a", Severity: sevHigh, Title: "A"})
	snap.addFinding(&Finding{ID: "b", Severity: sevMedium, Title: "B"})
	snap.addFinding(&Finding{ID: "c", Severity: sevLow, Title: "C"})
	states := []*watchState{{Name: "home", Snap: snap}}
	now := time.Now()
	s := computeScore(states, nil, &acksFile{}, now)
	if s.Score != 69 || s.High != 1 || len(s.Top) != 3 || s.Top[0].ID != "a" {
		t.Errorf("score: %+v", s)
	}
	acks := &acksFile{}
	acks.Acks = append(acks.Acks, ack{Key: "a"})
	if s := computeScore(states, nil, acks, now); s.Score != 92 || s.Grade != "Good" {
		t.Errorf("acknowledged problems must not count: %+v", s)
	}
}

func TestOutages(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	if f := trackOutage(dir, false, true, t0); f != nil {
		t.Fatal("alerted while still down")
	}
	if f := trackOutage(dir, false, true, t0.Add(time.Minute)); f != nil {
		t.Fatal("alerted while still down")
	}
	f := trackOutage(dir, true, true, t0.Add(3*time.Minute))
	if f == nil || f.Severity != sevLow {
		t.Fatalf("outage not reported: %+v", f)
	}
	// a short blip is ignored
	trackOutage(dir, false, true, t0.Add(4*time.Minute))
	if f := trackOutage(dir, true, true, t0.Add(4*time.Minute+30*time.Second)); f != nil {
		t.Error("a 30 second blip was reported")
	}
	// off Wi-Fi is not an outage
	trackOutage(dir, false, false, t0.Add(5*time.Minute))
	if f := trackOutage(dir, true, true, t0.Add(8*time.Minute)); f != nil {
		t.Error("being off the network was reported as an outage")
	}
	if len(loadOutages(dir)) != 1 || !strings.Contains(outagesSince(dir, t0.Add(-time.Hour)), "Internet outages: 1") {
		t.Error("outage log")
	}
	if ordSuffix(1) != "st" || ordSuffix(12) != "th" || ordSuffix(23) != "rd" {
		t.Error("ordSuffix")
	}
}

func TestReports(t *testing.T) {
	for u, ok := range map[string]bool{
		"http://192.168.1.10:9842": true, "http://100.101.102.103:9842": true, "https://hub.example.com": true,
		"http://hub.example.com": false, "http://8.8.8.8:9842": false, "ftp://192.168.1.10": false,
	} {
		if (reportURLAllowed(u) == nil) != ok {
			t.Errorf("reportURLAllowed(%s) = %v", u, reportURLAllowed(u))
		}
	}
	dir := t.TempDir()
	post := func(tok string, body any) int {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/report", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		handleReport(dir, "secret-token-123456", w, req)
		return w.Code
	}
	good := computerReport{Name: "Kids laptop", OS: "windows", Findings: []*Finding{{ID: "self:firewall-off", Severity: sevMedium, Title: "Firewall off"}}}
	if c := post("wrong", good); c != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", c)
	}
	if c := post("secret-token-123456", computerReport{Name: "../../etc"}); c != http.StatusBadRequest {
		t.Errorf("bad name: %d", c)
	}
	if c := post("secret-token-123456", good); c != http.StatusNoContent {
		t.Fatalf("good report: %d", c)
	}
	r := &stateReader{dir: dir}
	cs := r.computers(time.Now())
	if len(cs) != 1 || cs[0].Name != "Kids laptop" || len(cs[0].Findings) != 1 {
		t.Errorf("computers: %+v", cs)
	}
}

func TestFixes(t *testing.T) {
	if !strings.Contains(fixFor(Change{Kind: "port_open", Port: 23}), "Telnet") {
		t.Error("telnet fix")
	}
	if !strings.Contains(fixFor(Change{Kind: "port_open", Port: 9999, Outside: true}), "reachable from the internet") {
		t.Error("outside fix")
	}
	if fixFor(Change{Kind: "host_gone"}) != "" {
		t.Error("no fix expected for a device leaving")
	}
}

func TestQuietHours(t *testing.T) {
	if _, _, err := parseClockRange("22:00-07:00"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"22", "25:00-07:00", "22:00-07:61"} {
		if _, _, err := parseClockRange(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	s := alertSettings{Quiet: "22:00-07:00"}
	at := func(h, m int) time.Time { return time.Date(2026, 10, 14, h, m, 0, 0, time.Local) }
	if !s.inQuiet(at(23, 0)) || !s.inQuiet(at(3, 0)) || s.inQuiet(at(7, 0)) || s.inQuiet(at(12, 0)) {
		t.Error("over-midnight quiet hours")
	}
	day := alertSettings{Quiet: "09:00-17:00"}
	if !day.inQuiet(at(10, 0)) || day.inQuiet(at(18, 0)) {
		t.Error("daytime quiet hours")
	}
	changes := []Change{{Kind: "finding", Severity: sevHigh, Host: "a"}, {Kind: "finding", Severity: sevLow, Host: "b"}}
	send, hold := splitForDelivery(s, changes, at(23, 0))
	if len(send) != 1 || send[0].Severity != sevHigh || len(hold) != 1 {
		t.Errorf("quiet: send %v hold %v", send, hold)
	}
	send, hold = splitForDelivery(alertSettings{}, changes, at(23, 0))
	if len(send) != 2 || len(hold) != 0 {
		t.Error("with nothing set everything goes at once")
	}
	g := alertSettings{GroupMinutes: 10}
	held := []heldAlert{{Held: at(12, 0)}}
	if heldReady(g, held, at(12, 5)) || !heldReady(g, held, at(12, 10)) || heldReady(s, held, at(23, 30)) {
		t.Error("heldReady")
	}
}

func TestHeldAlertsFlush(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		b.ReadFrom(r.Body)
		got = append(got, b.String())
	}))
	defer srv.Close()
	os.MkdirAll(configDir(), 0o700)
	if err := os.WriteFile(alertSettingsPath(), []byte("group_minutes: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ac := &alertConfig{webhook: srv.URL, webhookFormat: "json"}
	deliver(context.Background(), ac, dir, []Change{{Kind: "finding", Severity: sevLow, Host: "a", ID: "one", Detail: "one"}})
	deliver(context.Background(), ac, dir, []Change{{Kind: "finding", Severity: sevMedium, Host: "b", ID: "two", Detail: "two"}})
	if len(got) != 0 {
		t.Fatal("grouped alerts were sent at once")
	}
	// age the queue
	held := readHeld(heldPath(dir))
	var buf bytes.Buffer
	for _, h := range held {
		h.Held = h.Held.Add(-2 * time.Minute)
		data, _ := json.Marshal(h)
		buf.Write(append(data, '\n'))
	}
	os.WriteFile(heldPath(dir), buf.Bytes(), 0o600)
	flushHeld(context.Background(), dir)
	if len(got) != 1 {
		t.Fatalf("expected one grouped message, got %d", len(got))
	}
	if _, err := os.Stat(heldPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Error("queue not emptied")
	}
}

type fakeRouter struct {
	devs  []routerDevice
	lines []string
	sets  []*Finding
}

func (f *fakeRouter) devices(context.Context) ([]routerDevice, error) { return f.devs, nil }
func (f *fakeRouter) logs(context.Context) ([]string, error)          { return f.lines, nil }
func (f *fakeRouter) settings(context.Context) ([]*Finding, error)    { return f.sets, nil }

func TestRouterFindings(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRouter{devs: []routerDevice{{IP: "192.168.1.2", MAC: "aa:aa:aa:aa:aa:aa", Name: "phone"}},
		lines: []string{"login failed from 203.0.113.9", "login failed from 203.0.113.9 (2)", "login failed from 203.0.113.9 (3)"}}
	warn := func(string) {}
	now := time.Now()
	fs, err := routerFindings(context.Background(), fr, dir, nil, now, warn)
	if err != nil || len(fs) != 0 {
		t.Fatalf("the first run only records: %+v %v", fs, err)
	}
	fr.devs = append(fr.devs, routerDevice{IP: "192.168.1.66", MAC: "bb:bb:bb:bb:bb:bb", Name: ""})
	fr.lines = append(fr.lines, "login failed from 203.0.113.9 (4)")
	fs, _ = routerFindings(context.Background(), fr, dir, nil, now.Add(time.Minute), warn)
	var newDev, fails bool
	for _, f := range fs {
		newDev = newDev || f.ID == "router:new-device:bb:bb:bb:bb:bb:bb"
		fails = fails || strings.Contains(f.ID, "203.0.113.9")
	}
	if !newDev || !fails {
		t.Errorf("second run: %+v", fs)
	}
	// lines already read are not counted again
	var st routerDeviceState
	data, _ := os.ReadFile(filepath.Join(dir, "router-api.json"))
	json.Unmarshal(data, &st)
	if len(st.Events) != 4 {
		t.Errorf("events: %d", len(st.Events))
	}
}

func TestRouterAPIs(t *testing.T) {
	if _, err := parseUbus([]byte(`{"jsonrpc":"2.0","id":1,"result":[6]}`)); err == nil {
		t.Error("ubus permission error")
	}
	res, err := parseUbus([]byte(`{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"abc"}]}`))
	if err != nil || !strings.Contains(string(res), "abc") {
		t.Error("ubus result")
	}
	fw := json.RawMessage(`{"values":{"cfg03dc81":{".type":"zone","name":"wan","input":"ACCEPT"},"cfg02dc81":{".type":"zone","name":"lan","input":"ACCEPT"}}}`)
	if fs := openwrtFirewallFindings(fw); len(fs) != 1 || fs[0].Severity != sevHigh {
		t.Errorf("openwrt firewall: %+v", fs)
	}
	svc := []map[string]string{{"name": "telnet", "disabled": "false", "address": ""}, {"name": "www-ssl", "disabled": "false"}, {"name": "ftp", "disabled": "true"}, {"name": "www", "disabled": "false", "address": "192.168.88.0/24"}}
	if fs := mikrotikServiceFindings(svc); len(fs) != 1 || !strings.Contains(fs[0].Title, "telnet") || strings.Contains(fs[0].Title, "ftp") || strings.Contains(fs[0].Title, "www") {
		t.Errorf("mikrotik: %+v", fs)
	}
	hosts, err := parseFritzHosts([]byte(`<?xml version="1.0"?><List><Item><Index>1</Index><IPAddress>192.168.178.20</IPAddress><MACAddress>AA:BB:CC:DD:EE:FF</MACAddress><Active>1</Active><HostName>laptop</HostName></Item></List>`))
	if err != nil || len(hosts) != 1 || hosts[0].MAC != "aa:bb:cc:dd:ee:ff" || !hosts[0].Active {
		t.Errorf("fritz hosts: %+v %v", hosts, err)
	}
	d := parseDigest(`Digest realm="HTTPS Access", nonce="ABC123", algorithm=MD5, qop="auth"`)
	if d == nil || d.realm != "HTTPS Access" || d.nonce != "ABC123" {
		t.Fatalf("digest: %+v", d)
	}
	h := d.header("u", "p", "POST", "/upnp/control/hosts")
	if !strings.Contains(h, `nc=00000001`) || !strings.Contains(h, `uri="/upnp/control/hosts"`) {
		t.Errorf("digest header: %s", h)
	}
	if _, err := routerBase(&routerConfig{Type: "openwrt", Address: "8.8.8.8"}); err == nil {
		t.Error("a public router address was accepted")
	}
	u, err := routerBase(&routerConfig{Type: "fritzbox", Address: "192.168.178.1"})
	if err != nil || u.String() != "http://192.168.178.1:49000" {
		t.Errorf("fritz base: %v %v", u, err)
	}
}

func TestOpenWrtAgainstFake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var obj, method string
		json.Unmarshal(req.Params[1], &obj)
		json.Unmarshal(req.Params[2], &method)
		switch obj + "." + method {
		case "session.login":
			w.Write([]byte(`{"result":[0,{"ubus_rpc_session":"s1"}]}`))
		case "luci-rpc.getDHCPLeases":
			w.Write([]byte(`{"result":[0,{"dhcp_leases":[{"hostname":"tv","ipaddr":"192.168.1.30","macaddr":"AA:BB:CC:00:11:22"}]}]}`))
		default:
			w.Write([]byte(`{"result":[2]}`))
		}
	}))
	defer srv.Close()
	o := &openwrtAPI{hc: srv.Client(), base: srv.URL, user: "root", pass: "x"}
	devs, err := o.devices(context.Background())
	if err != nil || len(devs) != 1 || devs[0].MAC != "aa:bb:cc:00:11:22" {
		t.Errorf("openwrt devices: %+v %v", devs, err)
	}
}

func TestBreaches(t *testing.T) {
	n, err := matchPwnedRange(strings.NewReader("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n"), "00d4f6e8fa6eecad2a3aa415eec418d38ec")
	if err != nil || n != 2 {
		t.Errorf("range match: %d %v", n, err)
	}
	if sha1Upper("password")[:5] != "5BAA6" {
		t.Error("sha1")
	}
	catalog := map[string]hibpBreach{"adobe": {Name: "Adobe", Title: "Adobe", Domain: "adobe.com", BreachDate: "2013-10-04", AddedDate: "2013-12-04T00:00:00Z", DataClasses: []string{"Email addresses", "Passwords"}},
		"spam": {Name: "Spam", Title: "Spam list", BreachDate: "2026-01-01", AddedDate: time.Now().UTC().Format("2006-01-02T15:04:05Z"), DataClasses: []string{"Email addresses"}}}
	fs := accountBreachFindings(map[string][]string{"me@example.com": {"Adobe", "Spam"}}, catalog, time.Now())
	if len(fs) != 2 {
		t.Fatalf("breach findings: %+v", fs)
	}
	for _, f := range fs {
		if strings.Contains(f.ID, "spam") && (f.Severity != sevMedium || !strings.Contains(f.Fix, "phishing")) {
			t.Errorf("a leak without passwords: %+v", f)
		}
		if strings.Contains(f.ID, "adobe") && !strings.Contains(f.Fix, "Change the password") {
			t.Errorf("a leak with passwords: %+v", f)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("domain") == "breached.example" {
			w.Write([]byte(`[{"Name":"Ex","Title":"Example","Domain":"breached.example","BreachDate":"2026-09-01","AddedDate":"2026-09-10T00:00:00Z","PwnCount":10,"DataClasses":["Passwords"]}]`))
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	old := hibpBaseURL
	hibpBaseURL = srv.URL
	defer func() { hibpBaseURL = old }()
	t.Setenv("HIBP_API_KEY", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs, errs := breachFindings(context.Background(), []string{"breached.example", "fine.example"})
	if len(errs) != 0 || len(fs) != 1 || fs[0].Severity != sevHigh {
		t.Errorf("site breach: %+v %v", fs, errs)
	}
}

func TestTraffic(t *testing.T) {
	line := []byte(`{"timestamp":"2026-10-14T10:00:00.123456+0200","event_type":"alert","src_ip":"192.168.1.42","dest_ip":"203.0.113.9","dest_port":443,"alert":{"signature":"ET MALWARE Test CnC Beacon","category":"A Network Trojan was detected","severity":1}}`)
	a := parseEve(line)
	if a == nil || a.Severity != 1 || a.Src != "192.168.1.42" {
		t.Fatalf("eve: %+v", a)
	}
	if parseEve([]byte(`{"event_type":"flow"}`)) != nil {
		t.Error("a flow record is not an alert")
	}
	now := a.Time.Add(time.Minute)
	noise := idsAlert{Time: a.Time, Src: "192.168.1.5", Dst: "1.1.1.1", Signature: "ET INFO Observed DNS Query to .cloud TLD", Severity: 3}
	fs := trafficFindings([]idsAlert{*a, *a, noise}, now)
	if len(fs) != 1 || fs[0].Severity != sevHigh || !strings.Contains(fs[0].Title, "2 times") || !strings.Contains(fs[0].Fix, "infected") {
		t.Errorf("traffic findings: %+v", fs)
	}
	// tail picks up appended alerts
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	os.WriteFile(p, nil, 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan idsAlert, 4)
	go tailEve(ctx, p, false, func(a idsAlert) { got <- a })
	time.Sleep(200 * time.Millisecond)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.Write(append(line, '\n'))
	f.Close()
	select {
	case a := <-got:
		if a.Dst != "203.0.113.9" {
			t.Errorf("tailed: %+v", a)
		}
	case <-ctx.Done():
		t.Error("tail did not pick up the new alert")
	}
}

func TestInstallJobs(t *testing.T) {
	u := systemdUnits("/bin/yaklite", jobArgs{auto: []string{"auto"}, conn: []string{"connwatch"}, summary: []string{"summary"}, web: []string{"serve", "--tailscale"}, router: []string{"routerlog", "-q"}, trip: []string{"tripwire", "-q"}}, time.Hour)
	if !strings.Contains(u["yaklite-routerlog.service"], `"routerlog" "-q"`) || !strings.Contains(u["yaklite-web.service"], `"--tailscale"`) {
		t.Errorf("units: %v", u)
	}
	if !isCGNAT(net.ParseIP("100.100.1.1")) || isCGNAT(net.ParseIP("100.128.0.1")) {
		t.Error("isCGNAT")
	}
}
