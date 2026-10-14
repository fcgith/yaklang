package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFindingsReportedOnceAndRemembered(t *testing.T) {
	now := time.Now()
	a := NewSnapshot("x", "", "t")
	a.addFinding(&Finding{ID: "upnp:tcp/3389", Severity: sevHigh, Title: "forwarded"})
	a.addFinding(&Finding{ID: "inbound:1.2.3.4:22", Severity: sevHigh, Title: "inbound", Until: now.Add(time.Hour)})
	first := Annotate(Diff(nil, a, DiffOptions{}, now), nil)
	if len(first) != 2 || first[0].Kind != "finding" || first[0].Severity != sevHigh {
		t.Fatalf("first run: %+v", first)
	}
	b := NewSnapshot("x", "", "t")
	b.addFinding(&Finding{ID: "upnp:tcp/3389", Severity: sevHigh, Title: "forwarded"})
	if ch := Diff(a, b, DiffOptions{}, now); len(ch) != 0 {
		t.Fatalf("an unchanged finding was reported again: %+v", ch)
	}
	if b.Findings["inbound:1.2.3.4:22"] == nil {
		t.Fatal("a finding inside its Until window was not carried forward")
	}
	c := NewSnapshot("x", "", "t")
	ch := Annotate(Diff(b, c, DiffOptions{}, now.Add(2*time.Hour)), nil)
	if len(ch) != 2 || ch[0].Kind != "finding_resolved" || ch[0].Severity != sevInfo {
		t.Fatalf("resolved: %+v", ch)
	}
}

func TestAcks(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := addAck("upnp:*", 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := addAck("port_open:10.0.0.5:tcp/22", time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	ch := []Change{{Kind: "finding", ID: "upnp:tcp/80"}, {Kind: "port_open", Host: "10.0.0.5", Proto: "tcp", Port: 22}, {Kind: "port_open", Host: "10.0.0.6", Proto: "tcp", Port: 22}}
	if got := dropAcked(ch, time.Now()); len(got) != 1 || got[0].Host != "10.0.0.6" {
		t.Errorf("dropAcked: %+v", got)
	}
	if got := dropAcked(ch, time.Now().Add(2*time.Hour)); len(got) != 2 {
		t.Errorf("an expired snooze still applies: %+v", got)
	}
	for in, want := range map[string]time.Duration{"1w": 7 * 24 * time.Hour, "2d": 48 * time.Hour, "12h": 12 * time.Hour, "forever": 0} {
		if d, err := parseDuration(in); err != nil || d != want {
			t.Errorf("parseDuration(%q) = %v, %v", in, d, err)
		}
	}
}

func TestPhoneActionsAreSigned(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	h := ntfyActions("https://ntfy.sh/mytopic", []Change{{Kind: "finding", ID: "upnp:tcp/3389"}})
	if !strings.Contains(h, "https://ntfy.sh/mytopic-actions") || strings.Count(h, "http,") != 3 {
		t.Fatalf("actions header: %s", h)
	}
	body := strings.SplitN(strings.SplitN(h, "body=", 2)[1], ",", 2)[0]
	verb, keys, ok := verifyAction(actionSecret(), body)
	if !ok || verb != "ack" || len(keys) != 1 || keys[0] != "upnp:tcp/3389" {
		t.Errorf("verify %q: %v %v %v", body, verb, keys, ok)
	}
	if _, _, ok := verifyAction(actionSecret(), "ack upnp:* sig=000000000000000000000000"); ok {
		t.Error("a forged action was accepted")
	}
}

func TestProcNetTCP(t *testing.T) {
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0501A8C0:0016 04030201:D431 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 20 4 30 10 -1
`
	s := parseProcNetTCP(data)
	if len(s) != 2 || s[0].State != "LISTEN" || s[0].LocalPort != 22 {
		t.Fatalf("%+v", s)
	}
	if s[1].LocalIP.String() != "192.168.1.5" || s[1].RemoteIP.String() != "1.2.3.4" || s[1].RemotePort != 54321 || s[1].inode() != "12346" {
		t.Errorf("%+v", s[1])
	}
	views := classify(s, &threatSet{ips: map[string]string{"1.2.3.4": "feodo"}})
	if len(views) != 1 || !views[0].Inbound || views[0].Threat != "feodo" {
		t.Errorf("classify: %+v", views)
	}
}

func TestBSDNetstatAndLsof(t *testing.T) {
	ns := `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.5.52345      17.57.146.20.5223      ESTABLISHED
tcp46      0      0  *.22                   *.*                    LISTEN
tcp6       0      0  fe80::1%lo0.1024       *.*                    LISTEN
`
	s := parseBSDNetstat(ns)
	if len(s) != 3 || s[0].RemoteIP.String() != "17.57.146.20" || s[0].RemotePort != 5223 || s[1].LocalPort != 22 || s[1].State != "LISTEN" {
		t.Fatalf("%+v", s)
	}
	owners := parseLsof("p123\ncidentityservicesd\nf5\nn192.168.1.5:52345->17.57.146.20:5223\nTST=ESTABLISHED\n")
	if p, ok := owners[s[0].key()]; !ok || p.name != "identityservicesd" || p.pid != 123 {
		t.Errorf("lsof owners: %+v", owners)
	}
	if v := classify(s, nil); len(v) != 1 || v[0].Inbound {
		t.Errorf("outbound connection classified as %+v", v)
	}
}

func TestIPOwnerLookup(t *testing.T) {
	o, ok := lookupIP(net.ParseIP("1.1.1.1"))
	if !ok || o.ASN != 13335 {
		t.Errorf("1.1.1.1: %+v %v", o, ok)
	}
	if _, ok := lookupIP(net.ParseIP("192.168.1.1")); ok {
		t.Error("a private address has no owner")
	}
	if countryName("DE") != "Germany" {
		t.Error("country names")
	}
}

func TestThreatFeedParsing(t *testing.T) {
	ts := &threatSet{ips: map[string]string{}}
	parseFeed(strings.NewReader("# comment\n203.0.113.9\n10.0.0.1\n0.0.0.0/0\n198.51.100.0/24 ; SBL123\n"), "drop", ts)
	parseFeed(strings.NewReader("#start\tend\tnetblock\n192.0.2.0\t192.0.2.255\t24\t1234\n"), "dshield", ts)
	for ip, want := range map[string]bool{"203.0.113.9": true, "10.0.0.1": false, "8.8.8.8": false, "198.51.100.77": true, "192.0.2.10": true} {
		if _, got := ts.lookup(net.ParseIP(ip)); got != want {
			t.Errorf("%s listed=%v want %v", ip, got, want)
		}
	}
}

func TestEmailAuthAndExpiry(t *testing.T) {
	ids := func(fs []*Finding) string {
		var s []string
		for _, f := range fs {
			s = append(s, f.ID)
		}
		return strings.Join(s, " ")
	}
	if got := ids(judgeEmailAuth("ex.com", "", "")); got != "email:no-spf:ex.com email:no-dmarc:ex.com" {
		t.Errorf("none: %s", got)
	}
	if got := ids(judgeEmailAuth("ex.com", "v=spf1 +all", "v=DMARC1; p=none")); got != "email:spf-allows-all:ex.com email:dmarc-none:ex.com" {
		t.Errorf("weak: %s", got)
	}
	if got := judgeEmailAuth("ex.com", "v=spf1 include:_spf.google.com -all", "v=DMARC1; p=reject"); len(got) != 0 {
		t.Errorf("good config flagged: %s", ids(got))
	}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	d := rdapDomain{}
	d.Events = append(d.Events, struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	}{"expiration", "2026-10-20T00:00:00Z"})
	if f := judgeExpiry("ex.com", d, now); f == nil || f.Severity != sevHigh {
		t.Errorf("10 days left: %+v", f)
	}
	if f := judgeExpiry("ex.com", d, now.AddDate(-1, 0, 0)); f != nil {
		t.Errorf("a year left: %+v", f)
	}
}

func TestLookalikes(t *testing.T) {
	l := lookalikes("www.example.co.uk")
	has := map[string]bool{}
	for _, d := range l {
		has[d] = true
	}
	for _, want := range []string{"exmple.co.uk", "exarnple.co.uk", "example.com", "exampel.co.uk"} {
		if !has[want] {
			t.Errorf("missing %s", want)
		}
	}
	if has["example.co.uk"] {
		t.Error("the domain itself is not a look-alike")
	}
}

func TestNewCertFindings(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	fs := newCertFindings([]ctCert{
		{ID: 1, Issuer: `C=US, O="Let's Encrypt", CN=R11`, Names: "a.ex.com\nex.com", NotBefore: "2026-10-08T10:00:00"},
		{ID: 2, Issuer: "O=Old", Names: "ex.com", NotBefore: "2026-01-01T00:00:00"},
	}, now)
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "Let's Encrypt") || !strings.Contains(fs[0].Title, "a.ex.com, ex.com") {
		t.Errorf("%+v", fs)
	}
}

func TestIGDDescription(t *testing.T) {
	xml := `<?xml version="1.0"?><root><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList></device></root>`
	gs, err := parseIGDDescription("http://192.168.1.1:5000/rootDesc.xml", []byte(xml))
	if err != nil || len(gs) != 1 || gs[0].controlURL != "http://192.168.1.1:5000/ctl/IPConn" {
		t.Fatalf("%+v %v", gs, err)
	}
	evil := strings.Replace(xml, "/ctl/IPConn", "http://169.254.169.254/x", 1)
	if gs, _ := parseIGDDescription("http://192.168.1.1:5000/rootDesc.xml", []byte(evil)); len(gs) != 0 {
		t.Error("a control URL on another host was accepted")
	}
	v := soapValues([]byte(`<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse><NewExternalPort>3389</NewExternalPort><NewInternalClient>192.168.1.20</NewInternalClient></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`))
	if v["NewExternalPort"] != "3389" || v["NewInternalClient"] != "192.168.1.20" {
		t.Errorf("%v", v)
	}
}

func TestDHCPPackets(t *testing.T) {
	xid := [4]byte{1, 2, 3, 4}
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	p := dhcpDiscoverPacket(xid, mac)
	if p[0] != 1 || p[242] != 1 {
		t.Fatalf("discover packet")
	}
	offer := append([]byte{}, p...)
	offer[0] = 2
	offer = append(offer[:240], 53, 1, 2, 54, 4, 192, 168, 1, 1, 255)
	if s := dhcpOfferServer(offer, xid); s != "192.168.1.1" {
		t.Errorf("offer server %q", s)
	}
	if s := dhcpOfferServer(offer, [4]byte{9, 9, 9, 9}); s != "" {
		t.Error("an offer for another transaction was accepted")
	}
	if s := parseIPConfigPacket("op = BOOTREPLY\nserver_identifier (ip): 192.168.1.1\nrouter (ip_mult): {192.168.1.1}"); s != "192.168.1.1" {
		t.Errorf("ipconfig getpacket: %q", s)
	}
}

func TestNameAnswers(t *testing.T) {
	// a PTR answer with a compressed name
	q := encodeName("5.1.168.192.in-addr.arpa")
	msg := []byte{0, 1, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0}
	msg = append(msg, q...)
	msg = append(msg, 0, 12, 0, 1)
	rdata := append(encodeName("Kitchen-iPad.local")[:len(encodeName("Kitchen-iPad.local"))-1], 0)
	msg = append(msg, 0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 10)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	msg = append(msg, rdata...)
	if n := cleanHostname(parsePTRAnswer(msg)); n != "Kitchen-iPad" {
		t.Errorf("mdns name %q", n)
	}
	nb := make([]byte, 57)
	nb[56] = 2
	nb = append(nb, []byte("WORKGROUP      ")...)
	nb = append(nb, 0x00, 0x80, 0) // group name
	nb = append(nb, []byte("NAS-BOX        ")...)
	nb = append(nb, 0x00, 0x04, 0)
	if n := parseNBStat(nb); n != "NAS-BOX" {
		t.Errorf("netbios name %q", n)
	}
}

func TestSelfChecks(t *testing.T) {
	fake := map[string]string{
		"/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": "Firewall is disabled. (State = 0)",
		"fdesetup status": "FileVault is On.",
		"csrutil status":  "System Integrity Protection status: enabled.",
		"spctl --status":  "assessments enabled",
		"defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled": "1",
	}
	run := func(_ context.Context, name string, args ...string) string {
		return fake[strings.Join(append([]string{name}, args...), " ")]
	}
	var fs []*Finding
	for _, f := range macSelfCheck(context.Background(), run) {
		if f.ID != "self:no-backup" && f.ID != "self:no-outgoing-firewall" {
			fs = append(fs, f)
		}
	}
	if len(fs) != 1 || fs[0].ID != "self:firewall-off" {
		t.Errorf("%+v", fs)
	}
	cfg := sshdSettings("# x\nPermitRootLogin yes\nPermitRootLogin no\nMatch User bob\nPasswordAuthentication no\n")
	if cfg["permitrootlogin"] != "yes" || cfg["passwordauthentication"] != "" {
		t.Errorf("%v", cfg)
	}
	sh := sharingFindings([]sock{{LocalIP: net.IPv4zero, LocalPort: 5900, State: "LISTEN"}, {LocalIP: net.IPv4(127, 0, 0, 1), LocalPort: 445, State: "LISTEN"}})
	if len(sh) != 1 || !strings.Contains(sh[0].Title, "Screen Sharing") {
		t.Errorf("%+v", sh)
	}
}

func TestAlertDestinations(t *testing.T) {
	for _, ok := range []string{"https://ntfy.sh/x", "smtps://me@smtp.example.com/you@example.com", "https://a,https://b", ""} {
		if err := validateWebhooks(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.com/x", "smtps://me:pw@smtp.example.com/you@example.com", "smtp://smtp.example.com/"} {
		if validateWebhooks(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if detectFormat("https://api.pushover.net/1/messages.json?token=a&user=b") != "pushover" {
		t.Error("pushover detection")
	}
	if r := redactURL("https://api.telegram.org/bot123:abc/sendMessage?chat_id=1"); strings.Contains(r, "abc") {
		t.Errorf("token leaked in %s", r)
	}
}

func TestSummary(t *testing.T) {
	now := time.Now()
	snap := NewSnapshot("192.168.1.0/24", "top", "connect")
	snap.Finished = now
	snap.Hosts["192.168.1.9"] = nil
	snap.addFinding(&Finding{ID: "upnp:enabled", Severity: sevMedium, Title: "UPnP is on", Fix: "turn it off"})
	st := []*watchState{{Name: "net-aabb", Snap: snap, Changes: []Change{
		{Time: now, Kind: "host_new", Host: "192.168.1.9", Severity: sevMedium, After: "Kitchen-iPad, Apple; no open ports"},
		{Time: now.Add(-30 * 24 * time.Hour), Kind: "host_new", Host: "192.168.1.8", Severity: sevMedium},
	}}}
	nf := &networksFile{Networks: map[string]*knownNetwork{"net-aabb": {Name: "Home"}}}
	title, body := buildSummary(st, nf, &acksFile{}, now, 7*24*time.Hour)
	if !strings.Contains(title, "1 alerts") || !strings.Contains(body, "192.168.1.9 (Kitchen-iPad, Apple) on Home") || !strings.Contains(body, "UPnP is on") || strings.Contains(body, "192.168.1.8") {
		t.Errorf("%s\n%s", title, body)
	}
}
