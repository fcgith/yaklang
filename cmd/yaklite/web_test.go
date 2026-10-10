package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func writeTestState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	snap := NewSnapshot("192.168.1.0/24", "top", "connect")
	snap.Started, snap.Finished = now.Add(-10*time.Second), now
	snap.Add("192.168.1.10", &Service{Port: 443, Proto: "tcp", Service: "https", Verified: true,
		TLS: &TLSInfo{Subject: `CN=nas "lan"`, NotAfter: now.Add(48 * time.Hour), SelfSigned: true}})
	snap.Add("192.168.1.10", &Service{Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH", Version: "9.6", Verified: true})
	if err := SaveSnapshot(filepath.Join(dir, "home.snapshot.json"), snap); err != nil {
		t.Fatal(err)
	}
	changes := []Change{
		{Time: now, Kind: "port_open", Severity: sevHigh, Host: "192.168.1.10", Port: 23, Proto: "tcp", After: "telnet <script>"},
		{Time: now, Kind: "host_new", Severity: sevLow, Host: "192.168.1.20", After: "tcp/80"},
	}
	if err := appendChanges(filepath.Join(dir, "home.changes.jsonl"), changes); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMetricsOutput(t *testing.T) {
	dir := writeTestState(t)
	inv := &Inventory{Hosts: map[string]*HostEntry{"192.168.1.10": {Name: "NAS"}}}
	h := newWebHandler(&stateReader{dir: dir, inv: inv}, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`yaklite_hosts{watch="home"} 1`,
		`yaklite_open_ports{watch="home"} 2`,
		`yaklite_host_open_ports{watch="home",host="192.168.1.10",name="NAS"} 2`,
		`subject="CN=nas \"lan\""`,
		`yaklite_changes_total{watch="home",kind="port_open",severity="high"} 1`,
		"# TYPE yaklite_changes_total counter",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
	// every metric family must be declared once
	if strings.Count(body, "# TYPE yaklite_service_info ") != 1 {
		t.Error("yaklite_service_info declared more than once")
	}
}

func localReq(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Host = "127.0.0.1:9842"
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return req
}

func TestDashboardEscapesAndForms(t *testing.T) {
	dir := writeTestState(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	h := newWebHandler(&stateReader{dir: dir}, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/", nil))
	page := rec.Body.String()
	if rec.Code != 200 || strings.Contains(page, "<script>") {
		t.Fatalf("page not served safely: %d", rec.Code)
	}
	if !strings.Contains(page, "telnet &lt;script&gt;") {
		t.Error("change text not shown escaped")
	}
	m := regexp.MustCompile(`name="token" value="([0-9a-f]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no form token on the page")
	}
	post := func(path, form, origin, host string) int {
		req := localReq(http.MethodPost, path, strings.NewReader(form))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if host != "" {
			req.Host = host
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := post("/", "", "", ""); c != http.StatusMethodNotAllowed {
		t.Errorf("POST / got %d", c)
	}
	if c := post("/ack", "key=port_open:192.168.1.10:tcp/23&for=forever", "", ""); c != http.StatusForbidden {
		t.Errorf("ack without token got %d", c)
	}
	if c := post("/ack", "token="+m[1]+"&key=port_open:192.168.1.10:tcp/23&for=forever", "https://evil.example", ""); c != http.StatusForbidden {
		t.Errorf("cross-site ack got %d", c)
	}
	if c := post("/ack", "token="+m[1]+"&key=port_open:192.168.1.10:tcp/23&for=forever", "", "evil.example:9842"); c != http.StatusForbidden {
		t.Errorf("rebinding Host got %d", c)
	}
	if c := post("/ack", "token="+m[1]+"&key=port_open:192.168.1.10:tcp/23&for=forever", "http://127.0.0.1:9842", ""); c != http.StatusSeeOther {
		t.Fatalf("ack got %d", c)
	}
	if !loadAcks().matches("port_open:192.168.1.10:tcp/23", time.Now()) {
		t.Error("ack not saved")
	}
	if c := post("/name", "token="+m[1]+"&host=192.168.1.10&name=Kitchen+NAS", "", ""); c != http.StatusSeeOther {
		t.Fatalf("name got %d", c)
	}
	inv, err := LoadInventory(filepath.Join(configDir(), "inventory.yaml"))
	if err != nil || inv.entry("192.168.1.10", "") == nil || inv.entry("192.168.1.10", "").Name != "Kitchen NAS" {
		t.Errorf("name not saved: %v", err)
	}
}

func TestDashboardPassword(t *testing.T) {
	dir := writeTestState(t)
	h := newWebHandler(&stateReader{dir: dir}, "s3cret")
	for _, c := range []struct {
		pw   string
		want int
	}{{"", 401}, {"nope", 401}, {"s3cret", 200}} {
		req := localReq(http.MethodGet, "/metrics", nil)
		if c.pw != "" {
			req.SetBasicAuth("me", c.pw)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("password %q: got %d want %d", c.pw, rec.Code, c.want)
		}
	}
	t.Setenv("YAKLITE_WEB_PASSWORD", "")
	if _, err := startWeb("0.0.0.0:0", &stateReader{dir: dir}); err == nil {
		t.Error("non-loopback listen without a password should be refused")
	}
}
