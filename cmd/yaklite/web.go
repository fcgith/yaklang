package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The web view reads the state directory on every request, so it works the
// same next to a long-running watch and next to a systemd timer that runs
// "watch --once". It never changes anything.

type watchState struct {
	Name    string
	Snap    *Snapshot
	Changes []Change // oldest first
}

type stateReader struct {
	dir string
	inv *Inventory

	mu    sync.Mutex
	cache map[string]cachedChanges
}

type cachedChanges struct {
	size    int64
	modTime time.Time
	changes []Change
}

func (r *stateReader) load() ([]*watchState, error) {
	snaps, err := filepath.Glob(filepath.Join(r.dir, "*.snapshot.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(snaps)
	var out []*watchState
	for _, p := range snaps {
		name := strings.TrimSuffix(filepath.Base(p), ".snapshot.json")
		snap, err := LoadSnapshot(p)
		if err != nil {
			continue
		}
		ch, _ := r.changes(filepath.Join(r.dir, name+".changes.jsonl"))
		out = append(out, &watchState{Name: name, Snap: snap, Changes: ch})
	}
	return out, nil
}

// changes parses a change log, re-reading it only when it has grown.
func (r *stateReader) changes(path string) ([]Change, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = map[string]cachedChanges{}
	}
	if c, ok := r.cache[path]; ok && c.size == st.Size() && c.modTime.Equal(st.ModTime()) {
		return c.changes, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var list []Change
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var c Change
		if json.Unmarshal(sc.Bytes(), &c) == nil {
			list = append(list, c)
		}
	}
	r.cache[path] = cachedChanges{size: st.Size(), modTime: st.ModTime(), changes: list}
	return list, nil
}

func (r *stateReader) hostName(host string, snap *Snapshot) string {
	if e := r.inv.entry(host, snap.mac(host)); e != nil {
		return e.Name
	}
	return ""
}

// ---- Prometheus ----

func promEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

type promWriter struct {
	b    strings.Builder
	seen map[string]bool
}

func (p *promWriter) metric(name, typ, help string) {
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	fmt.Fprintf(&p.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (p *promWriter) sample(name string, value float64, labels ...string) {
	p.b.WriteString(name)
	if len(labels) > 0 {
		p.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				p.b.WriteByte(',')
			}
			fmt.Fprintf(&p.b, `%s="%s"`, labels[i], promEscape(labels[i+1]))
		}
		p.b.WriteByte('}')
	}
	p.b.WriteByte(' ')
	p.b.WriteString(strconv.FormatFloat(value, 'f', -1, 64))
	p.b.WriteByte('\n')
}

func (r *stateReader) metrics(states []*watchState) string {
	var p promWriter
	// Each metric's samples must be contiguous, so loop per metric.
	p.metric("yaklite_last_scan_timestamp_seconds", "gauge", "Unix time the last scan finished.")
	for _, w := range states {
		p.sample("yaklite_last_scan_timestamp_seconds", float64(w.Snap.Finished.Unix()), "watch", w.Name)
	}
	p.metric("yaklite_scan_duration_seconds", "gauge", "How long the last scan took.")
	for _, w := range states {
		p.sample("yaklite_scan_duration_seconds", w.Snap.Finished.Sub(w.Snap.Started).Seconds(), "watch", w.Name)
	}
	p.metric("yaklite_hosts", "gauge", "Hosts with at least one open port in the last snapshot.")
	for _, w := range states {
		p.sample("yaklite_hosts", float64(len(w.Snap.Hosts)), "watch", w.Name)
	}
	p.metric("yaklite_open_ports", "gauge", "Open ports across all hosts in the last snapshot.")
	for _, w := range states {
		p.sample("yaklite_open_ports", float64(w.Snap.OpenPortCount()), "watch", w.Name)
	}
	p.metric("yaklite_host_open_ports", "gauge", "Open ports per host.")
	for _, w := range states {
		for _, h := range sortedHosts(w.Snap) {
			p.sample("yaklite_host_open_ports", float64(len(w.Snap.Hosts[h])), "watch", w.Name, "host", h, "name", r.hostName(h, w.Snap))
		}
	}
	p.metric("yaklite_host_missed_scans", "gauge", "Consecutive scans a known host did not answer (0 when it answered).")
	for _, w := range states {
		for _, h := range sortedHosts(w.Snap) {
			p.sample("yaklite_host_missed_scans", float64(w.Snap.Misses[h]), "watch", w.Name, "host", h, "name", r.hostName(h, w.Snap))
		}
	}
	p.metric("yaklite_device_info", "gauge", "One series per device found by MAC address.")
	for _, w := range states {
		for _, h := range sortedHosts(w.Snap) {
			d := w.Snap.Devices[h]
			if d == nil {
				continue
			}
			p.sample("yaklite_device_info", 1, "watch", w.Name, "host", h, "name", r.hostName(h, w.Snap), "mac", d.MAC,
				"vendor", d.Vendor, "hostname", d.Hostname, "randomized_mac", strconv.FormatBool(d.Randomized),
				"gateway", strconv.FormatBool(h == w.Snap.Gateway))
		}
	}
	p.metric("yaklite_service_info", "gauge", "One series per open port, labelled with what the fingerprinter found.")
	for _, w := range states {
		for _, h := range sortedHosts(w.Snap) {
			for _, s := range w.Snap.Hosts[h] {
				p.sample("yaklite_service_info", 1, "watch", w.Name, "host", h, "name", r.hostName(h, w.Snap),
					"port", strconv.Itoa(s.Port), "proto", s.Proto, "service", s.Service, "product", s.Product,
					"version", s.Version, "verified", strconv.FormatBool(s.Verified))
			}
		}
	}
	p.metric("yaklite_tls_cert_expiry_timestamp_seconds", "gauge", "Unix time the certificate on a port expires.")
	for _, w := range states {
		for _, h := range sortedHosts(w.Snap) {
			for _, s := range w.Snap.Hosts[h] {
				if s.TLS == nil {
					continue
				}
				p.sample("yaklite_tls_cert_expiry_timestamp_seconds", float64(s.TLS.NotAfter.Unix()),
					"watch", w.Name, "host", h, "name", r.hostName(h, w.Snap), "port", strconv.Itoa(s.Port),
					"subject", s.TLS.Subject, "self_signed", strconv.FormatBool(s.TLS.SelfSigned))
			}
		}
	}
	p.metric("yaklite_changes_total", "counter", "Changes recorded in the change log, by kind and severity.")
	for _, w := range states {
		counts := map[[2]string]int{}
		for _, c := range w.Changes {
			counts[[2]string{c.Kind, c.Severity}]++
		}
		keys := make([][2]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
		for _, k := range keys {
			p.sample("yaklite_changes_total", float64(counts[k]), "watch", w.Name, "kind", k[0], "severity", k[1])
		}
	}
	return p.b.String()
}

func sortedHosts(s *Snapshot) []string {
	hosts := make([]string, 0, len(s.Hosts))
	for h := range s.Hosts {
		hosts = append(hosts, h)
	}
	sortHosts(hosts)
	return hosts
}

// ---- HTML ----

type pageHost struct {
	Host, Name, Device string
	Gateway            bool
	Missed             int
	Services           []pageService
}

type pageService struct {
	Key, Label, Cert, CertClass string
	Unconfirmed                 bool
}

type pageChange struct {
	When, Severity, Text string
}

type pageWatch struct {
	Name, Targets, Method, LastScan, Took string
	Hosts, Ports, Alerts24h               int
	HostRows                              []pageHost
	Changes                               []pageChange
}

func (r *stateReader) page(states []*watchState, now time.Time) []pageWatch {
	var out []pageWatch
	for _, w := range states {
		pw := pageWatch{
			Name: w.Name, Targets: w.Snap.Targets, Method: w.Snap.Method,
			LastScan: w.Snap.Finished.Local().Format("2006-01-02 15:04"),
			Took:     w.Snap.Finished.Sub(w.Snap.Started).Round(time.Second).String(),
			Hosts:    len(w.Snap.Hosts), Ports: w.Snap.OpenPortCount(),
		}
		for _, h := range sortedHosts(w.Snap) {
			row := pageHost{Host: h, Name: r.hostName(h, w.Snap), Missed: w.Snap.Misses[h], Gateway: h == w.Snap.Gateway}
			if d := w.Snap.Devices[h]; d != nil {
				row.Device = strings.TrimSpace(d.MAC + "  " + d.describe())
			}
			for _, s := range w.Snap.Hosts[h] {
				ps := pageService{Key: s.Key(), Label: s.Label(), Unconfirmed: !s.Verified}
				if s.TLS != nil {
					ps.Cert = daysLeft(s.TLS, now)
					if s.TLS.SelfSigned {
						ps.Cert += ", self-signed"
					}
					switch expiryState(s.TLS, 21*24*time.Hour, now) {
					case "expired":
						ps.CertClass = "high"
					case "expiring":
						ps.CertClass = "medium"
					}
				}
				row.Services = append(row.Services, ps)
			}
			pw.HostRows = append(pw.HostRows, row)
		}
		for i := len(w.Changes) - 1; i >= 0 && len(pw.Changes) < 200; i-- {
			c := w.Changes[i]
			if c.Name == "" {
				c.Name = r.hostName(c.Host, w.Snap)
			}
			if (c.Severity == sevHigh || c.Severity == sevMedium) && now.Sub(c.Time) < 24*time.Hour {
				pw.Alerts24h++
			}
			text := c.String()
			if c.Severity != "" {
				text = strings.TrimSpace(text[len(c.Severity):])
			}
			pw.Changes = append(pw.Changes, pageChange{When: c.Time.Local().Format("Jan 02 15:04"), Severity: c.Severity, Text: text})
		}
		out = append(out, pw)
	}
	return out
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>yaklite</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e3e2dc;--high:#c2362b;--medium:#b86e00;--low:#2f6db3;--info:#6b6b66}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--fg:#ecebe6;--muted:#9a9993;--line:#33332f;--high:#ff6b5e;--medium:#f0a63a;--low:#79a8ec;--info:#9a9993}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:20px 16px 48px}h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 16px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.tile b{display:block;font-size:22px}.tile span{color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-top:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;border-top:0}
.wrap{overflow-x:auto}.muted{color:var(--muted)}.nw{white-space:nowrap}.svc{padding:1px 0}a{color:var(--low)}
.sev{display:inline-block;min-width:58px;font-size:12px;font-weight:700;text-transform:uppercase}
.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
code{font:12px ui-monospace,Menlo,monospace}
</style></head><body><main>
<h1>yaklite</h1>
<p class="sub">Read-only view of the state directory. Refreshes every minute. <a href="metrics">Prometheus metrics</a></p>
{{if not .}}<p>No snapshots yet. Run <code>yaklite watch</code> first.</p>{{end}}
{{range .}}
<h2>{{.Name}}</h2>
<p class="sub">{{.Targets}} · {{.Method}} scan · last run {{.LastScan}} ({{.Took}})</p>
<div class="tiles">
<div class="tile"><b>{{.Hosts}}</b><span>hosts</span></div>
<div class="tile"><b>{{.Ports}}</b><span>open ports</span></div>
<div class="tile"><b class="{{if .Alerts24h}}high{{end}}">{{.Alerts24h}}</b><span>medium/high alerts, 24h</span></div>
</div>
<h2>Devices</h2>
<div class="wrap"><table><tr><th>Host</th><th>Open ports and services</th></tr>
{{range .HostRows}}<tr><td><b>{{if .Name}}{{.Name}}{{else}}{{.Host}}{{end}}</b>{{if .Name}}<br><span class="muted">{{.Host}}</span>{{end}}{{if .Gateway}} <span class="muted">(gateway)</span>{{end}}{{if .Device}}<br><span class="muted">{{.Device}}</span>{{end}}{{if .Missed}}<br><span class="medium">missed {{.Missed}} scan(s)</span>{{end}}</td>
<td>{{if not .Services}}<span class="muted">no open ports</span>{{end}}{{range .Services}}<div class="svc"><code>{{.Key}}</code> {{.Label}}{{if .Unconfirmed}} <span class="muted">(unconfirmed)</span>{{end}}{{if .Cert}} <span class="{{if .CertClass}}{{.CertClass}}{{else}}muted{{end}}">cert: {{.Cert}}</span>{{end}}</div>{{end}}</td></tr>
{{end}}</table></div>
<h2>Recent changes</h2>
{{if .Changes}}<div class="wrap"><table><tr><th>When</th><th>Severity</th><th>Change</th></tr>
{{range .Changes}}<tr><td class="muted nw">{{.When}}</td><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td>{{.Text}}</td></tr>
{{end}}</table></div>{{else}}<p class="muted">No changes recorded yet.</p>{{end}}
{{end}}
</main></body></html>`))

// ---- server ----

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newWebHandler serves the dashboard, /metrics and /api/*. When password is
// set every request needs HTTP basic auth with that password (any user name).
func newWebHandler(r *stateReader, password string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		states, err := r.load()
		if err != nil {
			http.Error(w, "could not read state", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTmpl.Execute(w, r.page(states, time.Now()))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		states, err := r.load()
		if err != nil {
			http.Error(w, "could not read state", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, r.metrics(states))
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, req *http.Request) {
		states, err := r.load()
		if err != nil {
			http.Error(w, "could not read state", http.StatusInternalServerError)
			return
		}
		type apiWatch struct {
			Name     string    `json:"name"`
			Snapshot *Snapshot `json:"snapshot"`
			Changes  []Change  `json:"recent_changes"`
		}
		var out []apiWatch
		for _, s := range states {
			ch := s.Changes
			if len(ch) > 500 {
				ch = ch[len(ch)-500:]
			}
			out = append(out, apiWatch{s.Name, s.Snap, ch})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		if password != "" {
			_, pw, ok := req.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(pw), []byte(password)) != 1 {
				h.Set("WWW-Authenticate", `Basic realm="yaklite"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(w, req)
	})
}

// startWeb listens on addr. Non-loopback addresses need YAKLITE_WEB_PASSWORD,
// because the page is a map of the network.
func startWeb(addr string, r *stateReader) (*http.Server, error) {
	password := os.Getenv("YAKLITE_WEB_PASSWORD")
	if !isLoopback(addr) && password == "" {
		return nil, errors.New("--listen on a non-loopback address needs YAKLITE_WEB_PASSWORD set (the page is a map of your network)")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           newWebHandler(r, password),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go srv.Serve(ln)
	fmt.Fprintf(os.Stderr, "[yaklite] dashboard on http://%s/ (metrics at /metrics)\n", ln.Addr())
	return srv, nil
}
