package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
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
	dir           string
	inv           *Inventory
	invFromConfig bool // inv comes from ~/.config/yaklite/inventory.yaml and is reloaded when it changes
	invMod        time.Time

	mu    sync.Mutex
	cache map[string]cachedChanges
}

type cachedChanges struct {
	size    int64
	modTime time.Time
	changes []Change
}

func (r *stateReader) load() ([]*watchState, error) {
	r.refreshInventory()
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

// refreshInventory re-reads ~/.config/yaklite/inventory.yaml when it was
// the source of names and has changed (yaklite name, or the dashboard).
func (r *stateReader) refreshInventory() {
	if !r.invFromConfig {
		return
	}
	p := filepath.Join(configDir(), "inventory.yaml")
	st, err := os.Stat(p)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if st.ModTime().Equal(r.invMod) {
		return
	}
	if inv, err := LoadInventory(p); err == nil {
		r.inv, r.invMod = inv, st.ModTime()
	}
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
		for _, n := range sortedNames(w.Snap) {
			if hs := w.Snap.Names[n].HTTPS; hs != nil && hs.TLS != nil {
				p.sample("yaklite_tls_cert_expiry_timestamp_seconds", float64(hs.TLS.NotAfter.Unix()),
					"watch", w.Name, "host", n, "name", n, "port", "443",
					"subject", hs.TLS.Subject, "self_signed", strconv.FormatBool(hs.TLS.SelfSigned))
			}
		}
	}
	p.metric("yaklite_name_info", "gauge", "One series per DNS name in the outside view.")
	for _, w := range states {
		for _, n := range sortedNames(w.Snap) {
			ni := w.Snap.Names[n]
			status := 0
			if ni.Web != nil {
				status = ni.Web.Status
			}
			p.sample("yaklite_name_info", 1, "watch", w.Name, "name", n, "ips", strings.Join(ni.IPs, ","),
				"http_status", strconv.Itoa(status), "cert_mismatch", strconv.FormatBool(ni.CertMismatch))
		}
	}
	p.metric("yaklite_zone_transfer_open", "gauge", "1 when a domain's name servers allow zone transfers.")
	for _, w := range states {
		for _, d := range w.Snap.Domains {
			v := 0.0
			if len(w.Snap.ZoneTransfer[d]) > 0 {
				v = 1
			}
			p.sample("yaklite_zone_transfer_open", v, "watch", w.Name, "domain", d)
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
	p.metric("yaklite_findings", "gauge", "Open problems found by checks, by severity (acknowledged ones excluded).")
	acks := loadAcks()
	for _, w := range states {
		counts := map[string]int{}
		for _, f := range w.Snap.Findings {
			if !acks.matches(f.ID, time.Now()) {
				counts[f.Severity]++
			}
		}
		for _, sev := range []string{sevHigh, sevMedium, sevLow, sevInfo} {
			p.sample("yaklite_findings", float64(counts[sev]), "watch", w.Name, "severity", sev)
		}
	}
	return p.b.String()
}

func sortedNames(s *Snapshot) []string {
	names := make([]string, 0, len(s.Names))
	for n := range s.Names {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
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
	Host, Name, Device, FirstSeen string
	Gateway                       bool
	Missed                        int
	Services                      []pageService
}

type pageService struct {
	Key, Label, Cert, CertClass string
	Unconfirmed                 bool
}

type pageChange struct {
	When, Severity, Text, Key string
	Acked                     bool
}

type pageFinding struct {
	Severity, Title, Detail, Fix, ID string
	Acked                            bool
}

type pageName struct {
	Name, IPs, Web, Cert, CertClass string
}

type pageWatch struct {
	Name, Targets, Method, LastScan, Took string
	Hosts, Ports, Alerts24h               int
	HostRows                              []pageHost
	Names                                 []pageName
	ZoneTransfer                          []string
	Changes                               []pageChange
	Findings                              []pageFinding
}

type pageData struct {
	Watches []pageWatch
	Token   string // for the acknowledge and name forms
}

func (r *stateReader) page(states []*watchState, now time.Time) []pageWatch {
	var out []pageWatch
	acks := loadAcks()
	hist := loadHistory(r.dir)
	for _, w := range states {
		pw := pageWatch{
			Name: w.Name, Targets: w.Snap.Targets, Method: w.Snap.Method,
			LastScan: w.Snap.Finished.Local().Format("2006-01-02 15:04"),
			Took:     w.Snap.Finished.Sub(w.Snap.Started).Round(time.Second).String(),
			Hosts:    len(w.Snap.Hosts), Ports: w.Snap.OpenPortCount(),
		}
		for _, h := range sortedHosts(w.Snap) {
			row := pageHost{Host: h, Name: r.hostName(h, w.Snap), Missed: w.Snap.Misses[h], Gateway: h == w.Snap.Gateway}
			if t := hist.firstSeen(w.Name, h, w.Snap.mac(h)); !t.IsZero() {
				row.FirstSeen = t.Local().Format("2 Jan 2006")
			}
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
		for _, n := range sortedNames(w.Snap) {
			ni := w.Snap.Names[n]
			pn := pageName{Name: n, IPs: strings.Join(ni.IPs, ", "), Web: ni.Web.Short()}
			if ni.HTTPS != nil && ni.HTTPS.TLS != nil {
				pn.Cert = daysLeft(ni.HTTPS.TLS, now) + ", " + ni.HTTPS.TLS.Issuer
				switch expiryState(ni.HTTPS.TLS, 21*24*time.Hour, now) {
				case "expired":
					pn.CertClass = "high"
				case "expiring":
					pn.CertClass = "medium"
				}
				if ni.CertMismatch {
					pn.Cert = "does not cover this name; " + pn.Cert
					pn.CertClass = "medium"
				}
			}
			pw.Names = append(pw.Names, pn)
		}
		for d, ns := range w.Snap.ZoneTransfer {
			pw.ZoneTransfer = append(pw.ZoneTransfer, d+" (from "+strings.Join(ns, ", ")+")")
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
			pw.Changes = append(pw.Changes, pageChange{When: c.Time.Local().Format("Jan 02 15:04"), Severity: c.Severity, Text: text, Key: c.Key(), Acked: acks.matches(c.Key(), now)})
		}
		for _, f := range w.Snap.Findings {
			pw.Findings = append(pw.Findings, pageFinding{Severity: f.Severity, Title: f.Title, Detail: f.Detail, Fix: f.Fix, ID: f.ID, Acked: acks.matches(f.ID, now)})
		}
		sort.Slice(pw.Findings, func(i, j int) bool {
			a, b := pw.Findings[i], pw.Findings[j]
			if a.Acked != b.Acked {
				return !a.Acked
			}
			if sevRank[a.Severity] != sevRank[b.Severity] {
				return sevRank[a.Severity] > sevRank[b.Severity]
			}
			return a.ID < b.ID
		})
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
form.act{display:inline;margin:0}form.act button{font:12px system-ui,sans-serif;padding:2px 8px;margin:2px 4px 2px 0;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg);cursor:pointer}
.acked{opacity:.55}.fix{color:var(--muted);font-size:13px}
form.name input{font:13px system-ui,sans-serif;padding:2px 6px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg);width:150px}
</style></head><body><main>
<h1>yaklite</h1>
<p class="sub">What yaklite has found. Refreshes every minute. Buttons only change yaklite's own settings on this computer. <a href="metrics">Prometheus metrics</a></p>
{{$tok := .Token}}
{{if not .Watches}}<p>No snapshots yet. Run <code>yaklite watch</code> first.</p>{{end}}
{{range .Watches}}
<h2>{{.Name}}</h2>
<p class="sub">{{.Targets}} · {{.Method}} scan · last run {{.LastScan}} ({{.Took}})</p>
<div class="tiles">
<div class="tile"><b>{{.Hosts}}</b><span>hosts</span></div>
<div class="tile"><b>{{.Ports}}</b><span>open ports</span></div>
<div class="tile"><b class="{{if .Alerts24h}}high{{end}}">{{.Alerts24h}}</b><span>medium/high alerts, 24h</span></div>
</div>
{{if .ZoneTransfer}}<p class="high">Zone transfers are open for {{range .ZoneTransfer}}{{.}} {{end}}: anyone can list every name in the zone.</p>{{end}}
{{if .Findings}}<h2>Problems found</h2>
<div class="wrap"><table><tr><th>Severity</th><th>Problem</th><th></th></tr>
{{range .Findings}}<tr class="{{if .Acked}}acked{{end}}"><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td>{{.Title}}{{if .Detail}}<br><span class="muted">{{.Detail}}</span>{{end}}{{if .Fix}}<br><span class="fix">Fix: {{.Fix}}</span>{{end}}</td>
<td class="nw">{{if .Acked}}<span class="muted">acknowledged</span>{{else}}<form class="act" method="post" action="ack"><input type="hidden" name="token" value="{{$tok}}"><input type="hidden" name="key" value="{{.ID}}"><button name="for" value="forever">I know about this</button><button name="for" value="1w">Snooze 1 week</button></form>{{end}}</td></tr>
{{end}}</table></div>{{end}}
{{if .Names}}<h2>Websites and names</h2>
<div class="wrap"><table><tr><th>Name</th><th>Points to</th><th>Web</th><th>Certificate</th></tr>
{{range .Names}}<tr><td><b>{{.Name}}</b></td><td class="muted">{{.IPs}}</td><td>{{.Web}}</td><td class="{{if .CertClass}}{{.CertClass}}{{else}}muted{{end}}">{{.Cert}}</td></tr>
{{end}}</table></div>{{end}}
{{if .HostRows}}<h2>Devices</h2>
<div class="wrap"><table><tr><th>Host</th><th>Open ports and services</th></tr>
{{range .HostRows}}<tr><td><b>{{if .Name}}{{.Name}}{{else}}{{.Host}}{{end}}</b>{{if .Name}}<br><span class="muted">{{.Host}}</span>{{end}}{{if .Gateway}} <span class="muted">(gateway)</span>{{end}}{{if .Device}}<br><span class="muted">{{.Device}}</span>{{end}}{{if .FirstSeen}}<br><span class="muted">first seen {{.FirstSeen}}</span>{{end}}{{if .Missed}}<br><span class="medium">missed {{.Missed}} scan(s)</span>{{end}}{{if not .Name}}<form class="act name" method="post" action="name"><input type="hidden" name="token" value="{{$tok}}"><input type="hidden" name="host" value="{{.Host}}"><input name="name" placeholder="Name this device" maxlength="60"></form>{{end}}</td>
<td>{{if not .Services}}<span class="muted">no open ports</span>{{end}}{{range .Services}}<div class="svc"><code>{{.Key}}</code> {{.Label}}{{if .Unconfirmed}} <span class="muted">(unconfirmed)</span>{{end}}{{if .Cert}} <span class="{{if .CertClass}}{{.CertClass}}{{else}}muted{{end}}">cert: {{.Cert}}</span>{{end}}</div>{{end}}</td></tr>
{{end}}</table></div>{{end}}
<h2>Recent changes</h2>
{{if .Changes}}<div class="wrap"><table><tr><th>When</th><th>Severity</th><th>Change</th><th></th></tr>
{{range .Changes}}<tr class="{{if .Acked}}acked{{end}}"><td class="muted nw">{{.When}}</td><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td>{{.Text}}</td><td class="nw">{{if or (eq .Severity "high") (eq .Severity "medium")}}{{if .Acked}}<span class="muted">acknowledged</span>{{else}}<form class="act" method="post" action="ack"><input type="hidden" name="token" value="{{$tok}}"><input type="hidden" name="key" value="{{.Key}}"><button name="for" value="forever">I know</button><button name="for" value="1w">Snooze</button></form>{{end}}{{end}}</td></tr>
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
	tb := make([]byte, 18)
	rand.Read(tb)
	token := hex.EncodeToString(tb)
	mux := http.NewServeMux()
	// The two forms only change yaklite's own settings (acks.yaml and
	// inventory.yaml). Each needs the page's random token, so another
	// website open in the browser cannot submit them.
	mux.HandleFunc("/ack", func(w http.ResponseWriter, req *http.Request) {
		d, err := parseDuration(req.PostFormValue("for"))
		key := req.PostFormValue("key")
		if err != nil || key == "" || len(key) > 300 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if _, err := addAck(key, d, "from the dashboard"); err != nil {
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "./", http.StatusSeeOther)
	})
	mux.HandleFunc("/name", func(w http.ResponseWriter, req *http.Request) {
		host, name := req.PostFormValue("host"), strings.TrimSpace(req.PostFormValue("name"))
		if net.ParseIP(host) == nil || name == "" || len(name) > 60 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// prefer the MAC, which survives a new IP from the router
		key := host
		if states, err := r.load(); err == nil {
			for _, st := range states {
				if m := st.Snap.mac(host); m != "" {
					key = m
				}
			}
		}
		if err := cmdName([]string{key, name}); err != nil {
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		if r.inv == nil {
			r.invFromConfig = true
		}
		http.Redirect(w, req, "./", http.StatusSeeOther)
	})
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
		pageTmpl.Execute(w, pageData{Watches: r.page(states, time.Now()), Token: token})
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
	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, req *http.Request) {
		states, err := r.load()
		if err != nil {
			http.Error(w, "could not read state", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiSummary(states, loadAcks(), time.Now()))
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
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		if !hostAllowed(req.Host, password != "") {
			// a page on another site that rebinds its name to 127.0.0.1
			http.Error(w, "unexpected Host header", http.StatusForbidden)
			return
		}
		switch req.Method {
		case http.MethodGet, http.MethodHead:
		case http.MethodPost:
			if req.URL.Path != "/ack" && req.URL.Path != "/name" {
				http.Error(w, "not allowed", http.StatusMethodNotAllowed)
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, 4096)
			if o := req.Header.Get("Origin"); o != "" && o != "http://"+req.Host && o != "https://"+req.Host {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			if subtle.ConstantTimeCompare([]byte(req.PostFormValue("token")), []byte(token)) != 1 {
				http.Error(w, "stale page, reload it", http.StatusForbidden)
				return
			}
		default:
			http.Error(w, "not allowed", http.StatusMethodNotAllowed)
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

// hostAllowed accepts loopback names, and any name when a password is set
// (then the dashboard is meant to be reached from elsewhere).
func hostAllowed(host string, hasPassword bool) bool {
	if hasPassword {
		return true
	}
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
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

// apiSummary is the small status the menu bar plugin shows.
type summaryJSON struct {
	Status      string   `json:"status"` // ok, warn or alert
	OpenHigh    int      `json:"open_high"`
	OpenMedium  int      `json:"open_medium"`
	Alerts24h   int      `json:"alerts_24h"`
	LastCheck   string   `json:"last_check,omitempty"`
	TopProblems []string `json:"top_problems,omitempty"`
}

func apiSummary(states []*watchState, acks *acksFile, now time.Time) summaryJSON {
	var s summaryJSON
	var last time.Time
	type p struct {
		sev, title string
	}
	var probs []p
	for _, st := range states {
		if st.Snap.Finished.After(last) && st.Snap.Method != "connections" {
			last = st.Snap.Finished
		}
		for _, f := range st.Snap.Findings {
			if acks.matches(f.ID, now) {
				continue
			}
			switch f.Severity {
			case sevHigh:
				s.OpenHigh++
				probs = append(probs, p{f.Severity, f.Title})
			case sevMedium:
				s.OpenMedium++
				probs = append(probs, p{f.Severity, f.Title})
			}
		}
		for _, c := range st.Changes {
			if now.Sub(c.Time) < 24*time.Hour && sevRank[c.Severity] >= sevRank[sevMedium] && !acks.matches(c.Key(), now) {
				s.Alerts24h++
			}
		}
	}
	sort.SliceStable(probs, func(i, j int) bool { return sevRank[probs[i].sev] > sevRank[probs[j].sev] })
	for i := 0; i < len(probs) && i < 5; i++ {
		s.TopProblems = append(s.TopProblems, probs[i].title)
	}
	if !last.IsZero() {
		s.LastCheck = last.Local().Format("15:04")
	}
	switch {
	case s.OpenHigh > 0:
		s.Status = "alert"
	case s.OpenMedium > 0 || s.Alerts24h > 0:
		s.Status = "warn"
	default:
		s.Status = "ok"
	}
	return s
}
