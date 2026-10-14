package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The host watch looks inside this computer for the changes malware and
// attackers make once they are in: a program set to start automatically, a
// root certificate that lets them read encrypted traffic, a proxy or DNS
// server that routes traffic through them, a device-management profile, a
// new account or administrator. It records what is there the first time it
// runs and reports anything new after that. It only reads settings.

func init() {
	registerCheck(&check{name: "host", about: "new startup programs, trusted certificates, proxies, DNS, profiles and accounts on this computer", run: hostCheck})
}

type hostItem struct {
	Cat   string // startup, cert, proxy, dns, profile, mdm, vpn, user, admin
	Key   string // stable identity
	Label string // what to show
	Sev   string // overrides the category's severity (suspicious startup items)
}

func (h hostItem) id() string {
	sum := sha256.Sum256([]byte(h.Cat + "\x00" + h.Key))
	return "host:" + h.Cat + ":" + hex.EncodeToString(sum[:5])
}

// hostOS is what the collectors read the computer through, so tests can
// give them a fake one.
type hostOS struct {
	goos     string
	home     string
	run      runner
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
}

func realHostOS() *hostOS {
	home, _ := os.UserHomeDir()
	return &hostOS{goos: runtime.GOOS, home: home, run: cmdOut, readFile: os.ReadFile, readDir: os.ReadDir}
}

var hostCats = map[string]struct {
	sev         string
	reviewAll   bool // worth a look even when already there on the first run
	title       string
	reviewTitle string
	detail      string
	fix         string
}{
	"startup": {sevMedium, false, "New program set to start automatically: %s", "",
		"Setting itself to start at login or boot is the first thing most malware does.",
		"If you did not just install something that explains it, remove it: on a Mac, System Settings > General > Login Items, or delete the file named above and log out and in. yaklite ack this alert if it is yours."},
	"cert": {sevHigh, true, "A new trusted root certificate was added: %s", "Please check this trusted root certificate: %s",
		"Anyone holding its key can read and change your encrypted web traffic without any browser warning.",
		"If you did not add it on purpose (some company VPNs and debugging tools do), remove it: on a Mac in Keychain Access > System or login > Certificates, on Linux delete the file and run update-ca-certificates. Then change your important passwords."},
	"proxy": {sevHigh, true, "This computer's web traffic is now sent through a proxy: %s", "Please check this proxy setting: %s",
		"A proxy you did not set up can watch and change everything you browse.",
		"Turn it off in System Settings > Network > (your network) > Details > Proxies, unless your work set it up."},
	"dns": {sevMedium, false, "DNS servers were set by hand: %s", "",
		"Whoever answers DNS decides which server each website name goes to.",
		"If you did not set these, clear them in System Settings > Network > (your network) > Details > DNS so the network's own are used."},
	"profile": {sevHigh, true, "A configuration profile was installed: %s", "Please check this configuration profile: %s",
		"Profiles can install certificates, proxies and VPNs, and change many security settings at once.",
		"If it is not from your work or school, remove it in System Settings > General > Device Management (or Privacy & Security > Profiles)."},
	"mdm": {sevHigh, true, "This computer is now managed remotely (enrolled in device management)", "Please check: this computer is managed remotely (enrolled in device management)",
		"Device management lets its owner install software and change settings without asking.",
		"If this is not a work or school computer, remove the management profile in System Settings > General > Device Management."},
	"vpn": {sevLow, false, "A new VPN connection was added: %s", "",
		"", "If you did not add it, delete it in System Settings > VPN."},
	"user": {sevHigh, false, "A new user account was created: %s", "",
		"Attackers add accounts to get back in later.",
		"If you did not create it, delete it in System Settings > Users & Groups and change your own password."},
	"admin": {sevHigh, false, "%s is now an administrator", "",
		"Administrators can change anything on this computer.",
		"If you did not do this, remove the admin right in System Settings > Users & Groups."},
}

type hostBaseline struct {
	Created time.Time       `json:"created"`
	Items   map[string]bool `json:"items"`  // ids present when it was recorded
	Review  map[string]bool `json:"review"` // ids worth a look although already present
}

func hostBaselinePath(stateDir string) string { return filepath.Join(stateDir, "host-baseline.json") }

func loadHostBaseline(stateDir string) *hostBaseline {
	data, err := os.ReadFile(hostBaselinePath(stateDir))
	if err != nil {
		return nil
	}
	b := &hostBaseline{}
	if json.Unmarshal(data, b) != nil || b.Items == nil {
		return nil
	}
	return b
}

func saveHostBaseline(stateDir string, items []hostItem, review bool) error {
	b := &hostBaseline{Created: time.Now(), Items: map[string]bool{}, Review: map[string]bool{}}
	for _, it := range items {
		b.Items[it.id()] = true
		if review && (hostCats[it.Cat].reviewAll || it.Sev == sevHigh) {
			b.Review[it.id()] = true
		}
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll(stateDir, 0o700)
	return writeFilePrivate(hostBaselinePath(stateDir), data)
}

func hostCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	h := realHostOS()
	items := collectHostItems(ctx, h)
	base := loadHostBaseline(env.stateDir)
	if base == nil {
		if err := saveHostBaseline(env.stateDir, items, true); err != nil {
			return nil, err
		}
		base = loadHostBaseline(env.stateDir)
	}
	out := hostFindings(items, base)
	var socks []sock
	if s, err := listSockets(ctx); err == nil {
		socks = s
	}
	out = append(out, failedLoginFindings(ctx, h, socks)...)
	return out, nil
}

// hostFindings reports items that were not there when the baseline was
// recorded, and baseline items marked for review.
func hostFindings(items []hostItem, base *hostBaseline) []*Finding {
	var out []*Finding
	seen := map[string]bool{}
	for _, it := range items {
		id := it.id()
		if seen[id] {
			continue
		}
		seen[id] = true
		review := base.Review[id]
		if base.Items[id] && !review {
			continue
		}
		c, ok := hostCats[it.Cat]
		if !ok {
			continue
		}
		f := &Finding{ID: id, Severity: c.sev, Detail: c.detail, Fix: c.fix}
		if it.Sev != "" {
			f.Severity = it.Sev
		}
		tmpl := c.title
		if review {
			tmpl = c.reviewTitle
			if tmpl == "" {
				tmpl = "Please check: " + c.title
			}
			if f.Severity == sevHigh {
				f.Severity = sevMedium // it was already there; worth a look, not an alarm
			}
		}
		if strings.Contains(tmpl, "%s") {
			f.Title = fmt.Sprintf(tmpl, it.Label)
		} else {
			f.Title = tmpl
		}
		out = append(out, f)
	}
	return out
}

func collectHostItems(ctx context.Context, h *hostOS) []hostItem {
	var items []hostItem
	switch h.goos {
	case "darwin":
		items = append(items, macStartupItems(ctx, h)...)
		items = append(items, macCertItems(ctx, h)...)
		items = append(items, macNetItems(ctx, h)...)
		items = append(items, macAccountItems(ctx, h)...)
	case "linux":
		items = append(items, linuxStartupItems(ctx, h)...)
		items = append(items, linuxCertItems(h)...)
		items = append(items, linuxNetItems(ctx, h)...)
		items = append(items, linuxAccountItems(h)...)
	case "windows":
		items = append(items, windowsHostItems(ctx, h)...)
	}
	items = append(items, cronItems(ctx, h)...)
	sort.Slice(items, func(i, j int) bool { return items[i].id() < items[j].id() })
	return items
}

// suspiciousPath is a program location that legitimate installers avoid.
func suspiciousPath(p string) bool {
	p = strings.ToLower(p)
	for _, bad := range []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/", "/users/shared/", `\temp\`, `\appdata\local\temp\`} {
		if strings.Contains(p, bad) {
			return true
		}
	}
	// a hidden directory somewhere in the path, e.g. ~/.local/.x/agent
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if len(part) > 1 && part[0] == '.' && part != ".local" && part != ".config" && part != ".." {
			return true
		}
	}
	return false
}

func startupItem(key, name, prog string) hostItem {
	it := hostItem{Cat: "startup", Key: key, Label: name}
	if prog != "" {
		it.Label += " (runs " + prog + ")"
		if suspiciousPath(prog) {
			it.Sev = sevHigh
			it.Label += ", from a temporary or hidden folder"
		}
	}
	return it
}

func ownAgent(name string) bool {
	return strings.HasPrefix(name, "io.github.yaklite.") || strings.HasPrefix(name, "yaklite-")
}

// ---- macOS ----

func macStartupItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	for _, dir := range []string{filepath.Join(h.home, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/StartupItems"} {
		entries, err := h.readDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") || ownAgent(name) || strings.HasPrefix(name, "com.apple.") {
				continue
			}
			p := filepath.Join(dir, name)
			prog := ""
			if strings.HasSuffix(name, ".plist") {
				prog = plistProgram(h.run(ctx, "plutil", "-convert", "json", "-o", "-", p))
			}
			out = append(out, startupItem(p, strings.TrimSuffix(name, ".plist"), prog))
		}
	}
	// system extensions (network filters, endpoint security, drivers)
	for _, line := range strings.Split(h.run(ctx, "systemextensionsctl", "list"), "\n") {
		if !strings.Contains(line, "[activated enabled]") {
			continue
		}
		if m := regexp.MustCompile(`\s(\S+\.\S+) \(`).FindStringSubmatch(line); m != nil {
			out = append(out, startupItem("sysext:"+m[1], "system extension "+m[1], ""))
		}
	}
	return out
}

// plistProgram reads the program a launchd job runs from plutil's JSON.
func plistProgram(js string) string {
	var p struct {
		Program          string   `json:"Program"`
		ProgramArguments []string `json:"ProgramArguments"`
	}
	if json.Unmarshal([]byte(js), &p) != nil {
		return ""
	}
	if p.Program != "" {
		return p.Program
	}
	if len(p.ProgramArguments) > 0 {
		return p.ProgramArguments[0]
	}
	return ""
}

var trustCertRe = regexp.MustCompile(`(?m)^Cert \d+: (.+)$`)

func macCertItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	for _, dom := range []struct{ flag, name string }{{"-d", "admin"}, {"", "user"}} {
		args := []string{"dump-trust-settings"}
		if dom.flag != "" {
			args = append(args, dom.flag)
		}
		for _, m := range trustCertRe.FindAllStringSubmatch(h.run(ctx, "security", args...), -1) {
			name := strings.TrimSpace(m[1])
			out = append(out, hostItem{Cat: "cert", Key: dom.name + ":" + name, Label: name + " (" + dom.name + " trust settings)"})
		}
	}
	return out
}

func macNetItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	for _, p := range parseScutilProxy(h.run(ctx, "scutil", "--proxy")) {
		out = append(out, hostItem{Cat: "proxy", Key: p, Label: p})
	}
	lines := strings.Split(h.run(ctx, "networksetup", "-listallnetworkservices"), "\n")
	for i, svc := range lines {
		svc = strings.TrimSpace(strings.TrimPrefix(svc, "*"))
		if i == 0 && strings.Contains(svc, "asterisk") || svc == "" {
			continue
		}
		dns := h.run(ctx, "networksetup", "-getdnsservers", svc)
		if dns == "" || strings.Contains(dns, "aren't any") || strings.Contains(dns, "Error") {
			continue
		}
		servers := strings.Join(strings.Fields(dns), ", ")
		out = append(out, hostItem{Cat: "dns", Key: svc + "=" + servers, Label: servers + " on " + svc})
	}
	for _, m := range regexp.MustCompile(`profileIdentifier: (\S+)`).FindAllStringSubmatch(h.run(ctx, "profiles", "list"), -1) {
		if strings.HasPrefix(m[1], "io.github.yaklite.") {
			continue // yaklite private-dns
		}
		out = append(out, hostItem{Cat: "profile", Key: m[1], Label: m[1]})
	}
	if s := h.run(ctx, "profiles", "status", "-type", "enrollment"); regexp.MustCompile(`MDM enrollment: Yes`).MatchString(s) {
		out = append(out, hostItem{Cat: "mdm", Key: "enrolled"})
	}
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(h.run(ctx, "scutil", "--nc", "list"), -1) {
		out = append(out, hostItem{Cat: "vpn", Key: m[1], Label: m[1]})
	}
	return out
}

// parseScutilProxy lists the proxies `scutil --proxy` shows as enabled.
func parseScutilProxy(s string) []string {
	kv := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, " : "); ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	var out []string
	for _, p := range []string{"HTTP", "HTTPS", "SOCKS", "FTP", "RTSP", "Gopher"} {
		if kv[p+"Enable"] == "1" && kv[p+"Proxy"] != "" {
			out = append(out, fmt.Sprintf("%s proxy %s", p, net.JoinHostPort(kv[p+"Proxy"], kv[p+"Port"])))
		}
	}
	if kv["ProxyAutoConfigEnable"] == "1" {
		out = append(out, "automatic proxy configuration from "+kv["ProxyAutoConfigURLString"])
	}
	if kv["ProxyAutoDiscoveryEnable"] == "1" {
		out = append(out, "automatic proxy discovery (WPAD)")
	}
	return out
}

func macAccountItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	for _, line := range strings.Split(h.run(ctx, "dscl", ".", "-list", "/Users", "UniqueID"), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(f[0], "_") {
			continue
		}
		if uid, err := strconv.Atoi(f[1]); err == nil && uid >= 501 && uid < 100000 {
			out = append(out, hostItem{Cat: "user", Key: f[0], Label: f[0]})
		}
	}
	s := h.run(ctx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	if _, members, ok := strings.Cut(s, ":"); ok {
		for _, m := range strings.Fields(members) {
			if m != "root" {
				out = append(out, hostItem{Cat: "admin", Key: m, Label: m})
			}
		}
	}
	return out
}

// ---- Linux ----

func linuxStartupItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	type src struct {
		dir, ext, key string
	}
	for _, s := range []src{
		{filepath.Join(h.home, ".config/autostart"), ".desktop", "Exec="},
		{filepath.Join(h.home, ".config/systemd/user"), ".service", "ExecStart="},
		{filepath.Join(h.home, ".config/systemd/user"), ".timer", ""},
		{"/etc/systemd/system", ".service", "ExecStart="},
		{"/etc/systemd/system", ".timer", ""},
		{"/etc/cron.d", "", ""},
	} {
		entries, err := h.readDir(s.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.HasPrefix(name, ".") || ownAgent(name) || (s.ext != "" && !strings.HasSuffix(name, s.ext)) {
				continue
			}
			if e.Type()&os.ModeSymlink != 0 {
				continue // a distribution unit linked in, not one written here
			}
			p := filepath.Join(s.dir, name)
			prog := ""
			if s.key != "" {
				if data, err := h.readFile(p); err == nil {
					prog = iniValue(string(data), s.key)
				}
			}
			out = append(out, startupItem(p, name, prog))
		}
	}
	if _, err := h.readFile("/etc/rc.local"); err == nil {
		out = append(out, startupItem("/etc/rc.local", "/etc/rc.local", ""))
	}
	return out
}

// iniValue returns the program part of the first key= line, e.g. Exec=.
func iniValue(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			v := strings.TrimLeft(strings.TrimPrefix(line, key), "-@+!:")
			if f := strings.Fields(v); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

func linuxCertItems(h *hostOS) []hostItem {
	var out []hostItem
	for _, dir := range []string{"/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors", "/etc/ca-certificates/trust-source/anchors"} {
		entries, err := h.readDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			out = append(out, hostItem{Cat: "cert", Key: p, Label: p})
		}
	}
	return out
}

var envProxyRe = regexp.MustCompile(`(?i)^\s*(?:export\s+)?((?:https?|ftp|all)_proxy)\s*=\s*"?([^"\s]+)`)

func linuxNetItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	if data, err := h.readFile("/etc/environment"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if m := envProxyRe.FindStringSubmatch(line); m != nil {
				p := strings.ToLower(m[1]) + "=" + m[2]
				out = append(out, hostItem{Cat: "proxy", Key: p, Label: p + " in /etc/environment"})
			}
		}
	}
	if mode := strings.Trim(h.run(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode"), "' \n"); mode == "manual" || mode == "auto" {
		out = append(out, hostItem{Cat: "proxy", Key: "gnome:" + mode, Label: "desktop proxy setting (" + mode + ")"})
	}
	files := []string{"/etc/systemd/resolved.conf"}
	if entries, err := h.readDir("/etc/systemd/resolved.conf.d"); err == nil {
		for _, e := range entries {
			files = append(files, filepath.Join("/etc/systemd/resolved.conf.d", e.Name()))
		}
	}
	for _, f := range files {
		data, err := h.readFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "DNS=") && len(line) > 4 && !strings.Contains(f, "yaklite") {
				out = append(out, hostItem{Cat: "dns", Key: f + ":" + line, Label: line[4:] + " in " + f})
			}
		}
	}
	return out
}

func linuxAccountItems(h *hostOS) []hostItem {
	var out []hostItem
	if data, err := h.readFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 7 {
				continue
			}
			uid, err := strconv.Atoi(f[2])
			shell := f[6]
			if err != nil || (uid != 0 && (uid < 1000 || uid >= 60000)) || strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
				continue
			}
			label := f[0]
			if uid == 0 && f[0] != "root" {
				label += " (with root's user ID 0)"
			}
			out = append(out, hostItem{Cat: "user", Key: f[0], Label: label})
		}
	}
	if data, err := h.readFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 4 || (f[0] != "sudo" && f[0] != "wheel" && f[0] != "admin") {
				continue
			}
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					out = append(out, hostItem{Cat: "admin", Key: m, Label: m})
				}
			}
		}
	}
	return out
}

func cronItems(ctx context.Context, h *hostOS) []hostItem {
	if h.goos == "windows" {
		return nil
	}
	var out []hostItem
	for _, line := range strings.Split(h.run(ctx, "crontab", "-l"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || strings.HasPrefix(line, "no crontab") || strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}
		f := strings.Fields(line)
		prog := ""
		if len(f) > 5 {
			prog = f[5]
		}
		it := startupItem("cron:"+line, "scheduled task (crontab)", prog)
		out = append(out, it)
	}
	return out
}

// ---- failed logins ----

var failedLoginRe = regexp.MustCompile(`(?:Failed password|Invalid user|authentication failure).*?(?:from|rhost=)\s*(\S+)`)

// failedLoginFindings counts failed SSH logins in the last hour, when this
// computer offers SSH.
func failedLoginFindings(ctx context.Context, h *hostOS, socks []sock) []*Finding {
	ssh := false
	for _, s := range socks {
		if s.State == "LISTEN" && s.LocalPort == 22 && !s.LocalIP.IsLoopback() {
			ssh = true
		}
	}
	if !ssh {
		return nil
	}
	var logText string
	switch h.goos {
	case "linux":
		logText = h.run(ctx, "journalctl", "-q", "--no-pager", "--since", "-1h", "_COMM=sshd")
	case "darwin":
		logText = h.run(ctx, "log", "show", "--last", "1h", "--style", "syslog", "--predicate", `process == "sshd"`)
	}
	return failedLoginsFrom(logText, time.Now())
}

func failedLoginsFrom(logText string, now time.Time) []*Finding {
	counts := map[string]int{}
	for _, line := range strings.Split(logText, "\n") {
		if m := failedLoginRe.FindStringSubmatch(line); m != nil {
			ip := strings.TrimSuffix(m[1], ",")
			if net.ParseIP(ip) != nil {
				counts[ip]++
			}
		}
	}
	var out []*Finding
	for ip, n := range counts {
		if n < 5 {
			continue
		}
		who := ip
		sev := sevMedium
		if pip := net.ParseIP(ip); isPublicAddr(pip) {
			sev = sevHigh
			if o, ok := lookupIP(pip); ok {
				who += " (" + o.String() + ")"
			}
		}
		out = append(out, &Finding{ID: "host:ssh-failed:" + ip, Severity: sev, Host: ip, Until: now.Add(24 * time.Hour),
			Title:  fmt.Sprintf("%d failed attempts to log in to this computer over SSH in the last hour, from %s", n, who),
			Detail: "Someone is guessing passwords.",
			Fix:    "If you do not need Remote Login, turn it off (System Settings > General > Sharing). Otherwise allow only key logins, not passwords, and remove any router port forward for port 22."})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// isOwnProcess reports whether a socket belongs to yaklite itself.
func isOwnProcess(proc string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Base(proc)), "yaklite")
}

// ---- Windows ----

func psLines(ctx context.Context, h *hostOS, script string) []string {
	var out []string
	for _, l := range strings.Split(h.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

var regValueRe = regexp.MustCompile(`^\s+(\S.*?)\s+REG_\w+\s+(.*)$`)

// parseRegQuery reads `reg query` output into name -> value.
func parseRegQuery(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if m := regValueRe.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			out[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return out
}

func windowsHostItems(ctx context.Context, h *hostOS) []hostItem {
	var out []hostItem
	for _, key := range []string{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`} {
		for name, val := range parseRegQuery(h.run(ctx, "reg", "query", key)) {
			if ownAgent(name) || strings.HasPrefix(strings.ToLower(name), "yaklite") {
				continue
			}
			out = append(out, startupItem(key+`\`+name, name, val))
		}
	}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		dir := filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`)
		if entries, err := h.readDir(dir); err == nil {
			for _, e := range entries {
				if e.Name() != "desktop.ini" {
					out = append(out, startupItem(filepath.Join(dir, e.Name()), e.Name(), ""))
				}
			}
		}
	}
	for _, l := range psLines(ctx, h, `Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object { $_.TaskPath + $_.TaskName + '|' + ($_.Actions | Select-Object -First 1).Execute }`) {
		name, prog, _ := strings.Cut(l, "|")
		if strings.Contains(strings.ToLower(name), "yaklite") {
			continue
		}
		out = append(out, startupItem("task:"+name, "scheduled task "+name, prog))
	}
	for _, l := range psLines(ctx, h, `Get-ChildItem Cert:\LocalMachine\Root,Cert:\CurrentUser\Root | ForEach-Object { $_.Thumbprint + '|' + $_.Subject }`) {
		thumb, subj, _ := strings.Cut(l, "|")
		out = append(out, hostItem{Cat: "cert", Key: thumb, Label: subj})
	}
	is := parseRegQuery(h.run(ctx, "reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`))
	if is["ProxyEnable"] == "0x1" && is["ProxyServer"] != "" {
		out = append(out, hostItem{Cat: "proxy", Key: "proxy:" + is["ProxyServer"], Label: "proxy " + is["ProxyServer"]})
	}
	if is["AutoConfigURL"] != "" {
		out = append(out, hostItem{Cat: "proxy", Key: "pac:" + is["AutoConfigURL"], Label: "automatic proxy configuration from " + is["AutoConfigURL"]})
	}
	for _, l := range psLines(ctx, h, `Get-LocalUser | Where-Object Enabled | ForEach-Object Name`) {
		out = append(out, hostItem{Cat: "user", Key: l, Label: l})
	}
	for _, l := range psLines(ctx, h, `Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object Name`) {
		out = append(out, hostItem{Cat: "admin", Key: l, Label: l})
	}
	return out
}
