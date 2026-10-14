package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// The firewall command loads the known-attacker lists into this computer's
// own firewall, so those addresses are blocked both ways instead of only
// reported. It needs admin rights. On macOS it uses pf in its own anchor
// (com.apple/yaklite), on Linux its own nftables table, on Windows its own
// firewall rules; it never edits the system's own rules.

const firewallUsage = `usage: sudo yaklite firewall apply|remove|status|install|uninstall

  apply      download the lists and load them into the firewall now
  remove     take yaklite's rules out of the firewall
  status     show whether the rules are loaded
  install    apply now, at every boot and every 12 hours (a root background job)
  uninstall  remove the background job and the rules`

func firewallDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/db/yaklite"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "yaklite")
	}
	return "/var/lib/yaklite"
}

// never block these, whatever a list says
var firewallKeep = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222"}

// blockEntries lists the addresses and networks to block, split by family.
func blockEntries(t *threatSet) (v4, v6 []string) {
	keep := make([]net.IP, 0, len(firewallKeep))
	for _, k := range firewallKeep {
		keep = append(keep, net.ParseIP(k))
	}
	add := func(s string, ip net.IP) {
		if ip.To4() != nil {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	for s := range t.ips {
		ip := net.ParseIP(s)
		if ip == nil || containsIP(keep, ip) {
			continue
		}
		add(s, ip)
	}
next:
	for _, n := range t.nets {
		for _, k := range keep {
			if n.n.Contains(k) {
				continue next
			}
		}
		add(n.n.String(), n.n.IP)
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, k := range list {
		if k.Equal(ip) {
			return true
		}
	}
	return false
}

func pfRules(table string) string {
	return fmt.Sprintf(`table <yaklite_bad> persist file %q
block drop in quick from <yaklite_bad> to any
block return out quick from any to <yaklite_bad>
`, table)
}

func nftScript(v4, v6 []string) string {
	var b strings.Builder
	b.WriteString("table inet yaklite {\n")
	set := func(name, typ string, els []string) {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\tauto-merge\n", name, typ)
		if len(els) > 0 {
			b.WriteString("\t\telements = { " + strings.Join(els, ", ") + " }\n")
		}
		b.WriteString("\t}\n")
	}
	set("bad4", "ipv4_addr", v4)
	set("bad6", "ipv6_addr", v6)
	b.WriteString(`	chain input {
		type filter hook input priority -5; policy accept;
		ip saddr @bad4 drop
		ip6 saddr @bad6 drop
	}
	chain forward {
		type filter hook forward priority -5; policy accept;
		ip saddr @bad4 drop
		ip daddr @bad4 drop
		ip6 saddr @bad6 drop
		ip6 daddr @bad6 drop
	}
	chain output {
		type filter hook output priority -5; policy accept;
		ip daddr @bad4 reject
		ip6 daddr @bad6 reject
	}
}
`)
	return b.String()
}

// windowsRules builds a PowerShell script with rules of at most 1000
// addresses each (the firewall's practical limit per rule).
func windowsRules(all []string) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\nGet-NetFirewallRule -Group 'yaklite' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n")
	for i := 0; i < len(all); i += 1000 {
		j := min(i+1000, len(all))
		list := "'" + strings.Join(all[i:j], "','") + "'"
		for _, dir := range []string{"Inbound", "Outbound"} {
			fmt.Fprintf(&b, "New-NetFirewallRule -DisplayName 'yaklite known attackers %d %s' -Group 'yaklite' -Direction %s -Action Block -RemoteAddress @(%s) | Out-Null\n", i/1000+1, dir, dir, list)
		}
	}
	return b.String()
}

func requireAdmin() error {
	if runtime.GOOS == "windows" {
		if exec.Command("net", "session").Run() != nil {
			return errors.New("run this from an administrator PowerShell")
		}
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("this needs admin rights: run it with sudo")
	}
	return nil
}

func firewallApply(ctx context.Context, prog func(string, ...any)) error {
	dir := firewallDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	t, errs := loadThreats(ctx, dir, true)
	for _, e := range errs {
		prog("%s", e)
	}
	v4, v6 := blockEntries(t)
	if len(v4)+len(v6) == 0 {
		return errors.New("no lists could be downloaded, nothing loaded")
	}
	switch runtime.GOOS {
	case "darwin":
		table := filepath.Join(dir, "blocked.txt")
		if err := writeFilePrivate(table, []byte(strings.Join(append(v4, v6...), "\n")+"\n")); err != nil {
			return err
		}
		rules := filepath.Join(dir, "pf.rules")
		if err := writeFilePrivate(rules, []byte(pfRules(table))); err != nil {
			return err
		}
		if err := run("pfctl", "-a", "com.apple/yaklite", "-f", rules); err != nil {
			return err
		}
		// enable pf once and keep the reference token so it can be released
		tokPath := filepath.Join(dir, "pf-token")
		if _, err := os.Stat(tokPath); err != nil || !strings.Contains(cmdOut(ctx, "pfctl", "-s", "info"), "Status: Enabled") {
			out := cmdOut(ctx, "pfctl", "-E")
			if i := strings.Index(out, "Token : "); i >= 0 {
				writeFilePrivate(tokPath, []byte(strings.Fields(out[i+8:])[0]))
			}
		}
	case "linux":
		script := filepath.Join(dir, "yaklite.nft")
		if err := writeFilePrivate(script, []byte(nftScript(v4, v6))); err != nil {
			return err
		}
		exec.Command("nft", "delete", "table", "inet", "yaklite").Run()
		if err := run("nft", "-f", script); err != nil {
			return err
		}
	case "windows":
		script := filepath.Join(dir, "rules.ps1")
		if err := writeFilePrivate(script, []byte(windowsRules(append(v4, v6...)))); err != nil {
			return err
		}
		if err := run("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script); err != nil {
			return err
		}
	default:
		return fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	prog("blocking %d addresses and networks from %d lists", len(v4)+len(v6), len(threatFeeds))
	return nil
}

func firewallRemove(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("pfctl", "-a", "com.apple/yaklite", "-F", "all").Run()
		tokPath := filepath.Join(firewallDir(), "pf-token")
		if tok, err := os.ReadFile(tokPath); err == nil {
			exec.Command("pfctl", "-X", strings.TrimSpace(string(tok))).Run()
			os.Remove(tokPath)
		}
	case "linux":
		exec.Command("nft", "delete", "table", "inet", "yaklite").Run()
	case "windows":
		exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetFirewallRule -Group 'yaklite' -ErrorAction SilentlyContinue | Remove-NetFirewallRule").Run()
	}
	return nil
}

func firewallStatus(ctx context.Context) string {
	switch runtime.GOOS {
	case "darwin":
		n := len(strings.Fields(cmdOut(ctx, "pfctl", "-a", "com.apple/yaklite", "-t", "yaklite_bad", "-T", "show")))
		on := strings.Contains(cmdOut(ctx, "pfctl", "-s", "info"), "Status: Enabled")
		if n == 0 {
			return "not loaded"
		}
		if !on {
			return fmt.Sprintf("%d entries loaded, but pf is disabled", n)
		}
		return fmt.Sprintf("blocking %d addresses and networks", n)
	case "linux":
		out := cmdOut(ctx, "nft", "list", "table", "inet", "yaklite")
		if !strings.Contains(out, "bad4") {
			return "not loaded"
		}
		return "loaded (nft list table inet yaklite)"
	case "windows":
		n := cmdOut(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-NetFirewallRule -Group 'yaklite' -ErrorAction SilentlyContinue | Measure-Object).Count")
		if n == "" || n == "0" {
			return "not loaded"
		}
		return n + " yaklite rules loaded"
	}
	return "not supported here"
}

// firewallBin is the root-owned copy the background job runs, so the job
// never executes a file a normal user can replace.
func firewallBin() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramFiles"), "yaklite", "yaklite.exe")
	}
	return "/usr/local/libexec/yaklite-firewall"
}

const firewallLabel = "io.github.yaklite.firewall"

func firewallInstall(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	bin := firewallBin()
	if err := copyFile(self, bin); err != nil {
		return err
	}
	os.Chmod(bin, 0o755)
	os.Chmod(filepath.Dir(bin), 0o755)
	switch runtime.GOOS {
	case "darwin":
		p := "/Library/LaunchDaemons/" + firewallLabel + ".plist"
		plist := launchdPlist(firewallLabel, []string{bin, "firewall", "apply"}, 12*time.Hour, false, "/var/log/yaklite-firewall.log")
		plist = strings.Replace(plist, "\t<key>WatchPaths</key><array><string>/Library/Preferences/SystemConfiguration</string></array>\n", "", 1)
		if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
			return err
		}
		exec.Command("launchctl", "bootout", "system/"+firewallLabel).Run()
		return run("launchctl", "bootstrap", "system", p)
	case "linux":
		units := map[string]string{
			"yaklite-firewall.service": "[Unit]\nDescription=yaklite: block known attackers\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=" + systemdCmd(bin, []string{"firewall", "apply"}) + "\n",
			"yaklite-firewall.timer":   "[Unit]\nDescription=yaklite: refresh the known-attacker block list\n\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=12h\n\n[Install]\nWantedBy=timers.target\n",
		}
		for n, u := range units {
			if err := os.WriteFile("/etc/systemd/system/"+n, []byte(u), 0o644); err != nil {
				return err
			}
		}
		run("systemctl", "daemon-reload")
		return run("systemctl", "enable", "--now", "yaklite-firewall.timer")
	case "windows":
		return run("schtasks", "/Create", "/F", "/RU", "SYSTEM", "/SC", "HOURLY", "/MO", "12", "/TN", "yaklite-firewall", "/TR", `"`+bin+`" firewall apply`)
	}
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

func firewallUninstall(ctx context.Context) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("launchctl", "bootout", "system/"+firewallLabel).Run()
		os.Remove("/Library/LaunchDaemons/" + firewallLabel + ".plist")
	case "linux":
		exec.Command("systemctl", "disable", "--now", "yaklite-firewall.timer").Run()
		os.Remove("/etc/systemd/system/yaklite-firewall.service")
		os.Remove("/etc/systemd/system/yaklite-firewall.timer")
		exec.Command("systemctl", "daemon-reload").Run()
	case "windows":
		exec.Command("schtasks", "/Delete", "/F", "/TN", "yaklite-firewall").Run()
	}
	os.Remove(firewallBin())
}

func cmdFirewall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("firewall", flag.ExitOnError)
	quiet := fs.Bool("q", false, "quiet")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, firewallUsage) }
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	fs.Parse(args[1:])
	prog := progress(*quiet)
	if prog == nil {
		prog = func(string, ...any) {}
	}
	switch args[0] {
	case "status":
		fmt.Println("Firewall block list:", firewallStatus(ctx))
		return nil
	case "apply", "remove", "install", "uninstall":
		if err := requireAdmin(); err != nil {
			return err
		}
	default:
		fs.Usage()
		os.Exit(2)
	}
	switch args[0] {
	case "apply":
		return firewallApply(ctx, prog)
	case "remove":
		return firewallRemove(ctx)
	case "install":
		if err := firewallApply(ctx, prog); err != nil {
			return err
		}
		if err := firewallInstall(ctx); err != nil {
			return err
		}
		fmt.Println("Known attackers are now blocked, refreshed at every boot and every 12 hours.")
		fmt.Println("Undo with: sudo yaklite firewall uninstall")
	case "uninstall":
		firewallUninstall(ctx)
		firewallRemove(ctx)
		fmt.Println("Removed yaklite's firewall rules and background job.")
	}
	return nil
}
