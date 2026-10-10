package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// The self check looks at this computer's own safety settings. It only reads
// settings; it changes nothing and needs no admin password.

func init() {
	registerCheck(&check{name: "self", about: "this computer's own settings: firewall, disk encryption, updates, sharing", run: selfCheck})
}

// cmdOut runs a command and returns its combined output, or "" if it could not run.
func cmdOut(ctx context.Context, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func selfCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	var out []*Finding
	switch runtime.GOOS {
	case "darwin":
		out = macSelfCheck(ctx, cmdOut)
	case "linux":
		out = linuxSelfCheck(ctx, cmdOut, os.ReadFile)
	}
	if socks, err := listSockets(ctx); err == nil {
		out = append(out, sharingFindings(socks)...)
	}
	return out, nil
}

type runner func(ctx context.Context, name string, args ...string) string

func macSelfCheck(ctx context.Context, run runner) []*Finding {
	var out []*Finding
	fw := "/usr/libexec/ApplicationFirewall/socketfilterfw"
	if s := run(ctx, fw, "--getglobalstate"); s != "" && (strings.Contains(s, "disabled") || strings.Contains(s, "State = 0")) {
		out = append(out, &Finding{ID: "self:firewall-off", Severity: sevMedium,
			Title: "The Mac firewall is off",
			Fix:   "Turn it on in System Settings > Network > Firewall. It blocks other machines from reaching apps that did not ask for it."})
	} else if s != "" {
		if st := run(ctx, fw, "--getstealthmode"); strings.Contains(st, "disabled") || strings.Contains(st, "off") {
			out = append(out, &Finding{ID: "self:stealth-off", Severity: sevLow,
				Title: "Firewall stealth mode is off, so this Mac answers probes from other machines",
				Fix:   "Turn on Stealth Mode in System Settings > Network > Firewall > Options."})
		}
	}
	if s := run(ctx, "fdesetup", "status"); strings.Contains(s, "FileVault is Off") {
		out = append(out, &Finding{ID: "self:filevault-off", Severity: sevMedium,
			Title: "Disk encryption (FileVault) is off, so anyone with the laptop can read its files",
			Fix:   "Turn on FileVault in System Settings > Privacy & Security."})
	}
	if s := run(ctx, "csrutil", "status"); strings.Contains(s, "disabled") {
		out = append(out, &Finding{ID: "self:sip-off", Severity: sevHigh,
			Title: "System Integrity Protection is off, which lets malware change macOS itself",
			Fix:   "Restart into Recovery (hold the power button), open Terminal and run: csrutil enable"})
	}
	if s := run(ctx, "spctl", "--status"); strings.Contains(s, "disabled") {
		out = append(out, &Finding{ID: "self:gatekeeper-off", Severity: sevHigh,
			Title: "Gatekeeper is off, so apps from anywhere run without a check",
			Fix:   "Run in Terminal: sudo spctl --master-enable"})
	}
	su := "/Library/Preferences/com.apple.SoftwareUpdate"
	if s := run(ctx, "defaults", "read", su, "AutomaticCheckEnabled"); s == "0" {
		out = append(out, &Finding{ID: "self:updates-check-off", Severity: sevMedium,
			Title: "macOS does not check for updates automatically",
			Fix:   "Turn on automatic updates in System Settings > General > Software Update."})
	}
	if s := run(ctx, "defaults", "read", su, "CriticalUpdateInstall"); s == "0" {
		out = append(out, &Finding{ID: "self:security-updates-off", Severity: sevMedium,
			Title: "Security responses and system files are not installed automatically",
			Fix:   "Turn on \"Install Security Responses and system files\" in System Settings > General > Software Update > Automatic updates."})
	}
	if s := run(ctx, "defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"); s == "1" {
		out = append(out, &Finding{ID: "self:guest-on", Severity: sevLow,
			Title: "The guest account is on",
			Fix:   "Turn it off in System Settings > Users & Groups."})
	}
	return out
}

func linuxSelfCheck(ctx context.Context, run runner, read func(string) ([]byte, error)) []*Finding {
	var out []*Finding
	active := func(unit string) bool { return run(ctx, "systemctl", "is-active", unit) == "active" }
	if run(ctx, "systemctl", "--version") != "" && !active("firewalld") && !active("ufw") && !active("nftables") && !active("iptables") {
		out = append(out, &Finding{ID: "self:firewall-off", Severity: sevLow,
			Title: "No firewall service (ufw, firewalld or nftables) is running",
			Fix:   "Install and enable one, for example: sudo ufw enable"})
	}
	if lsblk := run(ctx, "lsblk", "-o", "TYPE,MOUNTPOINT", "-n", "-l"); lsblk != "" && !strings.Contains(lsblk, "crypt") {
		out = append(out, &Finding{ID: "self:disk-unencrypted", Severity: sevLow,
			Title: "No encrypted disk found, so anyone with the machine can read its files",
			Fix:   "For a laptop, reinstall with full disk encryption (LUKS) when you next can."})
	}
	if data, err := read("/etc/ssh/sshd_config"); err == nil {
		cfg := sshdSettings(string(data))
		if cfg["permitrootlogin"] == "yes" {
			out = append(out, &Finding{ID: "self:ssh-root", Severity: sevMedium,
				Title: "SSH allows logging in as root with a password",
				Fix:   "Set PermitRootLogin prohibit-password (or no) in /etc/ssh/sshd_config and restart sshd."})
		}
		if cfg["passwordauthentication"] == "yes" && cfg["permitemptypasswords"] == "yes" {
			out = append(out, &Finding{ID: "self:ssh-empty-passwords", Severity: sevHigh,
				Title: "SSH allows accounts with empty passwords",
				Fix:   "Set PermitEmptyPasswords no in /etc/ssh/sshd_config and restart sshd."})
		}
	}
	return out
}

// sshdSettings reads the first value of each keyword, as sshd does.
func sshdSettings(cfg string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(cfg))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		k := strings.ToLower(f[0])
		if k == "match" {
			break // conditional blocks do not apply to everyone
		}
		if _, ok := out[k]; !ok {
			out[k] = strings.ToLower(f[1])
		}
	}
	return out
}

var sharingPorts = map[int][2]string{
	22:   {"Remote Login (SSH)", sevLow},
	445:  {"File Sharing (SMB)", sevMedium},
	548:  {"File Sharing (AFP)", sevMedium},
	5900: {"Screen Sharing (VNC)", sevMedium},
	3283: {"Apple Remote Desktop", sevMedium},
	3031: {"Remote Apple Events", sevMedium},
	3389: {"Remote Desktop", sevMedium},
	631:  {"Printer Sharing", sevLow},
}

// sharingFindings lists remote-access and sharing services this computer
// offers to other machines.
func sharingFindings(socks []sock) []*Finding {
	var out []*Finding
	seen := map[int]bool{}
	for _, s := range socks {
		if s.State != "LISTEN" || s.LocalIP.IsLoopback() || seen[s.LocalPort] {
			continue
		}
		sp, ok := sharingPorts[s.LocalPort]
		if !ok {
			continue
		}
		seen[s.LocalPort] = true
		out = append(out, &Finding{ID: "self:sharing:" + strings.ToLower(strings.Fields(sp[0])[0]+"-"+strings.Fields(sp[0])[1]), Severity: sp[1],
			Title: sp[0] + " is on, so other machines on the network can try to log in to this computer",
			Fix:   "If you do not use it, turn it off (on a Mac: System Settings > General > Sharing). If you do, use a strong password and keep it off on public Wi-Fi."})
	}
	return out
}
