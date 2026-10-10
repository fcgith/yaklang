package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	agentLabel   = "io.github.yaklite.auto"
	webLabel     = "io.github.yaklite.web"
	connLabel    = "io.github.yaklite.conn"
	summaryLabel = "io.github.yaklite.summary"
)

var allLabels = []string{agentLabel, webLabel, connLabel, summaryLabel}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

func installedBinPath() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(homeDir(), "Library", "Application Support", "yaklite", "yaklite")
	}
	return filepath.Join(homeDir(), ".local", "bin", "yaklite")
}

func agentFiles() []string {
	switch runtime.GOOS {
	case "darwin":
		dir := filepath.Join(homeDir(), "Library", "LaunchAgents")
		var out []string
		for _, l := range allLabels {
			out = append(out, filepath.Join(dir, l+".plist"))
		}
		return out
	case "linux":
		dir := filepath.Join(homeDir(), ".config", "systemd", "user")
		var out []string
		for _, n := range systemdUnitNames {
			out = append(out, filepath.Join(dir, n))
		}
		return out
	}
	return nil
}

func installedAgent() string {
	for _, f := range agentFiles() {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return ""
}

func xmlEsc(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// launchdPlist describes a per-user background job. The auto job runs at
// login, every interval, and whenever the network configuration changes
// (joining a new Wi-Fi network rewrites files under SystemConfiguration).
func launchdPlist(label string, args []string, interval time.Duration, keepAlive bool, logPath string) string {
	return launchdPlistAt(label, args, interval, keepAlive, -1, logPath)
}

// launchdPlistAt also supports a weekly job: weekday 0-6 (Sunday is 0) at 09:00.
func launchdPlistAt(label string, args []string, interval time.Duration, keepAlive bool, weekday int, logPath string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + xmlEsc(label) + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range args {
		b.WriteString("\t\t<string>" + xmlEsc(a) + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	runAtLoad := true
	if keepAlive {
		b.WriteString("\t<key>KeepAlive</key><true/>\n")
	} else if weekday >= 0 {
		b.WriteString("\t<key>StartCalendarInterval</key><dict><key>Weekday</key><integer>" + strconv.Itoa(weekday) + "</integer><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>\n")
		runAtLoad = false
	} else {
		b.WriteString("\t<key>StartInterval</key><integer>" + strconv.Itoa(int(interval.Seconds())) + "</integer>\n")
		b.WriteString("\t<key>WatchPaths</key><array><string>/Library/Preferences/SystemConfiguration</string></array>\n")
		b.WriteString("\t<key>ThrottleInterval</key><integer>60</integer>\n")
	}
	if runAtLoad {
		b.WriteString("\t<key>RunAtLoad</key><true/>\n")
	}
	b.WriteString(`	<key>ProcessType</key><string>Background</string>
	<key>LowPriorityIO</key><true/>
	<key>Nice</key><integer>10</integer>
	<key>StandardOutPath</key><string>` + xmlEsc(logPath) + `</string>
	<key>StandardErrorPath</key><string>` + xmlEsc(logPath) + `</string>
</dict>
</plist>
`)
	return b.String()
}

func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s) + `"`
}

var systemdUnitNames = []string{"yaklite-auto.service", "yaklite-auto.timer", "yaklite-web.service", "yaklite-conn.service", "yaklite-summary.service", "yaklite-summary.timer"}

func systemdCmd(bin string, args []string) string {
	cmd := systemdQuote(bin)
	for _, a := range args {
		cmd += " " + systemdQuote(a)
	}
	return cmd
}

func systemdUnits(bin string, autoArgs, connArgs, summaryArgs []string, interval time.Duration) map[string]string {
	cmd := systemdCmd(bin, autoArgs)
	return map[string]string{
		"yaklite-conn.service": `[Unit]
Description=yaklite connection watch

[Service]
ExecStart=` + systemdCmd(bin, connArgs) + `
Restart=always
RestartSec=30
Nice=10

[Install]
WantedBy=default.target
`,
		"yaklite-summary.service": `[Unit]
Description=yaklite weekly summary

[Service]
Type=oneshot
ExecStart=` + systemdCmd(bin, summaryArgs) + `
`,
		"yaklite-summary.timer": `[Unit]
Description=yaklite weekly summary timer

[Timer]
OnCalendar=Mon *-*-* 09:00:00
Persistent=true

[Install]
WantedBy=timers.target
`,
		"yaklite-auto.service": `[Unit]
Description=yaklite network check

[Service]
Type=oneshot
ExecStart=` + cmd + `
SuccessExitStatus=3
Nice=10
`,
		"yaklite-auto.timer": `[Unit]
Description=yaklite network check timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=` + strconv.Itoa(int(interval.Minutes())) + `min
RandomizedDelaySec=2min

[Install]
WantedBy=timers.target
`,
		"yaklite-web.service": `[Unit]
Description=yaklite dashboard (localhost only)

[Service]
ExecStart=` + systemdQuote(bin) + ` serve
Restart=on-failure

[Install]
WantedBy=default.target
`,
	}
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cmdInstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	every := fs.Duration("every", time.Hour, "how often to check (it also checks whenever you join a network, on macOS)")
	webhook := fs.String("webhook", "", "also send alerts here: ntfy (with phone buttons), Discord, Telegram, Slack, Gotify, Pushover, Home Assistant, or smtps://user@host/you@example.com; comma separated for several")
	noDash := fs.Bool("no-dashboard", false, "do not run the local dashboard on http://127.0.0.1:9842")
	noConn := fs.Bool("no-connwatch", false, "do not watch this computer's connections (from the internet, with known attackers, to new countries)")
	noSummary := fs.Bool("no-summary", false, "do not send a weekly summary on Monday mornings")
	yes := fs.Bool("y", false, "do not ask questions (the current network stays untrusted)")
	fs.Parse(args)
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errors.New("install supports macOS and Linux; on other systems run `yaklite auto` from a scheduled task")
	}
	if err := validateWebhooks(*webhook); err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	bin := installedBinPath()
	if self != bin {
		if err := copyFile(self, bin); err != nil {
			return fmt.Errorf("copy binary to %s: %w", bin, err)
		}
		if runtime.GOOS == "darwin" {
			// a browser download is quarantined; the copy is the user's own choice
			exec.Command("xattr", "-d", "com.apple.quarantine", bin).Run()
		}
	}
	fmt.Println("Installed", bin)

	n, err := currentNetwork(ctx)
	if err == nil && !*yes {
		nf, _ := loadNetworks()
		if k := nf.Networks[n.ID()]; k == nil || !k.Trusted {
			fmt.Printf("\nYou are on %s (router %s).\n", n.CIDR, n.Gateway)
			if askYesNo("Is this your own network (home or office) that you are allowed to scan?", false) {
				name := askLine("Name for it:", "Home")
				if err := cmdTrust(ctx, []string{"--name", name}, true); err != nil {
					return err
				}
			} else {
				fmt.Println("OK, on this network yaklite will only check what this computer exposes.")
			}
		}
	}

	autoArgs := []string{"auto", "-q"}
	connArgs := []string{"connwatch", "-q", "--notify"}
	summaryArgs := []string{"summary", "--send"}
	if *webhook != "" {
		autoArgs = append(autoArgs, "--webhook", *webhook)
		connArgs = append(connArgs, "--webhook", *webhook)
		summaryArgs = append(summaryArgs, "--webhook", *webhook)
	}
	logDir := filepath.Join(defaultStateDir())
	os.MkdirAll(logDir, 0o700)
	want := map[string]bool{agentLabel: true, webLabel: !*noDash, connLabel: !*noConn, summaryLabel: !*noSummary}

	switch runtime.GOOS {
	case "darwin":
		uid := strconv.Itoa(os.Getuid())
		dir := filepath.Join(homeDir(), "Library", "LaunchAgents")
		contents := map[string]string{
			agentLabel:   launchdPlist(agentLabel, append([]string{bin}, autoArgs...), *every, false, filepath.Join(logDir, "auto.log")),
			webLabel:     launchdPlist(webLabel, []string{bin, "serve"}, 0, true, filepath.Join(logDir, "web.log")),
			connLabel:    launchdPlist(connLabel, append([]string{bin}, connArgs...), 0, true, filepath.Join(logDir, "conn.log")),
			summaryLabel: launchdPlistAt(summaryLabel, append([]string{bin}, summaryArgs...), 0, false, 1, filepath.Join(logDir, "summary.log")),
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for _, label := range allLabels {
			path := filepath.Join(dir, label+".plist")
			exec.Command("launchctl", "bootout", "gui/"+uid+"/"+label).Run()
			if !want[label] {
				os.Remove(path)
				continue
			}
			if err := os.WriteFile(path, []byte(contents[label]), 0o644); err != nil {
				return err
			}
			if err := run("launchctl", "bootstrap", "gui/"+uid, path); err != nil {
				return err
			}
		}
	case "linux":
		dir := filepath.Dir(agentFiles()[0])
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		units := systemdUnits(bin, autoArgs, connArgs, summaryArgs, *every)
		skip := map[string]bool{"yaklite-web.service": *noDash, "yaklite-conn.service": *noConn, "yaklite-summary.service": *noSummary, "yaklite-summary.timer": *noSummary}
		for name, content := range units {
			if skip[name] {
				os.Remove(filepath.Join(dir, name))
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return err
			}
		}
		if err := run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		enable := []string{"--user", "enable", "--now", "yaklite-auto.timer"}
		for _, u := range []string{"yaklite-web.service", "yaklite-conn.service", "yaklite-summary.timer"} {
			if !skip[u] {
				enable = append(enable, u)
			}
		}
		if err := run("systemctl", enable...); err != nil {
			return err
		}
		exec.Command("systemctl", "--user", "start", "yaklite-auto.service").Start()
	}

	fmt.Println("\nBackground checks are on. yaklite checks every", every.String(), "and when you join a network (macOS),")
	fmt.Println("and shows a notification when it finds something worth your attention.")
	if !*noConn {
		fmt.Println("It also watches this computer's connections: someone on the internet connecting in, and known attackers.")
	}
	if !*noSummary {
		fmt.Println("A short summary arrives every Monday at 9:00.")
	}
	if !*noDash {
		fmt.Println("Dashboard: http://127.0.0.1:9842/")
	}
	fmt.Println("\nUseful next steps:")
	fmt.Println("  yaklite status                       what network you are on and when it was last checked")
	fmt.Println("  yaklite trust --name Office          monitor every device on the current network")
	fmt.Println(`  yaklite name 192.168.1.10 "NAS" --expect 22,443   name a device and the ports it may expose`)
	fmt.Println("  yaklite uninstall                    stop background checks")
	return nil
}

func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete state, settings and the installed binary")
	fs.Parse(args)
	switch runtime.GOOS {
	case "darwin":
		uid := strconv.Itoa(os.Getuid())
		for _, l := range allLabels {
			exec.Command("launchctl", "bootout", "gui/"+uid+"/"+l).Run()
		}
	case "linux":
		exec.Command("systemctl", "--user", "disable", "--now", "yaklite-auto.timer", "yaklite-web.service", "yaklite-conn.service", "yaklite-summary.timer").Run()
	}
	for _, f := range agentFiles() {
		os.Remove(f)
	}
	if runtime.GOOS == "linux" {
		exec.Command("systemctl", "--user", "daemon-reload").Run()
	}
	fmt.Println("Background checks removed.")
	if *purge {
		for _, p := range []string{defaultStateDir(), configDir(), installedBinPath()} {
			os.RemoveAll(p)
			fmt.Println("removed", p)
		}
	}
	return nil
}
