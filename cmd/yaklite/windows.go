package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Windows support: background jobs through Task Scheduler, notifications
// through the built-in toast API, and the self check. Everything here goes
// through PowerShell or built-in tools; values are passed in environment
// variables or single-quoted, never pasted into a command line unescaped.

// ---- self check ----

func windowsSelfCheck(ctx context.Context, run runner) []*Finding {
	var out []*Finding
	if s := run(ctx, "netsh", "advfirewall", "show", "allprofiles", "state"); s != "" {
		off := 0
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && strings.EqualFold(f[0], "State") && strings.EqualFold(f[1], "OFF") {
				off++
			}
		}
		if off > 0 {
			out = append(out, &Finding{ID: "self:firewall-off", Severity: sevMedium,
				Title: fmt.Sprintf("The Windows firewall is off for %d of its network types", off),
				Fix:   "Turn it on in Settings > Privacy & security > Windows Security > Firewall & network protection."})
		}
	}
	if s := run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`$s = Get-MpComputerStatus; "$($s.RealTimeProtectionEnabled)|$($s.AMRunningMode)|$($s.AntivirusSignatureAge)"`); s != "" {
		if rt, mode, age, ok := parseDefender(s); ok {
			switch {
			case strings.EqualFold(mode, "Passive") || strings.Contains(strings.ToLower(mode), "not running"):
				// another antivirus is in charge
			case !rt:
				out = append(out, &Finding{ID: "self:defender-off", Severity: sevHigh,
					Title: "Microsoft Defender real-time protection is off",
					Fix:   "Turn it on in Settings > Privacy & security > Windows Security > Virus & threat protection > Manage settings."})
			case age > 7:
				out = append(out, &Finding{ID: "self:defender-old", Severity: sevMedium,
					Title: fmt.Sprintf("Microsoft Defender's virus definitions are %d days old", age),
					Fix:   "Run Windows Update, or click \"Check for updates\" under Virus & threat protection."})
			}
		}
	}
	if s := run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')`); strings.TrimSpace(s) == "2" {
		out = append(out, &Finding{ID: "self:disk-unencrypted", Severity: sevMedium,
			Title: "The system drive is not encrypted, so anyone with the laptop can read its files",
			Fix:   "Turn on Device encryption or BitLocker in Settings > Privacy & security > Device encryption (Windows Home calls it Device encryption)."})
	}
	lua := parseRegQuery(run(ctx, "reg", "query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "EnableLUA"))
	if lua["EnableLUA"] == "0x0" {
		out = append(out, &Finding{ID: "self:uac-off", Severity: sevHigh,
			Title: "User Account Control is off, so any program can change Windows without asking",
			Fix:   "Search the Start menu for \"Change User Account Control settings\" and move the slider back to the default."})
	}
	rdp := parseRegQuery(run(ctx, "reg", "query", `HKLM\System\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections"))
	if rdp["fDenyTSConnections"] == "0x0" {
		out = append(out, &Finding{ID: "self:rdp-on", Severity: sevLow,
			Title: "Remote Desktop is turned on",
			Fix:   "If you do not use it, turn it off in Settings > System > Remote Desktop."})
	}
	return out
}

func parseDefender(s string) (rt bool, mode string, age int, ok bool) {
	parts := strings.Split(strings.TrimSpace(s), "|")
	if len(parts) != 3 {
		return false, "", 0, false
	}
	switch strings.ToLower(parts[0]) {
	case "true":
		rt = true
	case "false":
	default:
		return false, "", 0, false
	}
	fmt.Sscan(parts[2], &age)
	return rt, parts[1], age, true
}

// ---- notifications ----

const toastScript = `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$n = $x.GetElementsByTagName('text')
$n.Item(0).AppendChild($x.CreateTextNode($env:YAKLITE_TITLE)) | Out-Null
$n.Item(1).AppendChild($x.CreateTextNode($env:YAKLITE_BODY)) | Out-Null
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))`

func notifyWindows(title, body string) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", toastScript)
	cmd.Env = append(os.Environ(), "YAKLITE_TITLE="+title, "YAKLITE_BODY="+body)
	cmd.Run()
}

// ---- background jobs ----

// winArg quotes one argument the way Windows programs split command lines.
func winArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
			slashes = 0
			b.WriteRune(r)
			continue
		default:
			slashes = 0
		}
		b.WriteRune(r)
	}
	b.WriteString(strings.Repeat(`\`, slashes))
	b.WriteByte('"')
	return b.String()
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type winTask struct {
	name    string
	args    []string
	trigger string // PowerShell expression for the trigger(s)
	daemon  bool
}

// windowsTasks are the Task Scheduler jobs for the wanted labels.
func windowsTasks(j jobArgs, want map[string]bool, every time.Duration) []winTask {
	mins := int(every.Minutes())
	if mins < 5 {
		mins = 5
	}
	logon := "New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME"
	all := []struct {
		label string
		t     winTask
	}{
		{agentLabel, winTask{"auto", j.auto, fmt.Sprintf("@((%s), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes %d)))", logon, mins), false}},
		{webLabel, winTask{"web", j.web, logon, true}},
		{connLabel, winTask{"conn", j.conn, logon, true}},
		{summaryLabel, winTask{"summary", j.summary, "New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am", false}},
		{routerLabel, winTask{"routerlog", j.router, logon, true}},
		{tripLabel, winTask{"tripwire", j.trip, logon, true}},
	}
	var out []winTask
	for _, x := range all {
		if want[x.label] {
			out = append(out, x.t)
		}
	}
	return out
}

// windowsInstallScript registers the jobs. They run hidden through
// conhost --headless so no console window flashes up.
func windowsInstallScript(bin string, tasks []winTask) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("Get-ScheduledTask -TaskPath '\\yaklite\\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false\n")
	for _, t := range tasks {
		args := []string{"--headless", winArg(bin)}
		for _, a := range t.args {
			args = append(args, winArg(a))
		}
		settings := "New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)"
		if t.daemon {
			settings = "New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit 0 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)"
		}
		fmt.Fprintf(&b, "Register-ScheduledTask -TaskPath '\\yaklite\\' -TaskName %s -Action (New-ScheduledTaskAction -Execute 'conhost.exe' -Argument %s) -Trigger %s -Settings (%s) -Force | Out-Null\n",
			psQuote(t.name), psQuote(strings.Join(args, " ")), t.trigger, settings)
		if t.daemon || t.name == "auto" {
			fmt.Fprintf(&b, "Start-ScheduledTask -TaskPath '\\yaklite\\' -TaskName %s\n", psQuote(t.name))
		}
	}
	return b.String()
}

func windowsMarker() string { return filepath.Join(configDir(), "windows-tasks") }

func installWindows(bin string, j jobArgs, want map[string]bool, every time.Duration) error {
	tasks := windowsTasks(j, want, every)
	if err := run("powershell", "-NoProfile", "-NonInteractive", "-Command", windowsInstallScript(bin, tasks)); err != nil {
		return err
	}
	var names []string
	for _, t := range tasks {
		names = append(names, t.name)
	}
	os.MkdirAll(configDir(), 0o700)
	return writeFilePrivate(windowsMarker(), []byte(strings.Join(names, "\n")+"\n"))
}

func uninstallWindows() {
	exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-ScheduledTask -TaskPath '\yaklite\' -ErrorAction SilentlyContinue | ForEach-Object { Stop-ScheduledTask -InputObject $_; Unregister-ScheduledTask -InputObject $_ -Confirm:$false }`).Run()
}
