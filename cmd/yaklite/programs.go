package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Programs talking to the internet are checked for the signs of something
// that did not come from a normal installer: running from a temporary or
// hidden folder, or (on macOS and Windows) not signed by any developer.

type exeVerdict struct {
	path     string
	unsigned bool
	oddPlace bool
	recent   bool // changed in the last 3 days
}

var exeCache sync.Map // path|mtime -> exeVerdict

// exePath finds the program file of a running process.
func exePath(ctx context.Context, pid int) string {
	if pid <= 0 {
		return ""
	}
	switch runtime.GOOS {
	case "linux":
		p, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		return p
	case "darwin":
		p := cmdOut(ctx, "ps", "-o", "comm=", "-p", strconv.Itoa(pid))
		if filepath.IsAbs(p) {
			return p
		}
		for _, line := range strings.Split(cmdOut(ctx, "lsof", "-p", strconv.Itoa(pid), "-a", "-d", "txt", "-Fn"), "\n") {
			if strings.HasPrefix(line, "n/") {
				return line[1:]
			}
		}
	case "windows":
		return cmdOut(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("(Get-Process -Id %d).Path", pid))
	}
	return ""
}

// trustedLocation is where package managers put programs they built
// themselves; those are often signed ad hoc only.
func trustedLocation(p string) bool {
	for _, pre := range []string{"/opt/homebrew/", "/usr/local/Cellar/", "/nix/store/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/System/", "/usr/libexec/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func judgeExe(ctx context.Context, path string) exeVerdict {
	v := exeVerdict{path: path}
	if strings.HasSuffix(path, " (deleted)") {
		v.oddPlace = true // still running after its file was removed
		return v
	}
	st, err := os.Stat(path)
	if err != nil {
		return v
	}
	key := path + "|" + st.ModTime().String()
	if c, ok := exeCache.Load(key); ok {
		return c.(exeVerdict)
	}
	v.oddPlace = suspiciousPath(path)
	v.recent = time.Since(st.ModTime()) < 72*time.Hour
	if !trustedLocation(path) {
		switch runtime.GOOS {
		case "darwin":
			v.unsigned = macUnsigned(cmdOut(ctx, "codesign", "-dv", "--verbose=2", path))
		case "windows":
			s := cmdOut(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("(Get-AuthenticodeSignature -LiteralPath '%s').Status", strings.ReplaceAll(path, "'", "''")))
			v.unsigned = s != "" && s != "Valid"
		}
	}
	exeCache.Store(key, v)
	return v
}

// macUnsigned reads `codesign -dv` output: no signature at all, or only an
// ad hoc one (no developer behind it).
func macUnsigned(out string) bool {
	return strings.Contains(out, "not signed at all") || strings.Contains(out, "Signature=adhoc")
}

// programFindings looks at the programs behind outbound internet
// connections.
func programFindings(ctx context.Context, views []connView, now time.Time) []*Finding {
	var out []*Finding
	done := map[int]bool{}
	for _, c := range views {
		if c.Inbound || c.PID <= 0 || done[c.PID] || c.PID == os.Getpid() || isOwnProcess(c.Process) {
			continue
		}
		done[c.PID] = true
		path := exePath(ctx, c.PID)
		if path == "" || isOwnProcess(path) {
			continue
		}
		v := judgeExe(ctx, path)
		if f := programFinding(v, c, now); f != nil {
			out = append(out, f)
		}
	}
	return out
}

func programFinding(v exeVerdict, c connView, now time.Time) *Finding {
	if !v.oddPlace && !v.unsigned {
		return nil
	}
	f := &Finding{ID: "program:" + strings.TrimSuffix(v.path, " (deleted)"), Host: c.RemoteIP.String(), Until: now.Add(7 * 24 * time.Hour),
		Fix: "If you do not recognise it, quit it, delete the file and run a malware scan (for example Malwarebytes). yaklite ack this alert if it is a tool you trust."}
	when := ""
	if v.recent {
		when = ", changed in the last 3 days,"
	}
	switch {
	case v.oddPlace:
		f.Severity = sevHigh
		f.Title = fmt.Sprintf("A program running from a temporary or hidden place%s is talking to the internet: %s, to %s", when, v.path, c.who())
		f.Detail = "Normal installers never put programs there; malware often does."
	default:
		f.Severity = sevMedium
		f.Title = fmt.Sprintf("A program signed by no developer%s is talking to the internet: %s, to %s", when, v.path, c.who())
		f.Detail = "Most legitimate apps are signed. Unsigned ones are often home-made tools, but also malware."
	}
	return f
}
