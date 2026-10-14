package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// On a network that is not yours (a café, hotel or airport), other people
// on it can see which sites you visit and try to trick your Mac. A VPN
// wraps everything in a tunnel to somewhere you trust. This check reminds
// you to turn one on, and can turn it on for you: put the command that
// starts your VPN in ~/.config/yaklite/vpn-command, for example
//
//	scutil --nc start "My VPN"
//	tailscale up --exit-node=home-box
//
// It runs once each time you join an untrusted network without a VPN.

func init() {
	registerCheck(&check{name: "vpnreminder", about: "a reminder to turn on a VPN on networks that are not yours (and starting it, if you set that up)", run: vpnReminderCheck})
}

func vpnCommandPath() string { return filepath.Join(configDir(), "vpn-command") }

// vpnActive reports whether a VPN carries this Mac's traffic: a connected
// VPN service, or the default route through a tunnel interface.
func vpnActive(ctx context.Context, run runner) bool {
	if strings.Contains(run(ctx, "scutil", "--nc", "list"), "(Connected)") {
		return true
	}
	switch runtime.GOOS {
	case "darwin":
		for _, line := range strings.Split(run(ctx, "route", "-n", "get", "default"), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "interface:" {
				return tunnelIface(f[1])
			}
		}
	case "linux":
		f := strings.Fields(run(ctx, "ip", "route", "show", "default"))
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return tunnelIface(f[i+1])
			}
		}
	}
	return false
}

func tunnelIface(name string) bool {
	for _, p := range []string{"utun", "tun", "wg", "ppp", "ipsec", "tailscale"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// readVPNCommand returns the user's VPN command, refusing a file that
// others could have written.
func readVPNCommand() string {
	p := vpnCommandPath()
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm()&0o022 != 0 {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}

func vpnReminderCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	if env.net == nil || env.trusted || !env.inAuto {
		return nil, nil
	}
	if vpnActive(ctx, cmdOut) {
		return nil, nil
	}
	f := &Finding{ID: "vpn-off:" + env.net.ID(), Severity: sevMedium, Until: time.Now().Add(2 * time.Hour),
		Title: "You are on a network that is not yours, without a VPN",
		Fix:   "Turn on your VPN now. Others on this network can see which sites you visit and may try to trick your Mac. If this network is yours, run: yaklite trust"}
	cmd := readVPNCommand()
	if cmd == "" {
		f.Detail = "Tip: put the command that starts your VPN in " + vpnCommandPath() + " and yaklite will start it for you on networks like this."
		return []*Finding{f}, nil
	}
	// run once per joined network: remember the last one we started it for
	mark := filepath.Join(env.stateDir, "vpn-started")
	if last, _ := os.ReadFile(mark); strings.TrimSpace(string(last)) == env.net.ID() {
		f.Detail = "yaklite already tried to start it with: " + cmd
		return []*Finding{f}, nil
	}
	writeFilePrivate(mark, []byte(env.net.ID()+"\n"))
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "/bin/sh", "-c", cmd).CombinedOutput()
	time.Sleep(3 * time.Second)
	if err == nil && vpnActive(ctx, cmdOut) {
		env.prog("started the VPN with: %s", cmd)
		return nil, nil
	}
	f.Detail = "yaklite tried to start it with: " + cmd + " (" + trunc(strings.TrimSpace(string(out)), 200) + ")"
	return []*Finding{f}, nil
}
