package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// private-dns sets this computer to send its DNS lookups encrypted to a
// resolver that blocks known malware and phishing domains, so the Wi-Fi
// you are on (or a hacked router) can neither see nor fake them.

type dnsProvider struct {
	name, about, url, tlsName string
	servers                   []string
}

var dnsProviders = map[string]dnsProvider{
	"quad9": {"Quad9", "non-profit, blocks malware and phishing, Swiss privacy law", "https://dns.quad9.net/dns-query", "dns.quad9.net",
		[]string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}},
	"cloudflare": {"Cloudflare (security)", "blocks malware", "https://security.cloudflare-dns.com/dns-query", "security.cloudflare-dns.com",
		[]string{"1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"}},
	"mullvad": {"Mullvad (base)", "blocks malware, ads and trackers, no logging", "https://base.dns.mullvad.net/dns-query", "base.dns.mullvad.net",
		[]string{"194.242.2.4", "2a07:e340::4"}},
}

func uuidFrom(s string) string {
	h := sha256.Sum256([]byte(s))
	h[6] = (h[6] & 0x0f) | 0x50 // name-based
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// mobileConfig is an unsigned macOS/iOS profile with one DNS-over-HTTPS
// setting. The same file works on an iPhone or iPad.
func mobileConfig(key string, p dnsProvider) string {
	var addrs strings.Builder
	for _, s := range p.servers {
		addrs.WriteString("\t\t\t\t<string>" + xmlEsc(s) + "</string>\n")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key><string>HTTPS</string>
				<key>ServerURL</key><string>` + xmlEsc(p.url) + `</string>
				<key>ServerAddresses</key>
				<array>
` + addrs.String() + `				</array>
			</dict>
			<key>PayloadDisplayName</key><string>Encrypted DNS (` + xmlEsc(p.name) + `)</string>
			<key>PayloadIdentifier</key><string>io.github.yaklite.dns.` + key + `.settings</string>
			<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key><string>` + uuidFrom("settings-"+key) + `</string>
			<key>PayloadVersion</key><integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key><string>Sends DNS lookups encrypted to ` + xmlEsc(p.name) + `, which ` + xmlEsc(p.about) + `. Made by yaklite.</string>
	<key>PayloadDisplayName</key><string>yaklite private DNS (` + xmlEsc(p.name) + `)</string>
	<key>PayloadIdentifier</key><string>io.github.yaklite.dns.` + key + `</string>
	<key>PayloadRemovalDisallowed</key><false/>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>` + uuidFrom("profile-"+key) + `</string>
	<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`
}

func resolvedDropIn(p dnsProvider) string {
	var servers []string
	for _, s := range p.servers {
		servers = append(servers, s+"#"+p.tlsName)
	}
	return "# written by yaklite private-dns\n[Resolve]\nDNS=" + strings.Join(servers, " ") + "\nDNSOverTLS=yes\n"
}

const resolvedDropInPath = "/etc/systemd/resolved.conf.d/yaklite-private-dns.conf"

func cmdPrivateDNS(args []string) error {
	fs := flag.NewFlagSet("private-dns", flag.ExitOnError)
	prov := fs.String("provider", "quad9", "quad9, cloudflare or mullvad")
	apply := fs.Bool("apply", false, "Linux: write the systemd-resolved setting and restart it (needs sudo)")
	off := fs.Bool("off", false, "Linux: remove the setting again")
	out := fs.String("o", "", "macOS: where to save the profile (default: your Downloads folder)")
	fs.Parse(args)
	p, ok := dnsProviders[*prov]
	if !ok {
		return fmt.Errorf("unknown --provider %q (quad9, cloudflare or mullvad)", *prov)
	}
	switch runtime.GOOS {
	case "darwin":
		path := *out
		if path == "" {
			path = filepath.Join(homeDir(), "Downloads", "yaklite-private-dns-"+*prov+".mobileconfig")
		}
		if err := os.WriteFile(path, []byte(mobileConfig(*prov, p)), 0o644); err != nil {
			return err
		}
		exec.Command("open", path).Run()
		fmt.Printf("Saved %s and opened it.\n\n", path)
		fmt.Println("To finish: open System Settings > General > Device Management (Profiles on older macOS),")
		fmt.Printf("double-click \"yaklite private DNS (%s)\" and click Install.\n", p.name)
		fmt.Println("To undo, remove the profile there. The same file works on an iPhone or iPad (AirDrop it).")
	case "linux":
		if *off {
			if err := requireAdmin(); err != nil {
				return err
			}
			os.Remove(resolvedDropInPath)
			return run("systemctl", "restart", "systemd-resolved")
		}
		if !*apply {
			fmt.Printf("With systemd-resolved, save this as %s and run: sudo systemctl restart systemd-resolved\n\n%s\n", resolvedDropInPath, resolvedDropIn(p))
			fmt.Println("Or run: sudo yaklite private-dns --apply")
			return nil
		}
		if err := requireAdmin(); err != nil {
			return err
		}
		if exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run() != nil {
			return errors.New("systemd-resolved is not running here; set DNS-over-TLS in your network manager instead")
		}
		os.MkdirAll(filepath.Dir(resolvedDropInPath), 0o755)
		if err := os.WriteFile(resolvedDropInPath, []byte(resolvedDropIn(p)), 0o644); err != nil {
			return err
		}
		if err := run("systemctl", "restart", "systemd-resolved"); err != nil {
			return err
		}
		fmt.Printf("DNS now goes encrypted to %s. Undo with: sudo yaklite private-dns --off\n", p.name)
	case "windows":
		fmt.Println("In an administrator PowerShell:")
		for _, s := range p.servers {
			fmt.Printf("  Add-DnsClientDohServerAddress -ServerAddress %s -DohTemplate %s -AllowFallbackToUdp $false -AutoUpgrade $true\n", s, p.url)
		}
		fmt.Println("Then in Settings > Network & internet > (your network) > DNS server assignment, choose Manual,")
		fmt.Printf("enter %s and set DNS over HTTPS to On (automatic template).\n", strings.Join(p.servers[:2], " and "))
	default:
		return fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	return nil
}
