package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Inventory is the user's description of what should be on the network.
//
//	hosts:
//	  192.168.1.10:
//	    name: NAS
//	    expect: [22, 443, 5000]   # tcp ports this device is allowed to expose
//	  192.168.1.20:
//	    name: Living room TV
//	  "aa:bb:cc:dd:ee:ff":        # devices can also be keyed by MAC address,
//	    name: Laptop              # which survives the router handing out a new IP
//	  192.168.1.99:
//	    name: Guest laptop
//	    ignore: true              # never alert about this host
//	risky_ports: [23, 445]        # optional, replaces the built-in list
//	rules:                        # recognise devices it cannot name by itself
//	  - kind: Security camera
//	    vendor: Hikvision         # MAC maker contains this (any case)
//	  - kind: NAS
//	    ports: [5000, 5001]       # all of these are open
//	  - kind: Printer
//	    banner: "(?i)laserjet"    # a fingerprint or banner matches this regex
type Inventory struct {
	Hosts      map[string]*HostEntry `yaml:"hosts"`
	RiskyPorts []int                 `yaml:"risky_ports,omitempty"`
	Rules      []*DeviceRule         `yaml:"rules,omitempty"`
}

type HostEntry struct {
	Name   string `yaml:"name"`
	Expect []int  `yaml:"expect,omitempty"`
	Ignore bool   `yaml:"ignore,omitempty"`
}

// DeviceRule names devices by what they look like. Every given field must match.
type DeviceRule struct {
	Kind     string `yaml:"kind"`
	Vendor   string `yaml:"vendor,omitempty"`
	Hostname string `yaml:"hostname,omitempty"` // contains, any case
	Ports    []int  `yaml:"ports,omitempty"`
	Banner   string `yaml:"banner,omitempty"`
	re       *regexp.Regexp
}

func (r *DeviceRule) matches(d *Device, svcs []*Service) bool {
	if r.Vendor != "" && (d == nil || !strings.Contains(strings.ToLower(d.Vendor), strings.ToLower(r.Vendor))) {
		return false
	}
	if r.Hostname != "" && (d == nil || !strings.Contains(strings.ToLower(d.Hostname), strings.ToLower(r.Hostname))) {
		return false
	}
	open := map[int]bool{}
	for _, s := range svcs {
		open[s.Port] = true
	}
	for _, p := range r.Ports {
		if !open[p] {
			return false
		}
	}
	if r.re != nil {
		hit := false
		for _, s := range svcs {
			if r.re.MatchString(s.Label() + " " + s.Banner + " " + strings.Join(s.CPEs, " ")) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// applyRules labels devices that match one of the inventory's rules.
func (inv *Inventory) applyRules(s *Snapshot) {
	if inv == nil || len(inv.Rules) == 0 {
		return
	}
	for h, svcs := range s.Hosts {
		d := s.Devices[h]
		for _, r := range inv.Rules {
			if r.matches(d, svcs) {
				if d == nil {
					d = &Device{}
					s.Devices[h] = d
				}
				d.Kind = r.Kind
				break
			}
		}
	}
}

func (h *HostEntry) expects(port int) bool {
	for _, p := range h.Expect {
		if p == port {
			return true
		}
	}
	return false
}

func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	hosts := map[string]*HostEntry{}
	for k, e := range inv.Hosts {
		if e == nil {
			e = &HostEntry{}
		}
		switch {
		case net.ParseIP(k) != nil:
			hosts[k] = e
		case normalizeMAC(k) != "":
			hosts[normalizeMAC(k)] = e
		default:
			return nil, fmt.Errorf("%s: host key %q is not an IP or MAC address", path, k)
		}
	}
	inv.Hosts = hosts
	for i, r := range inv.Rules {
		if r == nil || r.Kind == "" {
			return nil, fmt.Errorf("%s: rule %d needs a kind", path, i+1)
		}
		if r.Banner != "" {
			if r.re, err = regexp.Compile(r.Banner); err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", path, r.Kind, err)
			}
		}
		if r.Vendor == "" && len(r.Ports) == 0 && r.Banner == "" && r.Hostname == "" {
			return nil, fmt.Errorf("%s: rule %q matches everything; give vendor, hostname, ports or banner", path, r.Kind)
		}
	}
	return &inv, nil
}

// riskyPorts are services that should rarely be reachable on a home or office
// network, and almost never from the internet: cleartext logins, file
// sharing, remote desktops, and databases or APIs that often run without auth.
var riskyPorts = map[int]string{
	21: "FTP (cleartext logins)", 23: "Telnet (cleartext logins)", 135: "Windows RPC", 139: "SMB/NetBIOS file sharing",
	445: "SMB file sharing", 1433: "SQL Server", 1883: "MQTT (often no auth)", 2375: "Docker API without TLS (full host control)",
	3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC remote desktop",
	5985: "WinRM", 6379: "Redis (often no auth)", 9200: "Elasticsearch (often no auth)", 11211: "Memcached",
	27017: "MongoDB (often no auth)", 69: "TFTP (no authentication)", 161: "SNMP (often default community strings)",
	623: "IPMI server management (remote power and console)",
}

var riskyServiceWords = []string{"telnet", "vnc", "rdp", "ms-wbt-server", "redis", "mongodb", "memcache", "docker"}

const (
	sevInfo   = "info"
	sevLow    = "low"
	sevMedium = "medium"
	sevHigh   = "high"
)

var sevRank = map[string]int{sevInfo: 0, sevLow: 1, sevMedium: 2, sevHigh: 3}

func parseSeverity(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := sevRank[s]; !ok {
		return "", fmt.Errorf("unknown severity %q (use info, low, medium or high)", s)
	}
	return s, nil
}

func (inv *Inventory) risky(port int, label string) (string, bool) {
	if inv != nil && len(inv.RiskyPorts) > 0 {
		for _, p := range inv.RiskyPorts {
			if p == port {
				return "listed in risky_ports", true
			}
		}
		return "", false
	}
	if why, ok := riskyPorts[port]; ok {
		return why, true
	}
	l := strings.ToLower(label)
	for _, w := range riskyServiceWords {
		if strings.Contains(l, w) {
			return w + " service", true
		}
	}
	return "", false
}

// entry finds the inventory entry for a host by IP, then by MAC.
func (inv *Inventory) entry(host, mac string) *HostEntry {
	if inv == nil {
		return nil
	}
	if e := inv.Hosts[host]; e != nil {
		return e
	}
	if mac != "" {
		return inv.Hosts[mac]
	}
	return nil
}

// Annotate fills in friendly names and severities and drops changes for
// ignored hosts. It works without an inventory, using only the risky-port list.
func Annotate(changes []Change, inv *Inventory) []Change {
	out := changes[:0]
	for _, c := range changes {
		entry := inv.entry(c.Host, c.MAC)
		if entry != nil {
			if entry.Ignore {
				continue
			}
			c.Name = entry.Name
		}
		known := entry != nil
		hasExpect := known && len(entry.Expect) > 0

		switch c.Kind {
		case "host_new":
			c.Severity = sevMedium
			if known {
				c.Severity, c.Detail = sevInfo, "known device"
			} else if inv != nil && c.MAC != "" && inv.Hosts[c.Host] == nil {
				c.Detail = "unknown device joined the network"
			} else if inv != nil {
				c.Detail = "not in inventory"
			} else {
				c.Severity = sevLow
			}
		case "host_gone":
			c.Severity = sevInfo
			if known {
				c.Severity = sevLow
			}
		case "port_open":
			why, isRisky := inv.risky(c.Port, c.After)
			switch {
			case hasExpect && entry.expects(c.Port):
				c.Severity, c.Detail = sevInfo, "expected"
			case isRisky:
				c.Severity, c.Detail = sevHigh, why
			case hasExpect:
				c.Severity, c.Detail = sevMedium, "not in expected ports"
			case c.Outside:
				c.Severity, c.Detail = sevMedium, "reachable from the internet"
			default:
				c.Severity = sevLow
			}
		case "port_closed":
			c.Severity = sevInfo
			if hasExpect && entry.expects(c.Port) {
				c.Severity, c.Detail = sevMedium, "expected service is down"
			}
		case "service_changed":
			c.Severity = sevLow
			if why, isRisky := inv.risky(c.Port, c.After); isRisky && !(hasExpect && entry.expects(c.Port)) {
				c.Severity, c.Detail = sevHigh, why
			}
		case "tls_expired":
			c.Severity = sevHigh
		case "tls_expiring":
			c.Severity = sevMedium
		case "tls_cert_changed":
			c.Severity = sevLow
			if strings.HasPrefix(c.Detail, "issuer changed") {
				c.Severity = sevMedium
			}
		case "mac_changed":
			switch {
			case c.Detail == "gateway":
				c.Severity, c.Detail = sevHigh, "the router's MAC changed: a new router, or someone impersonating it (ARP spoofing)"
			case known:
				c.Severity = sevMedium
			default:
				c.Severity = sevLow // DHCP often hands an address to a different device
			}
		case "finding":
			if c.Severity == "" {
				c.Severity = sevMedium
			}
		case "finding_resolved":
			c.Severity = sevInfo
		case "gateway_impersonated", "zone_transfer_open":
			c.Severity = sevHigh
		case "name_new":
			c.Severity = sevLow
		case "name_gone":
			c.Severity = sevInfo
		case "dns_changed", "cert_mismatch":
			c.Severity = sevMedium
		case "web_changed":
			c.Severity = sevLow
			if strings.HasPrefix(c.After, "5") || c.After == "unreachable" {
				c.Severity, c.Detail = sevMedium, "site down"
			}
		default:
			c.Severity = sevLow
		}
		if c.Fix == "" && sevRank[c.Severity] >= sevRank[sevLow] {
			c.Fix = fixFor(c)
		}
		out = append(out, c)
	}
	return out
}

func filterSeverity(changes []Change, min string) []Change {
	var out []Change
	for _, c := range changes {
		if sevRank[c.Severity] >= sevRank[min] {
			out = append(out, c)
		}
	}
	return out
}
