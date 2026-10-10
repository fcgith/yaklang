package main

import (
	"fmt"
	"net"
	"os"
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
//	  192.168.1.99:
//	    name: Guest laptop
//	    ignore: true              # never alert about this host
//	risky_ports: [23, 445]        # optional, replaces the built-in list
type Inventory struct {
	Hosts      map[string]*HostEntry `yaml:"hosts"`
	RiskyPorts []int                 `yaml:"risky_ports"`
}

type HostEntry struct {
	Name   string `yaml:"name"`
	Expect []int  `yaml:"expect"`
	Ignore bool   `yaml:"ignore"`
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
	for k := range inv.Hosts {
		if net.ParseIP(k) == nil {
			return nil, fmt.Errorf("%s: host key %q is not an IP address", path, k)
		}
		if inv.Hosts[k] == nil {
			inv.Hosts[k] = &HostEntry{}
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
	27017: "MongoDB (often no auth)",
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
	if inv != nil && inv.RiskyPorts != nil {
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

// Annotate fills in friendly names and severities and drops changes for
// ignored hosts. It works without an inventory, using only the risky-port list.
func Annotate(changes []Change, inv *Inventory) []Change {
	out := changes[:0]
	for _, c := range changes {
		var entry *HostEntry
		if inv != nil {
			entry = inv.Hosts[c.Host]
		}
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
		default:
			c.Severity = sevLow
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
