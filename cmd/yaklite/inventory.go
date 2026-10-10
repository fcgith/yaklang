package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Service is one open port on one host, with whatever the fingerprinter could tell.
type Service struct {
	Port     int      `json:"port"`
	Proto    string   `json:"proto"`
	Service  string   `json:"service,omitempty"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
	Banner   string   `json:"banner,omitempty"`
	Verified bool     `json:"verified"` // false when only the port is known to be open
	TLS      *TLSInfo `json:"tls,omitempty"`
	// TLSState is "", "expiring" or "expired" as of this snapshot, so expiry is
	// alerted once when it is first seen rather than on every scan.
	TLSState string `json:"tls_state,omitempty"`
}

// Key identifies a service across snapshots.
func (s Service) Key() string { return fmt.Sprintf("%s/%d", s.Proto, s.Port) }

// Label is a short human description used in change events.
func (s Service) Label() string {
	label := s.Service
	if s.Product != "" {
		label = s.Product
	}
	if s.Version != "" {
		label += " " + s.Version
	}
	if label == "" {
		label = "unknown"
	}
	return label
}

// Snapshot is the result of one scan of a set of targets.
type Snapshot struct {
	Version  int                   `json:"version"`
	Started  time.Time             `json:"started"`
	Finished time.Time             `json:"finished"`
	Targets  string                `json:"targets"`
	Ports    string                `json:"ports"`
	Method   string                `json:"method"`
	Hosts    map[string][]*Service `json:"hosts"`
	// Devices holds MAC address, vendor and name for hosts found on a
	// directly attached network. Hosts with no open ports appear in Hosts
	// with an empty list.
	Devices map[string]*Device `json:"devices,omitempty"`
	// Gateway is the default gateway's IP when it was on a scanned network.
	Gateway string `json:"gateway,omitempty"`
	// Misses counts consecutive scans in which a previously seen host did not
	// answer. It lets watch mode wait before reporting a host as gone.
	Misses map[string]int `json:"misses,omitempty"`
}

func NewSnapshot(targets, ports, method string) *Snapshot {
	return &Snapshot{Version: 1, Targets: targets, Ports: ports, Method: method, Hosts: map[string][]*Service{}, Devices: map[string]*Device{}, Misses: map[string]int{}}
}

func (s *Snapshot) Add(host string, svc *Service) {
	s.Hosts[host] = append(s.Hosts[host], svc)
}

// Sort makes snapshot output stable so files diff cleanly.
func (s *Snapshot) Sort() {
	for _, svcs := range s.Hosts {
		sort.Slice(svcs, func(i, j int) bool {
			if svcs[i].Port != svcs[j].Port {
				return svcs[i].Port < svcs[j].Port
			}
			return svcs[i].Proto < svcs[j].Proto
		})
	}
}

func (s *Snapshot) OpenPortCount() int {
	n := 0
	for _, svcs := range s.Hosts {
		n += len(svcs)
	}
	return n
}

// Change is one difference between two snapshots.
type Change struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"` // host_new, host_gone, port_open, port_closed, service_changed, tls_expiring, tls_expired, tls_cert_changed, mac_changed, gateway_impersonated
	Severity string    `json:"severity,omitempty"`
	Host     string    `json:"host"`
	MAC      string    `json:"mac,omitempty"`
	Name     string    `json:"name,omitempty"` // friendly name from the inventory file
	Port     int       `json:"port,omitempty"`
	Proto    string    `json:"proto,omitempty"`
	Before   string    `json:"before,omitempty"`
	After    string    `json:"after,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

func (c Change) who() string {
	if c.Name != "" {
		return fmt.Sprintf("%s (%s)", c.Name, c.Host)
	}
	return c.Host
}

func (c Change) String() string {
	var msg string
	switch c.Kind {
	case "host_new":
		msg = fmt.Sprintf("NEW HOST      %s (%s)", c.who(), c.After)
	case "host_gone":
		msg = fmt.Sprintf("HOST GONE     %s (was %s)", c.who(), c.Before)
	case "port_open":
		msg = fmt.Sprintf("PORT OPENED   %s %s/%d %s", c.who(), c.Proto, c.Port, c.After)
	case "port_closed":
		msg = fmt.Sprintf("PORT CLOSED   %s %s/%d (was %s)", c.who(), c.Proto, c.Port, c.Before)
	case "service_changed":
		msg = fmt.Sprintf("SERVICE CHANGED %s %s/%d %s -> %s", c.who(), c.Proto, c.Port, c.Before, c.After)
	case "tls_expiring":
		msg = fmt.Sprintf("CERT EXPIRING %s %s/%d %s", c.who(), c.Proto, c.Port, c.After)
	case "tls_expired":
		msg = fmt.Sprintf("CERT EXPIRED  %s %s/%d %s", c.who(), c.Proto, c.Port, c.After)
	case "tls_cert_changed":
		msg = fmt.Sprintf("CERT CHANGED  %s %s/%d %s -> %s", c.who(), c.Proto, c.Port, c.Before, c.After)
	case "mac_changed":
		msg = fmt.Sprintf("MAC CHANGED   %s %s -> %s", c.who(), c.Before, c.After)
	case "gateway_impersonated":
		msg = fmt.Sprintf("GATEWAY MAC CLAIMED %s also answers with the router's MAC %s", c.who(), c.After)
	default:
		msg = c.Kind + " " + c.who()
	}
	if c.Detail != "" {
		msg += " [" + c.Detail + "]"
	}
	if c.Severity != "" {
		msg = fmt.Sprintf("%-6s %s", strings.ToUpper(c.Severity), msg)
	}
	return msg
}

// DiffOptions tunes how two snapshots are compared.
type DiffOptions struct {
	// GoneAfter is how many consecutive scans a host must be missing before
	// it is reported as gone.
	GoneAfter int
	// TLSWarn is how far ahead of expiry a certificate is reported. Zero
	// disables expiry warnings.
	TLSWarn time.Duration
}

func portList(svcs []*Service) string {
	out := ""
	for i, s := range svcs {
		if i > 0 {
			out += ","
		}
		out += s.Key()
	}
	if out == "" {
		return "no open ports"
	}
	return out
}

func macLabel(d *Device) string {
	if d == nil || d.MAC == "" {
		return ""
	}
	if desc := d.describe(); desc != "" {
		return d.MAC + " (" + desc + ")"
	}
	return d.MAC
}

func hostSummary(d *Device, svcs []*Service) string {
	if desc := d.describe(); desc != "" {
		return desc + "; " + portList(svcs)
	}
	return portList(svcs)
}

func (s *Snapshot) mac(h string) string {
	if s == nil || s.Devices[h] == nil {
		return ""
	}
	return s.Devices[h].MAC
}

// gatewayImpersonators lists other hosts answering with the gateway's MAC,
// the usual sign of ARP spoofing.
func gatewayImpersonators(s *Snapshot) map[string]bool {
	out := map[string]bool{}
	gwMAC := s.mac(s.Gateway)
	if gwMAC == "" {
		return out
	}
	for h, d := range s.Devices {
		if h != s.Gateway && d != nil && d.MAC == gwMAC && !d.Self {
			out[h] = true
		}
	}
	return out
}

// Diff compares prev with cur. Hosts missing from cur are only reported as gone
// once they have been missing for goneAfter consecutive scans; until then they
// are carried forward into cur so the next comparison still knows them.
// A nil prev means a first run: every host is reported as new.
func Diff(prev, cur *Snapshot, opt DiffOptions, now time.Time) []Change {
	goneAfter := opt.GoneAfter
	if goneAfter < 1 {
		goneAfter = 1
	}
	var changes []Change
	if cur.Misses == nil {
		cur.Misses = map[string]int{}
	}
	if cur.Devices == nil {
		cur.Devices = map[string]*Device{}
	}

	hosts := map[string]bool{}
	for h := range cur.Hosts {
		hosts[h] = true
	}
	if prev != nil {
		for h := range prev.Hosts {
			hosts[h] = true
		}
	}
	ordered := make([]string, 0, len(hosts))
	for h := range hosts {
		ordered = append(ordered, h)
	}
	sort.Strings(ordered)

	for _, h := range ordered {
		curSvcs, inCur := cur.Hosts[h]
		var prevSvcs []*Service
		inPrev := false
		if prev != nil {
			prevSvcs, inPrev = prev.Hosts[h]
		}

		switch {
		case inCur && !inPrev:
			changes = append(changes, Change{Time: now, Kind: "host_new", Host: h, MAC: cur.mac(h), After: hostSummary(cur.Devices[h], curSvcs)})
			for _, s := range curSvcs {
				changes = append(changes, Change{Time: now, Kind: "port_open", Host: h, Port: s.Port, Proto: s.Proto, After: s.Label()})
				changes = append(changes, tlsChanges(h, nil, s, opt.TLSWarn, now)...)
			}
		case !inCur && inPrev:
			misses := prev.Misses[h] + 1
			if misses >= goneAfter {
				changes = append(changes, Change{Time: now, Kind: "host_gone", Host: h, MAC: prev.mac(h), Before: hostSummary(prev.Devices[h], prevSvcs)})
				continue
			}
			// not gone yet: remember it
			cur.Hosts[h] = prevSvcs
			cur.Misses[h] = misses
			if d := prev.Devices[h]; d != nil {
				cur.Devices[h] = d
			}
		default:
			if pm, cm := prev.mac(h), cur.mac(h); pm != "" && cm != "" && pm != cm {
				c := Change{Time: now, Kind: "mac_changed", Host: h, MAC: cm, Before: macLabel(prev.Devices[h]), After: macLabel(cur.Devices[h])}
				if h == cur.Gateway {
					c.Detail = "gateway"
				}
				changes = append(changes, c)
			}
			prevBy := map[string]*Service{}
			for _, s := range prevSvcs {
				prevBy[s.Key()] = s
			}
			curBy := map[string]*Service{}
			for _, s := range curSvcs {
				curBy[s.Key()] = s
			}
			for _, s := range curSvcs {
				p, ok := prevBy[s.Key()]
				if !ok {
					changes = append(changes, Change{Time: now, Kind: "port_open", Host: h, Port: s.Port, Proto: s.Proto, After: s.Label()})
					changes = append(changes, tlsChanges(h, nil, s, opt.TLSWarn, now)...)
					continue
				}
				changes = append(changes, tlsChanges(h, p, s, opt.TLSWarn, now)...)
				// only compare fingerprints when both sides identified something,
				// so a flaky probe does not look like a service swap
				if s.Verified && p.Verified && p.Label() != s.Label() {
					changes = append(changes, Change{Time: now, Kind: "service_changed", Host: h, Port: s.Port, Proto: s.Proto, Before: p.Label(), After: s.Label()})
				}
			}
			for _, p := range prevSvcs {
				if _, ok := curBy[p.Key()]; !ok {
					changes = append(changes, Change{Time: now, Kind: "port_closed", Host: h, Port: p.Port, Proto: p.Proto, Before: p.Label()})
				}
			}
		}
	}
	var before map[string]bool
	if prev != nil {
		before = gatewayImpersonators(prev)
	}
	for h := range gatewayImpersonators(cur) {
		if !before[h] {
			changes = append(changes, Change{Time: now, Kind: "gateway_impersonated", Host: h, MAC: cur.mac(h), After: cur.mac(h),
				Detail: "possible ARP spoofing of the router " + cur.Gateway})
		}
	}
	return changes
}

// writeFilePrivate writes data atomically with owner-only permissions.
func writeFilePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".yaklite-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func SaveSnapshot(path string, s *Snapshot) error {
	s.Sort()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFilePrivate(path, append(data, '\n'))
}

func LoadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.Hosts == nil {
		s.Hosts = map[string][]*Service{}
	}
	if s.Misses == nil {
		s.Misses = map[string]int{}
	}
	if s.Devices == nil {
		s.Devices = map[string]*Device{}
	}
	return &s, nil
}
