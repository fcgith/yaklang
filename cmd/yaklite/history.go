package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Device history: when each device was first and last seen on each watched
// network, so "when did that thing appear?" has an answer. Devices are keyed
// by MAC address when known (it survives a new IP), otherwise by IP.

type deviceSeen struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	IP    string    `json:"ip"`
	MAC   string    `json:"mac,omitempty"`
	Name  string    `json:"name,omitempty"` // hostname or vendor seen last
	Ports string    `json:"ports,omitempty"`
}

type historyFile map[string]map[string]*deviceSeen // watch -> device key -> seen

func historyPath(stateDir string) string { return filepath.Join(stateDir, "device-history.json") }

func loadHistory(stateDir string) historyFile {
	h := historyFile{}
	if data, err := os.ReadFile(historyPath(stateDir)); err == nil {
		json.Unmarshal(data, &h)
	}
	return h
}

func updateHistory(stateDir, watch string, s *Snapshot) {
	if s == nil || s.Method == "connections" || len(s.Domains) > 0 {
		return
	}
	h := loadHistory(stateDir)
	if h[watch] == nil {
		h[watch] = map[string]*deviceSeen{}
	}
	for ip, svcs := range s.Hosts {
		if s.Misses[ip] > 0 {
			continue // carried forward, not actually seen
		}
		key, mac, name := ip, "", ""
		if d := s.Devices[ip]; d != nil {
			if d.MAC != "" {
				key, mac = d.MAC, d.MAC
			}
			name = d.describe()
		}
		e := h[watch][key]
		if e == nil {
			e = &deviceSeen{First: s.Finished}
			h[watch][key] = e
		}
		e.Last, e.IP, e.MAC, e.Ports = s.Finished, ip, mac, portList(svcs)
		if name != "" {
			e.Name = name
		}
	}
	if data, err := json.MarshalIndent(h, "", "  "); err == nil {
		writeFilePrivate(historyPath(stateDir), data)
	}
}

// firstSeen returns when a host was first seen in a watch.
func (h historyFile) firstSeen(watch, ip, mac string) time.Time {
	if e := h[watch][mac]; mac != "" && e != nil {
		return e.First
	}
	if e := h[watch][ip]; e != nil {
		return e.First
	}
	return time.Time{}
}

func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	fs.Parse(args)
	h := loadHistory(*stateDir)
	nf, _ := loadNetworks()
	if len(h) == 0 {
		fmt.Println("No device history yet.")
	}
	var watches []string
	for w := range h {
		watches = append(watches, w)
	}
	sort.Strings(watches)
	inv, _ := LoadInventory(filepath.Join(configDir(), "inventory.yaml"))
	for _, w := range watches {
		fmt.Printf("\n%s\n", watchLabel(w, nf))
		var list []*deviceSeen
		for _, e := range h[w] {
			list = append(list, e)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].First.After(list[j].First) })
		for _, e := range list {
			name := e.Name
			if ie := inv.entry(e.IP, e.MAC); ie != nil && ie.Name != "" {
				name = ie.Name
			}
			last := e.Last.Local().Format("2006-01-02 15:04")
			if time.Since(e.Last) < 2*time.Hour {
				last = "now"
			}
			fmt.Printf("  first %s  last %-16s  %-15s %-17s %s\n", e.First.Local().Format("2006-01-02 15:04"), last, e.IP, e.MAC, strings.TrimSpace(name))
		}
	}
	return nil
}
