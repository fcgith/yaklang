package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The KEV check compares the software the fingerprinter recognised on your
// devices with CISA's list of Known Exploited Vulnerabilities: flaws that
// attackers are using right now. The list says which products are affected,
// not which versions, so a match means "make sure this is fully updated".

func init() {
	registerCheck(&check{name: "kev", about: "devices running software with actively exploited flaws (CISA KEV list)", run: kevCheck})
}

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevEntry struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

func loadKEV(ctx context.Context, stateDir string, download bool) ([]kevEntry, error) {
	p := filepath.Join(stateDir, "threat-lists", "kev.json")
	os.MkdirAll(filepath.Dir(p), 0o700)
	if st, err := os.Stat(p); download && (err != nil || time.Since(st.ModTime()) > 24*time.Hour) {
		if err := fetchToFile(ctx, kevURL, p); err != nil && st == nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulns []kevEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Vulns, nil
}

func normWords(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// cpeParts returns vendor and product from cpe:/a:vendor:product:... or cpe:2.3:a:vendor:product:...
func cpeParts(cpe string) (vendor, product string) {
	f := strings.Split(cpe, ":")
	if len(f) >= 5 && f[1] == "2.3" {
		return normWords(f[3]), normWords(f[4])
	}
	if len(f) >= 4 {
		return normWords(f[2]), normWords(f[3])
	}
	return "", ""
}

// kevMatches finds entries for a product. Vendor must match; the product
// names must match after normalising, or one must contain the other.
func kevMatches(list []kevEntry, vendor, product string) []kevEntry {
	if vendor == "" || product == "" {
		return nil
	}
	var out []kevEntry
	for _, k := range list {
		v, p := normWords(k.Vendor), normWords(k.Product)
		if v != vendor && !strings.HasPrefix(v, vendor+" ") && !strings.HasPrefix(vendor, v+" ") {
			continue
		}
		if p == product || (len(product) >= 4 && strings.Contains(" "+p+" ", " "+product+" ")) || (len(p) >= 4 && strings.Contains(" "+product+" ", " "+p+" ")) {
			out = append(out, k)
		}
	}
	return out
}

func kevSummary(ks []kevEntry) (string, bool) {
	sort.Slice(ks, func(i, j int) bool { return ks[i].DateAdded > ks[j].DateAdded })
	ransom := false
	var ids []string
	for i, k := range ks {
		if k.Ransomware == "Known" {
			ransom = true
		}
		if i < 4 {
			ids = append(ids, k.CVE)
		}
	}
	s := strings.Join(ids, ", ")
	if len(ks) > 4 {
		s += fmt.Sprintf(" and %d more", len(ks)-4)
	}
	return s, ransom
}

func kevCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	if !env.opts.threatLists || len(env.snap.Hosts) == 0 {
		return nil, nil
	}
	list, err := loadKEV(ctx, env.stateDir, true)
	if err != nil {
		return nil, err
	}
	var out []*Finding
	for host, svcs := range env.snap.Hosts {
		seen := map[string]bool{}
		for _, s := range svcs {
			for _, cpe := range s.CPEs {
				v, p := cpeParts(cpe)
				key := v + "|" + p
				if seen[key] {
					continue
				}
				seen[key] = true
				ks := kevMatches(list, v, p)
				if len(ks) == 0 {
					continue
				}
				ids, ransom := kevSummary(ks)
				f := &Finding{ID: fmt.Sprintf("kev:%s:%s", host, strings.ReplaceAll(key, " ", "_")), Severity: sevMedium, Host: host,
					Title:  fmt.Sprintf("%s runs %s (port %d), which has flaws attackers are actively using", host, s.Label(), s.Port),
					Detail: "Listed by CISA as exploited in the wild: " + ids + ". The list does not say which versions, so check yours.",
					Fix:    "Update this device's firmware or software to the latest version, or stop exposing that port."}
				if ransom {
					f.Detail += " Some are used by ransomware gangs."
				}
				out = append(out, f)
			}
		}
	}
	// the router itself, by its maker
	if gw := env.snap.Gateway; gw != "" && env.snap.Devices[gw] != nil && env.snap.Devices[gw].Vendor != "" {
		vendor := normWords(strings.Fields(env.snap.Devices[gw].Vendor)[0])
		var ks []kevEntry
		cutoff := time.Now().AddDate(-2, 0, 0).Format("2006-01-02")
		for _, k := range list {
			if normWords(k.Vendor) == vendor && k.DateAdded >= cutoff {
				ks = append(ks, k)
			}
		}
		if len(ks) > 0 {
			ids, _ := kevSummary(ks)
			out = append(out, &Finding{ID: "kev:router:" + vendor, Severity: sevLow, Host: gw,
				Title:  fmt.Sprintf("Your router is made by %s, whose products had %d actively exploited flaws in the last two years", env.snap.Devices[gw].Vendor, len(ks)),
				Detail: ids,
				Fix:    "Check the router has the latest firmware and that remote administration from the internet is off."})
		}
	}
	return out, nil
}
