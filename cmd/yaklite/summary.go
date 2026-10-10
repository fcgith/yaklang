package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The weekly summary: one short report of what yaklite watched, what changed
// and what is still worth fixing.

func cmdSummary(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	since := fs.String("since", "7d", "period to cover")
	send := fs.Bool("send", false, "send it to --webhook and as a desktop notification instead of printing it")
	webhook := fs.String("webhook", "", "where to send it (same destinations as for alerts)")
	fs.Parse(args)
	d, err := parseDuration(*since)
	if err != nil {
		return err
	}
	if err := validateWebhooks(*webhook); err != nil {
		return err
	}
	r := &stateReader{dir: *stateDir}
	nf, _ := loadNetworks()
	if inv, err := LoadInventory(filepath.Join(configDir(), "inventory.yaml")); err == nil {
		r.inv = inv
	}
	states, err := r.load()
	if err != nil {
		return err
	}
	title, body := buildSummary(states, nf, loadAcks(), time.Now(), d)
	if !*send {
		fmt.Println(title)
		fmt.Println()
		fmt.Print(body)
		return nil
	}
	notifyDesktop(title, firstLines(body, 3))
	for _, err := range sendText(ctx, *webhook, title, body) {
		fmt.Fprintln(os.Stderr, "[yaklite] summary delivery failed:", err)
	}
	return nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// watchLabel turns a state name into something a person recognises.
func watchLabel(name string, nf *networksFile) string {
	switch {
	case name == "connections":
		return "this computer's connections"
	case strings.HasSuffix(name, "-self"):
		if k := nf.Networks[strings.TrimSuffix(name, "-self")]; k != nil {
			return "this computer on " + k.Name
		}
	case nf.Networks[name] != nil:
		return nf.Networks[name].Name
	case strings.HasPrefix(name, "outside_"):
		return "outside view"
	}
	return name
}

func buildSummary(states []*watchState, nf *networksFile, acks *acksFile, now time.Time, period time.Duration) (string, string) {
	from := now.Add(-period)
	var b strings.Builder
	counts := map[string]int{}
	var newDevices []string
	var open []*Finding
	quiet := 0
	for _, st := range states {
		label := watchLabel(st.Name, nf)
		if st.Snap.Method != "connections" && len(st.Domains()) == 0 {
			fmt.Fprintf(&b, "- %s: %d devices, %d open ports, last checked %s\n", label, len(st.Snap.Hosts), st.Snap.OpenPortCount(), st.Snap.Finished.Local().Format("Mon 15:04"))
		} else {
			fmt.Fprintf(&b, "- %s: last checked %s\n", label, st.Snap.Finished.Local().Format("Mon 15:04"))
		}
		for _, c := range st.Changes {
			if c.Time.Before(from) || c.Severity == "" || c.Severity == sevInfo {
				continue
			}
			if acks.matches(c.Key(), now) {
				quiet++
				continue
			}
			counts[c.Severity]++
			if c.Kind == "host_new" {
				n := c.Host
				if c.Name != "" {
					n = c.Name + " (" + c.Host + ")"
				} else if c.After != "" {
					n += " (" + strings.SplitN(c.After, ";", 2)[0] + ")"
				}
				newDevices = append(newDevices, n+" on "+label)
			}
		}
		for _, f := range st.Snap.Findings {
			if !acks.matches(f.ID, now) && sevRank[f.Severity] >= sevRank[sevMedium] {
				open = append(open, f)
			}
		}
	}
	total := counts[sevHigh] + counts[sevMedium] + counts[sevLow]
	title := fmt.Sprintf("yaklite weekly summary: %d alerts", total)
	if counts[sevHigh] > 0 {
		title += fmt.Sprintf(" (%d serious)", counts[sevHigh])
	}
	var out strings.Builder
	if total == 0 && len(open) == 0 {
		out.WriteString("All quiet: nothing new needed your attention.\n\n")
	} else {
		fmt.Fprintf(&out, "Alerts this period: %d serious, %d worth a look, %d minor.\n", counts[sevHigh], counts[sevMedium], counts[sevLow])
	}
	if quiet > 0 {
		fmt.Fprintf(&out, "%d more were alerts you had acknowledged or snoozed.\n", quiet)
	}
	if len(newDevices) > 0 {
		sort.Strings(newDevices)
		out.WriteString("\nNew devices:\n")
		for _, d := range newDevices {
			out.WriteString("- " + d + "\n")
		}
	}
	if len(open) > 0 {
		sort.Slice(open, func(i, j int) bool {
			if sevRank[open[i].Severity] != sevRank[open[j].Severity] {
				return sevRank[open[i].Severity] > sevRank[open[j].Severity]
			}
			return open[i].ID < open[j].ID
		})
		out.WriteString("\nStill to fix:\n")
		seen := map[string]bool{}
		for _, f := range open {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			out.WriteString("- " + f.Title + "\n")
			if f.Fix != "" {
				out.WriteString("  Fix: " + f.Fix + "\n")
			}
		}
	}
	out.WriteString("\nWatched:\n")
	out.WriteString(b.String())
	return title, out.String()
}

// Domains is the list of watched domains, for outside views.
func (st *watchState) Domains() []string { return st.Snap.Domains }
