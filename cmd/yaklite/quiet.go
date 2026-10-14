package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Quiet hours and grouping. High alerts always go out at once. Others are
// held during quiet hours and, when grouping is on, collected for a few
// minutes so a burst arrives as one message. Every running watch flushes
// the queue on its next cycle, so nothing waits much longer than that.

type alertSettings struct {
	Quiet        string `yaml:"quiet_hours,omitempty"`   // "22:00-07:00"
	GroupMinutes int    `yaml:"group_minutes,omitempty"` // 0 = send each alert as it comes
}

func alertSettingsPath() string { return filepath.Join(configDir(), "alerts.yaml") }

func loadAlertSettings() alertSettings {
	var s alertSettings
	if data, err := os.ReadFile(alertSettingsPath()); err == nil {
		yaml.Unmarshal(data, &s)
	}
	return s
}

// parseClockRange reads "22:00-07:00" as minutes after midnight.
func parseClockRange(s string) (from, to int, err error) {
	a, b, ok := strings.Cut(strings.ReplaceAll(s, " ", ""), "-")
	if !ok {
		return 0, 0, fmt.Errorf("quiet hours must look like 22:00-07:00, not %q", s)
	}
	clock := func(x string) (int, error) {
		h, m, _ := strings.Cut(x, ":")
		hh, err1 := strconv.Atoi(h)
		mm := 0
		var err2 error
		if m != "" {
			mm, err2 = strconv.Atoi(m)
		}
		if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
			return 0, fmt.Errorf("bad time %q in quiet hours", x)
		}
		return hh*60 + mm, nil
	}
	if from, err = clock(a); err != nil {
		return
	}
	to, err = clock(b)
	return
}

// inQuiet says whether t (local time) falls in the quiet hours.
func (s alertSettings) inQuiet(t time.Time) bool {
	if s.Quiet == "" {
		return false
	}
	from, to, err := parseClockRange(s.Quiet)
	if err != nil || from == to {
		return false
	}
	now := t.Hour()*60 + t.Minute()
	if from < to {
		return now >= from && now < to
	}
	return now >= from || now < to // over midnight
}

type heldAlert struct {
	Held    time.Time `json:"held"`
	Desktop string    `json:"desktop,omitempty"`
	Webhook string    `json:"webhook,omitempty"`
	Format  string    `json:"format,omitempty"`
	Change  Change    `json:"change"`
}

func heldPath(stateDir string) string { return filepath.Join(stateDir, "held-alerts.jsonl") }

// splitForDelivery decides what goes now and what waits.
func splitForDelivery(s alertSettings, changes []Change, now time.Time) (send, hold []Change) {
	quiet := s.inQuiet(now)
	for _, c := range changes {
		if c.Severity == sevHigh || (!quiet && s.GroupMinutes <= 0) {
			send = append(send, c)
		} else {
			hold = append(hold, c)
		}
	}
	return
}

// deliver shows and sends alerts, holding the ones that can wait.
func deliver(ctx context.Context, ac *alertConfig, stateDir string, changes []Change) {
	send, hold := splitForDelivery(loadAlertSettings(), changes, time.Now())
	if len(hold) > 0 {
		if f, err := os.OpenFile(heldPath(stateDir), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			for _, c := range hold {
				data, _ := json.Marshal(heldAlert{Held: time.Now(), Desktop: ac.desktop, Webhook: ac.webhook, Format: ac.webhookFormat, Change: c})
				f.Write(append(data, '\n'))
			}
			f.Close()
		}
	}
	if len(send) > 0 {
		sendNow(ctx, ac.desktop, ac.webhook, ac.webhookFormat, send)
	}
}

func sendNow(ctx context.Context, desktop, webhook, format string, changes []Change) {
	if desktop != "" {
		notifyChanges(desktop, changes)
	}
	for _, err := range sendAlerts(ctx, webhook, format, changes) {
		fmt.Fprintln(os.Stderr, "[yaklite] alert delivery failed:", err)
	}
}

// heldReady says whether the held alerts should go out now.
func heldReady(s alertSettings, held []heldAlert, now time.Time) bool {
	if len(held) == 0 || s.inQuiet(now) {
		return false
	}
	oldest := held[0].Held
	for _, h := range held {
		if h.Held.Before(oldest) {
			oldest = h.Held
		}
	}
	return now.Sub(oldest) >= time.Duration(s.GroupMinutes)*time.Minute
}

// flushHeld sends the held alerts once their time has come, grouped by
// destination so each place gets one message.
func flushHeld(ctx context.Context, stateDir string) {
	p := heldPath(stateDir)
	held := readHeld(p)
	if !heldReady(loadAlertSettings(), held, time.Now()) {
		return
	}
	// claim the file so two watches do not both send it
	claim := fmt.Sprintf("%s.%d", p, os.Getpid())
	if os.Rename(p, claim) != nil {
		return
	}
	held = readHeld(claim)
	os.Remove(claim)
	type dest struct{ webhook, format string }
	byDest := map[dest][]Change{}
	desktops := map[string]bool{}
	var all []Change
	seen := map[string]bool{}
	for _, h := range held {
		k := h.Change.Key()
		if seen[h.Webhook+"\x00"+k] {
			continue
		}
		seen[h.Webhook+"\x00"+k] = true
		if h.Webhook != "" {
			byDest[dest{h.Webhook, h.Format}] = append(byDest[dest{h.Webhook, h.Format}], h.Change)
		}
		if h.Desktop != "" {
			desktops[h.Desktop] = true
			all = append(all, h.Change)
		}
	}
	if len(all) > 0 {
		var names []string
		for d := range desktops {
			names = append(names, d)
		}
		sort.Strings(names)
		notifyChanges(strings.Join(names, ", "), all)
	}
	for d, cs := range byDest {
		for _, err := range sendAlerts(ctx, d.webhook, d.format, cs) {
			fmt.Fprintln(os.Stderr, "[yaklite] alert delivery failed:", err)
		}
	}
}

func readHeld(p string) []heldAlert {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []heldAlert
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var h heldAlert
		if json.Unmarshal(sc.Bytes(), &h) == nil {
			out = append(out, h)
		}
	}
	return out
}

// cmdQuiet sets quiet hours and grouping.
func cmdQuiet(args []string) error {
	fs := flag.NewFlagSet("quiet", flag.ExitOnError)
	group := fs.Int("group", -1, "collect alerts for this many minutes and send them as one message (0 = off)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: yaklite quiet [22:00-07:00 | off] [--group 10]\n\nDuring quiet hours only high alerts come through; the rest arrive when they end.")
		fs.PrintDefaults()
	}
	// allow the time range before or after the flag
	var rest []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			fs.Parse(args[i:])
			rest = append(rest, fs.Args()...)
			break
		}
		rest = append(rest, args[i])
	}
	s := loadAlertSettings()
	changed := false
	if len(rest) > 1 {
		return errors.New("usage: yaklite quiet [22:00-07:00 | off] [--group 10]")
	}
	if len(rest) == 1 {
		if rest[0] == "off" {
			s.Quiet = ""
		} else {
			if _, _, err := parseClockRange(rest[0]); err != nil {
				return err
			}
			s.Quiet = rest[0]
		}
		changed = true
	}
	if *group >= 0 {
		if *group > 24*60 {
			return errors.New("--group is in minutes, at most 1440")
		}
		s.GroupMinutes = *group
		changed = true
	}
	if changed {
		data, _ := yaml.Marshal(s)
		os.MkdirAll(configDir(), 0o700)
		if err := writeFilePrivate(alertSettingsPath(), append([]byte("# yaklite alert timing (yaklite quiet)\n"), data...)); err != nil {
			return err
		}
	}
	if s.Quiet == "" {
		fmt.Println("Quiet hours: off")
	} else {
		fmt.Println("Quiet hours:", s.Quiet, "(high alerts still come through)")
	}
	if s.GroupMinutes > 0 {
		fmt.Printf("Grouping: alerts are collected for %d minutes and sent together (high alerts go at once)\n", s.GroupMinutes)
	} else {
		fmt.Println("Grouping: off (each alert is sent as it comes)")
	}
	return nil
}
