package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// The connection watch also notices when the internet goes away: every
// cycle it opens a connection to three public DNS providers, and when none
// answer while the computer is still on a network, the internet is down.
// Outages are logged and alerted (gently) when the connection comes back.

type outageState struct {
	DownSince time.Time `json:"down_since,omitempty"`
	LastProbe time.Time `json:"last_probe"`
}

type outage struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (o outage) String() string {
	d := o.End.Sub(o.Start).Round(time.Minute)
	day := o.Start.Local().Format("Mon 2 Jan")
	return fmt.Sprintf("%s %s–%s (%s)", day, o.Start.Local().Format("15:04"), o.End.Local().Format("15:04"), d)
}

func internetUp(ctx context.Context) bool {
	res := make(chan bool, 3)
	for _, a := range []string{"1.1.1.1:443", "9.9.9.9:443", "8.8.8.8:443"} {
		go func(a string) {
			d := net.Dialer{Timeout: 4 * time.Second}
			c, err := d.DialContext(ctx, "tcp", a)
			if err == nil {
				c.Close()
			}
			res <- err == nil
		}(a)
	}
	for i := 0; i < 3; i++ {
		if <-res {
			return true
		}
	}
	return false
}

func loadOutages(dir string) []outage {
	f, err := os.Open(filepath.Join(dir, "outages.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []outage
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var o outage
		if json.Unmarshal(sc.Bytes(), &o) == nil {
			out = append(out, o)
		}
	}
	return out
}

// trackOutage updates the outage state with one probe result and returns a
// finding when an outage just ended.
func trackOutage(dir string, up, onNetwork bool, now time.Time) *Finding {
	p := filepath.Join(dir, "outage-state.json")
	var st outageState
	if data, err := os.ReadFile(p); err == nil {
		json.Unmarshal(data, &st)
	}
	defer func() {
		st.LastProbe = now
		if data, err := json.Marshal(st); err == nil {
			writeFilePrivate(p, data)
		}
	}()
	if !st.LastProbe.IsZero() && now.Sub(st.LastProbe) > 5*time.Minute {
		st.DownSince = time.Time{} // asleep or not running: no idea what happened meanwhile
	}
	switch {
	case !onNetwork:
		st.DownSince = time.Time{} // off Wi-Fi is not an internet outage
	case !up:
		if st.DownSince.IsZero() {
			st.DownSince = now
		}
	case !st.DownSince.IsZero():
		o := outage{Start: st.DownSince, End: now}
		st.DownSince = time.Time{}
		if o.End.Sub(o.Start) < 90*time.Second {
			return nil
		}
		if data, err := json.Marshal(o); err == nil {
			if f, err := os.OpenFile(filepath.Join(dir, "outages.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				f.Write(append(data, '\n'))
				f.Close()
			}
		}
		today := 0
		for _, x := range loadOutages(dir) {
			if now.Sub(x.Start) < 24*time.Hour {
				today++
			}
		}
		f := &Finding{ID: "outage:" + o.Start.UTC().Format("20060102T1504"), Severity: sevLow, Until: now.Add(time.Hour),
			Title: "Your internet was down: " + o.String(),
			Fix:   "Usually the provider. If it keeps happening, restart the router and note the times for your provider; repeated short drops can also mean someone is attacking your connection."}
		if today >= 3 {
			f.Severity = sevMedium
			f.Title = fmt.Sprintf("Your internet was down for the %d%s time in 24 hours: %s", today, ordSuffix(today), o.String())
		}
		return f
	}
	return nil
}

func ordSuffix(n int) string {
	switch {
	case n%100 >= 11 && n%100 <= 13:
		return "th"
	case n%10 == 1:
		return "st"
	case n%10 == 2:
		return "nd"
	case n%10 == 3:
		return "rd"
	}
	return "th"
}

func recentOutages(dir string, now time.Time, n int) []string {
	all := loadOutages(dir)
	var out []string
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		if now.Sub(all[i].Start) < 7*24*time.Hour {
			out = append(out, all[i].String())
		}
	}
	return out
}

// outagesSince is one summary line about outages in a period.
func outagesSince(dir string, from time.Time) string {
	n := 0
	var total time.Duration
	for _, o := range loadOutages(dir) {
		if o.Start.After(from) {
			n++
			total += o.End.Sub(o.Start)
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("Internet outages: %d, %s in total (yaklite outages lists them).", n, total.Round(time.Minute))
}

func cmdOutages(args []string) error {
	fs := flag.NewFlagSet("outages", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	fs.Parse(args)
	all := loadOutages(*stateDir)
	if len(all) == 0 {
		fmt.Println("No internet outages recorded (the connection watch records them; yaklite install starts it).")
		return nil
	}
	for _, o := range all {
		fmt.Println(o.String())
	}
	return nil
}
