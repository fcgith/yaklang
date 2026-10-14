package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// firstOnlineFindings notes the first time each program connects to the
// internet, with where it went. A new program going online is how most
// spyware and stolen-password tools show themselves; for a newly installed
// app it is just a heads-up. Nothing is noted during the learning period.
func firstOnlineFindings(mem *connMemory, views []connView, now time.Time, learning bool) []*Finding {
	type dest struct{ who []string }
	byProg := map[string]*dest{}
	for _, c := range views {
		p := c.proc()
		if c.Inbound || p == "" || isOwnProcess(p) {
			continue
		}
		d := byProg[p]
		if d == nil {
			d = &dest{}
			byProg[p] = d
		}
		if len(d.who) < 3 {
			d.who = append(d.who, c.who())
		}
	}
	var progs []string
	for p := range byProg {
		progs = append(progs, p)
	}
	sort.Strings(progs)
	var out []*Finding
	for _, p := range progs {
		if _, ok := mem.Programs[p]; ok {
			continue
		}
		mem.Programs[p] = now
		if learning {
			continue
		}
		out = append(out, &Finding{ID: "first-online:" + p, Severity: sevLow, Until: now.Add(3 * 24 * time.Hour),
			Title:  fmt.Sprintf("%s connected to the internet for the first time", p),
			Detail: "It talked to " + strings.Join(byProg[p].who, ", ") + ".",
			Fix:    "Fine if you just installed or updated it. If you do not know what it is, quit it and look it up; `yaklite check --only apps` lists apps Apple has not checked."})
	}
	return out
}
