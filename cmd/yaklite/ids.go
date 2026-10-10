package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Suricata (or anything else writing Suricata's eve.json format) watches the
// traffic itself, which yaklite cannot. When its log is readable, serious
// alerts from the last day show up with yaklite's other alerts.
//
// The log is found at $YAKLITE_SURICATA_EVE, or /var/log/suricata/eve.json.

func init() {
	registerCheck(&check{name: "ids", about: "alerts from Suricata, if it runs on this machine (eve.json)", run: idsCheck})
}

func evePath() string {
	if p := os.Getenv("YAKLITE_SURICATA_EVE"); p != "" {
		return p
	}
	return "/var/log/suricata/eve.json"
}

type eveAlert struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Alert     struct {
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

func idsCheck(ctx context.Context, env *checkEnv) ([]*Finding, error) {
	f, err := os.Open(evePath())
	if err != nil {
		return nil, nil // no Suricata here
	}
	defer f.Close()
	return eveFindings(f, time.Now())
}

// eveFindings reads the tail of an eve.json log (the last 8 MB).
func eveFindings(f io.ReadSeeker, now time.Time) ([]*Finding, error) {
	if end, err := f.Seek(0, io.SeekEnd); err == nil && end > 8<<20 {
		f.Seek(end-8<<20, io.SeekStart)
	} else {
		f.Seek(0, io.SeekStart)
	}
	out := map[string]*Finding{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, []byte(`"alert"`)) {
			continue
		}
		var a eveAlert
		if json.Unmarshal(line, &a) != nil || a.EventType != "alert" || a.Alert.Severity > 2 || a.Alert.Severity < 1 {
			continue
		}
		t, err := time.Parse("2006-01-02T15:04:05.999999-0700", a.Timestamp)
		if err != nil || now.Sub(t) > 24*time.Hour {
			continue
		}
		id := fmt.Sprintf("ids:%d:%s", a.Alert.SignatureID, a.SrcIP)
		sev := sevMedium
		if a.Alert.Severity == 1 {
			sev = sevHigh
		}
		out[id] = &Finding{ID: id, Severity: sev, Host: a.SrcIP, Until: t.Add(24 * time.Hour),
			Title:  fmt.Sprintf("Suricata: %s, from %s to %s port %d", a.Alert.Signature, a.SrcIP, a.DestIP, a.DestPort),
			Detail: a.Alert.Category + ", last seen " + t.Local().Format("Jan 2 15:04"),
			Fix:    "Look up the signature name. If the source is on your network, check that device; if it is outside, make sure the target port is not exposed."}
	}
	var list []*Finding
	for _, f := range out {
		list = append(list, f)
	}
	return list, sc.Err()
}
