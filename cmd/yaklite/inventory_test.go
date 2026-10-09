package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func snap(hosts map[string][]*Service) *Snapshot {
	s := NewSnapshot("t", "p", "connect")
	for h, svcs := range hosts {
		s.Hosts[h] = svcs
	}
	return s
}

func kinds(cs []Change) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Kind+" "+c.Host)
	}
	return out
}

func TestDiffFirstRunReportsEverythingNew(t *testing.T) {
	cur := snap(map[string][]*Service{"10.0.0.2": {{Port: 22, Proto: "tcp"}}})
	cs := Diff(nil, cur, 2, time.Now())
	if len(cs) != 2 || cs[0].Kind != "host_new" || cs[1].Kind != "port_open" {
		t.Fatalf("got %v", kinds(cs))
	}
}

func TestDiffPortsAndServices(t *testing.T) {
	prev := snap(map[string][]*Service{"10.0.0.2": {
		{Port: 22, Proto: "tcp", Product: "OpenSSH", Version: "8.9", Verified: true},
		{Port: 80, Proto: "tcp", Service: "http"},
	}})
	cur := snap(map[string][]*Service{"10.0.0.2": {
		{Port: 22, Proto: "tcp", Product: "OpenSSH", Version: "9.6", Verified: true},
		{Port: 443, Proto: "tcp", Service: "https"},
	}})
	cs := Diff(prev, cur, 2, time.Now())
	want := map[string]bool{"service_changed 10.0.0.2": true, "port_open 10.0.0.2": true, "port_closed 10.0.0.2": true}
	if len(cs) != 3 {
		t.Fatalf("got %v", kinds(cs))
	}
	for _, c := range cs {
		if !want[c.Kind+" "+c.Host] {
			t.Fatalf("unexpected %v", c)
		}
	}
}

func TestDiffUnverifiedFingerprintIsNotAServiceChange(t *testing.T) {
	prev := snap(map[string][]*Service{"h": {{Port: 6379, Proto: "tcp", Service: "redis", Verified: true}}})
	cur := snap(map[string][]*Service{"h": {{Port: 6379, Proto: "tcp", Service: "opsec-ela", Verified: false}}})
	if cs := Diff(prev, cur, 1, time.Now()); len(cs) != 0 {
		t.Fatalf("flaky probe reported as change: %v", kinds(cs))
	}
}

func TestDiffHostGoneNeedsConsecutiveMisses(t *testing.T) {
	prev := snap(map[string][]*Service{"a": {{Port: 22, Proto: "tcp"}}, "b": {{Port: 80, Proto: "tcp"}}})
	cur := snap(map[string][]*Service{"a": {{Port: 22, Proto: "tcp"}}})
	if cs := Diff(prev, cur, 2, time.Now()); len(cs) != 0 {
		t.Fatalf("first miss should be silent, got %v", kinds(cs))
	}
	if cur.Misses["b"] != 1 || cur.Hosts["b"] == nil {
		t.Fatalf("missing host not carried forward: %+v", cur)
	}
	next := snap(map[string][]*Service{"a": {{Port: 22, Proto: "tcp"}}})
	cs := Diff(cur, next, 2, time.Now())
	if len(cs) != 1 || cs[0].Kind != "host_gone" || cs[0].Host != "b" {
		t.Fatalf("got %v", kinds(cs))
	}
	// a host that comes back resets its miss count
	back := snap(map[string][]*Service{"a": {{Port: 22, Proto: "tcp"}}, "b": {{Port: 80, Proto: "tcp"}}})
	if cs := Diff(cur, back, 2, time.Now()); len(cs) != 0 || back.Misses["b"] != 0 {
		t.Fatalf("returning host: %v misses=%d", kinds(cs), back.Misses["b"])
	}
}

func TestSnapshotFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "s.json")
	s := snap(map[string][]*Service{"h": {{Port: 22, Proto: "tcp"}}})
	if err := SaveSnapshot(p, s); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(p))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	got, err := LoadSnapshot(p)
	if err != nil || len(got.Hosts["h"]) != 1 {
		t.Fatalf("round trip: %v %+v", err, got)
	}
}
