package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// When reverse DNS has no name for a device, ask the device itself: Apple
// devices, Chromecasts, printers and many smart-home gadgets answer a
// multicast-DNS question sent straight to them, and Windows machines and
// NAS boxes answer a NetBIOS name query. Both are single small packets to
// the device; nothing is broadcast.

func announcedNames(ctx context.Context, devices map[string]*Device) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 16)
	for h, d := range devices {
		if d.Hostname != "" || d.Self {
			continue
		}
		ip := net.ParseIP(h).To4()
		if ip == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP, d *Device) {
			defer wg.Done()
			defer func() { <-sem }()
			name := mdnsName(ctx, ip)
			if name == "" {
				name = netbiosName(ctx, ip)
			}
			if name != "" {
				mu.Lock()
				d.Hostname = name
				mu.Unlock()
			}
		}(ip, d)
	}
	wg.Wait()
}

func udpAsk(ctx context.Context, ip net.IP, port int, q []byte) []byte {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil
	}
	defer conn.Close()
	deadline := time.Now().Add(1200 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	if _, err := conn.Write(q); err != nil {
		return nil
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// mdnsName sends a unicast reverse (PTR) question to the device's mDNS port.
func mdnsName(ctx context.Context, ip net.IP) string {
	var id [2]byte
	rand.Read(id[:])
	q := append([]byte{id[0], id[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, encodeName(reverseName(ip))...)
	q = append(q, 0, 12, 0, 1) // PTR, IN
	resp := udpAsk(ctx, ip, 5353, q)
	return cleanHostname(parsePTRAnswer(resp))
}

func reverseName(ip net.IP) string {
	v4 := ip.To4()
	return net.IPv4(v4[3], v4[2], v4[1], v4[0]).String() + ".in-addr.arpa"
}

func encodeName(n string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// readName decodes a possibly compressed DNS name at off.
func readName(msg []byte, off int) (string, int) {
	var labels []string
	end := -1
	for hops := 0; off < len(msg) && hops < 32; hops++ {
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", -1
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
		default:
			if off+1+l > len(msg) {
				return "", -1
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", -1
}

func parsePTRAnswer(msg []byte) string {
	if len(msg) < 12 || msg[2]&0x80 == 0 {
		return ""
	}
	qd, an := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, off = readName(msg, off)
		if off < 0 || off+4 > len(msg) {
			return ""
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		_, off = readName(msg, off)
		if off < 0 || off+10 > len(msg) {
			return ""
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return ""
		}
		if typ == 12 {
			name, _ := readName(msg, off)
			return name
		}
		off += rdlen
	}
	return ""
}

// netbiosName sends a NetBIOS node status query and returns the machine name.
func netbiosName(ctx context.Context, ip net.IP) string {
	var id [2]byte
	rand.Read(id[:])
	q := []byte{id[0], id[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K'}
	for i := 0; i < 30; i++ {
		q = append(q, 'A') // the wildcard name "*", encoded
	}
	q = append(q, 0, 0, 0x21, 0, 1) // NBSTAT, IN
	return cleanHostname(parseNBStat(udpAsk(ctx, ip, 137, q)))
}

func parseNBStat(msg []byte) string {
	// header(12) + name(34) + type/class(4) + ttl(4) + rdlen(2) = 56, then count
	if len(msg) < 57 {
		return ""
	}
	n := int(msg[56])
	for i := 0; i < n; i++ {
		off := 57 + i*18
		if off+18 > len(msg) {
			break
		}
		name := strings.TrimRight(string(msg[off:off+15]), " \x00")
		suffix, flags := msg[off+15], msg[off+16]
		if suffix == 0x00 && flags&0x80 == 0 { // workstation name, not a group
			return name
		}
	}
	return ""
}

func cleanHostname(n string) string {
	n = strings.TrimSuffix(strings.TrimSpace(n), ".")
	n = strings.TrimSuffix(n, ".local")
	if n == "" || len(n) > 63 || strings.ContainsAny(n, "\x00\n\r\t") {
		return ""
	}
	return n
}
