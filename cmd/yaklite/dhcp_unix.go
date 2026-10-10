//go:build !windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"
)

// dhcpDiscover broadcasts a DHCP DISCOVER and lists the servers that offer
// an address. It needs root to use port 68, and accepts nothing it is offered.
func dhcpDiscover(ctx context.Context, iface string) ([]string, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return nil, errors.New("no MAC address for " + iface)
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
			if serr == nil {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}
		})
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, "udp4", ":68")
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	var xid [4]byte
	rand.Read(xid[:])
	pkt := dhcpDiscoverPacket(xid, ifi.HardwareAddr)
	if _, err := pc.WriteTo(pkt, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return nil, err
	}
	pc.SetReadDeadline(time.Now().Add(4 * time.Second))
	var servers []string
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if s := dhcpOfferServer(buf[:n], xid); s != "" {
			if s == "0.0.0.0" {
				s = from.(*net.UDPAddr).IP.String()
			}
			if !contains(servers, s) {
				servers = append(servers, s)
			}
		}
	}
	return servers, nil
}

func dhcpDiscoverPacket(xid [4]byte, mac net.HardwareAddr) []byte {
	p := make([]byte, 240, 300)
	p[0], p[1], p[2] = 1, 1, 6 // BOOTREQUEST, Ethernet, MAC length
	copy(p[4:8], xid[:])
	binary.BigEndian.PutUint16(p[10:], 0x8000) // ask for a broadcast reply
	copy(p[28:], mac)
	copy(p[236:], []byte{99, 130, 83, 99}) // magic cookie
	p = append(p, 53, 1, 1)                // DHCPDISCOVER
	p = append(p, 55, 3, 1, 3, 6)          // ask for netmask, router, DNS
	p = append(p, 255)
	return p
}

// dhcpOfferServer returns the server identifier of an OFFER for xid.
func dhcpOfferServer(p []byte, xid [4]byte) string {
	if len(p) < 240 || p[0] != 2 || [4]byte(p[4:8]) != xid || [4]byte(p[236:240]) != [4]byte{99, 130, 83, 99} {
		return ""
	}
	offer, server := false, "0.0.0.0"
	for i := 240; i < len(p); {
		code := p[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(p) || i+2+int(p[i+1]) > len(p) {
			break
		}
		val := p[i+2 : i+2+int(p[i+1])]
		switch {
		case code == 53 && len(val) == 1:
			offer = val[0] == 2
		case code == 54 && len(val) == 4:
			server = net.IP(val).String()
		}
		i += 2 + len(val)
	}
	if !offer {
		return ""
	}
	return server
}
