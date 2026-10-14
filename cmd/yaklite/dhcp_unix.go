//go:build !windows

package main

import (
	"context"
	"crypto/rand"
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
