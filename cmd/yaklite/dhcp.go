package main

import (
	"encoding/binary"
	"net"
)

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
