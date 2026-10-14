package main

import "fmt"

// fixFor gives plain step-by-step advice for a change, so every alert says
// what to do about it. Findings carry their own advice.

var portFixes = map[int]string{
	21:    "FTP sends passwords unencrypted. Turn it off on the device, or switch to SFTP.",
	23:    "Telnet sends passwords unencrypted and is a favourite target of botnets. Turn it off in the device's settings; if it cannot be turned off, update its firmware or replace the device.",
	135:   "Windows RPC should not be reachable from other devices. Turn on the Windows firewall (Settings > Privacy & security > Windows Security > Firewall).",
	139:   "Old Windows file sharing (NetBIOS) is open. Turn off file sharing on that device if you do not use it, or allow it only on your home network profile.",
	445:   "File sharing (SMB) is open. If you do not share files from this device, turn sharing off; if you do, use a strong password and make sure the router does not forward port 445.",
	1900:  "UPnP is answering. Turn UPnP off on the device (and on the router) unless something needs it.",
	161:   "SNMP is open and often uses the default password \"public\". Turn it off in the device's settings or change the community string.",
	3306:  "A MySQL database is reachable from the network. Make it listen on localhost only, or firewall it to the machines that need it.",
	3389:  "Remote Desktop is open. Turn it off if you do not use it (Settings > System > Remote Desktop); if you do, require Network Level Authentication and never forward it on the router.",
	5432:  "A PostgreSQL database is reachable from the network. Make it listen on localhost only, or firewall it.",
	5900:  "Screen sharing (VNC) is open. Turn it off if you do not use it (on a Mac: System Settings > General > Sharing > Screen Sharing), or set a strong password.",
	6379:  "A Redis database is open, usually with no password. Bind it to localhost and set requirepass.",
	9200:  "An Elasticsearch database is open, usually with no password. Bind it to localhost and turn on security.",
	11211: "Memcached is open and can be abused for attacks. Bind it to localhost.",
	27017: "A MongoDB database is open. Bind it to localhost and turn on authentication.",
	2375:  "The Docker API is open without a password, which gives full control of that machine. Close it now.",
}

func fixFor(c Change) string {
	who := c.who()
	switch c.Kind {
	case "host_new":
		return fmt.Sprintf("Check whether you know %s: yaklite scan shows its maker and name. If it is yours, name it (yaklite name %s \"Name\", or on the dashboard). If not, block it on the router and change your Wi-Fi password.", who, c.Host)
	case "port_open", "service_changed":
		if f, ok := portFixes[c.Port]; ok {
			return f
		}
		if c.Outside {
			return fmt.Sprintf("Port %d is reachable from the internet. Remove the port forward or UPnP mapping on the router unless you need it, and keep that service updated.", c.Port)
		}
		return fmt.Sprintf("If you did not expect %s to offer port %d, find out which app opened it and turn that off. If it is expected, add it with yaklite name %s \"Name\" --expect %d.", who, c.Port, c.Host, c.Port)
	case "tls_expired", "tls_expiring":
		return "Renew the certificate on that device (for a router or NAS, usually under its security or HTTPS settings), or turn on automatic renewal."
	case "tls_cert_changed":
		return "Usually a routine renewal. If the issuer changed and you did not change anything, someone may be intercepting traffic: check the device and your router."
	case "mac_changed":
		if c.Severity == sevHigh {
			return "If you did not replace the router, someone may be pretending to be it to read your traffic. Disconnect, restart the router, change the Wi-Fi password and look for unknown devices."
		}
		return "Usually the router handing that address to another device. Check the device list if you do not expect it."
	case "gateway_impersonated":
		return "Another device is pretending to be the router. Disconnect from this network now, especially on public Wi-Fi; at home, find and unplug that device and change the Wi-Fi password."
	case "dns_changed":
		return "If you did not change your DNS records, log in to your domain registrar, change the password, turn on two-factor login and restore the records."
	case "cert_mismatch":
		return "The site is serving a certificate for a different name. Fix the certificate on the server, or check that the name still points at your own server."
	case "zone_transfer_open":
		return "Your name servers hand out every record to anyone. Turn off zone transfers (AXFR) to unknown addresses in your DNS provider's settings."
	case "web_changed":
		if c.Severity == sevMedium {
			return "Your site looks down. Check the server and your hosting provider's status page."
		}
	}
	return ""
}
