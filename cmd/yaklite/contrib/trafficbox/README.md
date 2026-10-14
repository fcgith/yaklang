# Traffic box

A small always-on computer (a Raspberry Pi 4 or 5, or an old laptop with Linux)
that watches your home network's traffic for known attacks, infected devices
and malware calling home. It runs [Suricata](https://suricata.io), a free
intrusion detection system, and yaklite turns Suricata's alerts into the same
plain alerts as the rest of yaklite, with what to do about each.

It only watches. It does not block anything and changes nothing on the network.

## Getting the traffic to the box

Suricata can only see traffic that reaches the box's network port. Pick one:

- **A switch with port mirroring** (easiest): plug the router's LAN cable into
  a small managed switch (TP-Link TL-SG105E, Netgear GS305E, about 30 euros),
  turn on "port mirroring" in its settings, mirror the router's port to the
  box's port.
- **MikroTik router**: Tools > Packet Sniffer, stream to the box's address
  (TZSP), and on the box run Suricata on a TZSP interface instead. This is
  more fiddly.
- **OpenWrt router**: install `suricata` on a router with enough memory, or use
  `iptables -j TEE` to copy traffic to the box.

Without one of these the box only sees its own traffic and broadcasts, which
catches very little.

## Starting it

On the box, with Docker installed and this repository cloned:

```sh
# edit compose.yaml: set INTERFACE and -i to the port that gets the mirrored traffic
docker compose -f cmd/yaklite/contrib/trafficbox/compose.yaml up -d --build
docker compose -f cmd/yaklite/contrib/trafficbox/compose.yaml exec suricata suricata-update
docker compose -f cmd/yaklite/contrib/trafficbox/compose.yaml restart suricata
```

Run the two `suricata-update` lines weekly (a cron job) to keep the rules fresh.

Add `--webhook https://ntfy.sh/your-topic` to the `yaklite-traffic` command to
get alerts on your phone. Without Docker, install Suricata from your
distribution and run `yaklite traffic --eve /var/log/suricata/eve.json --notify`.

## What you get

One alert per rule and pair of devices per day, for example:

> Suspicious traffic from 192.168.1.42 to 203.0.113.9:443: ET MALWARE ... (12 times)
> What to do: A device may be infected. Find which one has address 192.168.1.42 ...

Routine informational rules (ET INFO, ET POLICY) are left out unless Suricata
rates them high.
