# yaklite

A small network inventory and change-monitoring tool built from the parts of
yaklang that held up in testing: the port scanner (connect and SYN) and the
service fingerprinter (nmap-derived probes plus ~11.8k web/CPE rules).

It answers two questions for a network you own:

- **What is on my network right now?** `yaklite scan`
- **What changed since last time?** `yaklite watch` / `yaklite diff`

Only scan networks you own or are authorised to test.

## Set and forget on a Mac (or Linux laptop)

```sh
curl -fsSLo yaklite https://github.com/fcgith/yaklang/releases/download/yaklite-latest/yaklite-macos
chmod +x yaklite
./yaklite install
```

That is all. `install` copies itself to `~/Library/Application Support/yaklite/`,
asks whether the network you are on is yours, and sets up two background jobs
for your user (no admin password):

- a check that runs at login, every hour, and **whenever you join a network**
  (launchd watches the network configuration), and
- the dashboard on <http://127.0.0.1:9842/>.

Problems show up as normal macOS notifications. Add
`--webhook https://ntfy.sh/your-topic` to also get them on your phone.

What a check does depends on the network:

| Network | What yaklite does |
| --- | --- |
| **Trusted** (you said it is yours) | Watches every device on it, as `watch` does: new and unknown devices, risky open ports, certificates, UDP services, the router's MAC changing and ARP spoofing |
| **Untrusted** (café, hotel, someone else's office) | Does not scan other people's devices. Checks what **this computer** exposes there (file sharing, remote login, databases, dev servers) and reads the neighbour table the OS already has to spot another device answering as the router |

Networks are told apart by the router's MAC address, so home, office and the
café down the road each keep their own baseline. A network you have not seen
before is untrusted, and you get a notification saying so. Commands:

```sh
yaklite status                                  # current network, trusted or not, last check
yaklite trust --name Office                     # monitor every device here (only on networks you may scan)
yaklite untrust
yaklite name 192.168.1.10 "NAS" --expect 22,443  # name a device (IP or MAC) and the ports it may expose
yaklite name aa:bb:cc:dd:ee:ff "Kid's tablet"
yaklite uninstall [--purge]
```

Settings live in `~/.config/yaklite/` (`networks.yaml`, `inventory.yaml`),
state and logs in `~/.local/state/yaklite/`. Alerts default to `medium` and
above.

Good to know:

- **No admin rights are needed.** Everything uses normal connections and the
  OS neighbour table. Only the optional `--syn` scan needs root.
- **Unsigned binary.** Downloading with `curl` as above avoids the Gatekeeper
  prompt. If you download it in a browser, macOS will block the first run.
  Allow it under System Settings > Privacy & Security, or run
  `xattr -d com.apple.quarantine yaklite`. Signing and notarizing needs an
  Apple Developer ID, which this build does not have.
- **Local Network permission (macOS 15 and later).** macOS may ask whether
  yaklite can find devices on your local network. Say yes; without it,
  trusted-network scans see nothing beyond the router.
- On Linux, `install` creates systemd user units (`yaklite-auto.timer`,
  `yaklite-web.service`) that check every hour; notifications use
  `notify-send`.
- yaklite detects and warns. It cannot block anything, because that needs
  control of the router or firewall. Each alert says what changed, so you know
  what to fix.

## What it leaves out, on purpose

The full `yak` binary is 310 MB and ships an AI agent, gRPC engine, MITM CA,
plugin store and self-updater. Testing found unsafe defaults in several of
these. yaklite links none of them:

| Full yak | yaklite |
| --- | --- |
| Resets umask to 0, so files and the CA key end up world-readable or world-writable | Leaves your umask alone. State dir is `0700`, files are `0600` |
| Creates `~/yakit-projects` | Keeps yaklang's working files in `~/.local/state/yaklite/engine` (`0700`) |
| gRPC, MCP, AI gateway and reverse listeners, some on `0.0.0.0` | Opens no listening sockets, except the optional read-only dashboard, which is localhost-only unless you set a password |
| Self-update and plugin downloads with TLS verification off | No update or download code. The webhook uses Go's default client with certificate checks, and plain `http://` is refused except to localhost |
| AI provider calls to the vendor cloud by default | No AI code |

Binary size: about 57 MB (stripped) against 310 MB.

## Usage

```sh
go build -ldflags "-s -w" -o yaklite ./cmd/yaklite

# one-off inventory of your LAN, common ports, with fingerprints
./yaklite scan -t 192.168.1.0/24

# all ports on a single host, saved as JSON
./yaklite scan -t 192.168.1.10 -p all -o nas.json

# faster subnet discovery with raw SYN packets (root or CAP_NET_RAW)
sudo ./yaklite scan -t 192.168.1.0/24 -p top --syn

# compare two saved scans (exit code 3 when anything changed)
./yaklite diff monday.json friday.json

# your domains and public IP, seen from the internet
./yaklite outside -d example.com --ip 203.0.113.7 --scan
```

`-p` accepts `top` (default, ~80 ports common on home and office networks:
SSH, web, SMB, RDP, VNC, printers, NAS, MQTT, Home Assistant, Plex, Jellyfin,
Docker, Kubernetes, databases, WireGuard), `all`, or a list such as
`22,80,8000-8100`.

Fingerprints that come only from the port number are shown as
`(unconfirmed)` and are never reported as a service change, so a flaky probe
does not raise an alert.

## Finding every device, not just ones with open ports

On networks the machine is directly attached to, yaklite also finds devices
by their MAC address, so phones, TVs and IoT gadgets with no open ports show
up too. It sends one tiny UDP packet to each address, which makes the OS look
up its MAC, then reads the OS neighbour table (`/proc/net/arp` on Linux,
`arp -an` on macOS). No root is needed. For each device it records:

- the MAC address and the maker, from the IEEE vendor registry built into
  the binary (`data/oui.txt.gz`; rebuild with `contrib/update-oui.py`)
- whether the MAC is a private, randomized one, as phones use
- its name from reverse DNS, which most home routers answer with the name
  the device gave over DHCP (`--no-names` skips this)
- which device is the default gateway

`--no-arp` turns this off.

This adds three alerts aimed at someone tampering with the network:

| Change | Severity |
| --- | --- |
| The router's MAC address changed (a new router, or someone impersonating it) | high |
| Another device answers with the router's MAC (the usual sign of ARP spoofing) | high |
| An IP now belongs to a different MAC | medium for devices in your inventory, otherwise low |

The inventory file can name devices by MAC address as well as by IP, which
keeps working when the router hands out a new IP:

```yaml
hosts:
  "b8:27:eb:12:34:56":
    name: Pi-hole
    expect: [22, 53, 80]
```

With an inventory, any device that is not in it raises a medium "unknown
device joined the network" alert.

### UDP services

`--udp` also asks every live device about common UDP services, using the
fingerprinter's UDP probes: DNS, TFTP, NTP, NetBIOS, SNMP, IPsec, IPMI,
SSDP/UPnP, STUN, SIP, mDNS, CoAP, Ubiquiti discovery and memcached
(`--udp-ports` to change). A UDP port is only reported when the service
answers, since silence proves nothing. TFTP, SNMP and IPMI count as risky.
It adds roughly 5 to 10 seconds per device, run in parallel.

## Outside view: what the internet sees of you

`yaklite outside` watches domains and public IPs you own from the outside:

```sh
# one look, no alerts
./yaklite outside -d example.com --scan

# every 6 hours, alerting like watch does
./yaklite outside -d example.com,example.org --ip 203.0.113.7 --webhook https://ntfy.sh/your-topic

# from a cheap VPS, to see your home connection the way an attacker does
./yaklite outside --ip $(curl -s https://ifconfig.me) --once
```

Each run:

1. **Finds names.** It searches the certificate transparency logs (crt.sh and
   certspotter, which receive only the domain name) for every certificate ever
   issued under your domains. `--brute` also guesses names with yaklang's DNS
   wordlist, and `--no-ct` skips the log search. Names that no longer resolve
   are dropped.
2. **Checks your DNS servers for open zone transfers.** It uses yaklang's AXFR
   check against your domain's own name servers. An open zone transfer hands
   your whole zone to anyone.
3. **Resolves every name and checks its website.** For each name it reads
   the certificate on 443 and checks that it covers the name, then loads the
   home page to record the status, `Server` header and title.
4. **Port scans the public IPs you list with `--ip`,** with the same
   fingerprinting as `scan`. IPs that your names resolve to are not scanned by
   default, because they often belong to a CDN or hosting provider rather
   than to you. Add `--scan-resolved` when you own them.

Alerts:

| Change | Severity |
| --- | --- |
| Your DNS servers allow zone transfers | high |
| A risky port (RDP, SMB, databases, ...) is reachable from the internet | high |
| Any other port opens on a public IP | medium |
| A name now resolves to different IPs (a move, or a hijack) | medium |
| The certificate on a name does not cover it | medium |
| A site starts failing (5xx or unreachable) | medium |
| A certificate expires soon, expires, or changes issuer | medium/high, as for the LAN |
| A new name appears (for example a new certificate was issued) | low |
| The `Server` header or status class changes | low |

Scanning your public IP from inside your own network goes through your
router's NAT loopback, which can show ports the internet cannot reach (or
hide ones it can). Run `outside --ip` from a machine outside your network,
such as a small VPS, for the real picture.

## Monitoring with watch

`yaklite watch` scans on a schedule, keeps the last snapshot, and reports:

- `host_new`, `host_gone` (only after `--gone-after` scans in a row, default 2, so a sleeping laptop does not alert every hour)
- `port_open`, `port_closed`
- `service_changed` (for example `OpenSSH 8.9p1 -> Dropbear sshd 2022.83`)
- `tls_expiring`, `tls_expired`, `tls_cert_changed` for HTTPS and other TLS
  ports (see below)

Every change gets a severity (`info`, `low`, `medium`, `high`) and is appended
to `<state>/<name>.changes.jsonl`. Only changes at or above `--min-severity`
(default `low`) are printed, posted and counted for the exit code.

```sh
# long-running
./yaklite watch -t 192.168.1.0/24 --every 1h --inventory home.yaml --webhook https://ntfy.sh/your-topic

# one cycle, for cron or a systemd timer (exit 3 = changes found)
./yaklite watch -t 192.168.1.0/24 --once --inventory home.yaml
```

### Device inventory (optional, recommended)

Tell yaklite what your devices are and which ports they are allowed to
expose. Alerts then use names instead of IPs and only escalate what does not
match.

```yaml
# home.yaml
hosts:
  192.168.1.1:
    name: Router
    expect: [53, 80, 443]
  192.168.1.10:
    name: NAS
    expect: [22, 443, 5000, 5001]
  192.168.1.20:
    name: Living room TV          # known device, any ports
  192.168.1.99:
    name: Guest laptop
    ignore: true                  # never alert about this host
# risky_ports: [23, 445, 3389]    # optional, replaces the built-in list
```

How severities are assigned:

| Change | Severity |
| --- | --- |
| Port opens on a risky port (Telnet, FTP, SMB, RDP, VNC, Redis, MongoDB, Docker API without TLS, databases, ...) and it is not in `expect`, or a service changes into one of those | high |
| TLS certificate expired | high |
| New host that is not in the inventory | medium (low without an inventory) |
| Port opens that is not in the host's `expect` list | medium |
| A port in `expect` stops answering | medium |
| TLS certificate expires within `--tls-warn-days` (default 21) | medium |
| Certificate replaced by one from a different issuer | medium |
| Other new ports, service version changes, same-issuer renewals, a known device going offline | low |
| Expected ports, known devices joining, other ports closing, unknown devices leaving | info |

The first run records a baseline. With an inventory it reports anything that
already does not match it. Without one it only reports `high` findings, such
as an exposed Telnet or Redis port, so the first run is not a wall of
"new host" lines.

### TLS certificate checks

On common TLS ports (443, 8443, 993, 5001, ...) and on anything the
fingerprinter identifies as SSL/TLS, yaklite reads the certificate the
service presents: subject, issuer, expiry, fingerprint, TLS version and
whether it is self-signed. It sends no application data. Expiry is alerted
once when the certificate enters the warning window and once when it expires,
not on every scan. `--tls-warn-days 0` turns expiry warnings off and
`--no-tls` skips certificate reads entirely.

### Notifications

`--webhook` takes an `https://` URL (plain `http://` only to localhost). The
body is picked from the URL, or set it with `--webhook-format`:

| Service | Example URL | Format |
| --- | --- | --- |
| ntfy | `https://ntfy.sh/your-topic` | text with title, priority and tags headers |
| Discord | `https://discord.com/api/webhooks/<id>/<token>` | `content` |
| Telegram | `https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>` | `text` |
| Slack, Mattermost | `https://hooks.slack.com/services/...` | `text` |
| Gotify | `https://gotify.example/message?token=<APP_TOKEN>` | title, message, priority |
| Anything else | your own endpoint | `{"text": "...", "changes": [...]}` (`json`) |

Priorities follow the worst severity in the batch, so a phone can ring for
`high` and stay quiet for `low`. Webhook URLs contain secrets, so keep them in
a root-owned unit file or environment file rather than shell history.

## Dashboard and Prometheus metrics

`yaklite serve` shows a read-only web page with each watched network's
devices, open ports, certificate status and recent changes, plus a
Prometheus `/metrics` endpoint. It reads the state directory on every
request, so it works next to a systemd timer that runs `watch --once`.
`watch --listen ADDR` serves the same thing from a long-running watch.

```sh
./yaklite serve --inventory home.yaml                # http://127.0.0.1:9842/
YAKLITE_WEB_PASSWORD=change-me ./yaklite serve --listen 0.0.0.0:9842
```

It listens on localhost only by default. Any other address is refused unless
`YAKLITE_WEB_PASSWORD` is set, because the page is a map of your network; the
browser or Prometheus then logs in with HTTP basic auth (any user name). The
server answers only GET, sets a strict Content-Security-Policy and runs no
JavaScript.

Metrics:

| Metric | Meaning |
| --- | --- |
| `yaklite_hosts`, `yaklite_open_ports` | Totals in the last snapshot, per `watch` |
| `yaklite_host_open_ports{host,name}` | Open ports per device |
| `yaklite_host_missed_scans{host,name}` | Scans in a row a known device did not answer |
| `yaklite_service_info{host,port,service,product,version,verified}` | One series per open port |
| `yaklite_tls_cert_expiry_timestamp_seconds{host,port,subject}` | When each certificate expires |
| `yaklite_changes_total{kind,severity}` | Counter of logged changes |
| `yaklite_last_scan_timestamp_seconds`, `yaklite_scan_duration_seconds` | Scan health |

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: yaklite
    scrape_interval: 1m
    static_configs: [{targets: ['127.0.0.1:9842']}]
    # basic_auth: {username: prometheus, password: change-me}
```

`contrib/grafana-dashboard.json` is a ready Grafana dashboard (import it and
pick your Prometheus data source): hosts and ports over time, changes by
severity, certificate days left and the open-port table. Useful alert rules:

```yaml
- alert: YakliteHighSeverityChange
  expr: increase(yaklite_changes_total{severity="high"}[1h]) > 0
- alert: YakliteCertExpiring
  expr: yaklite_tls_cert_expiry_timestamp_seconds - time() < 14 * 86400
- alert: YakliteNotScanning
  expr: time() - yaklite_last_scan_timestamp_seconds > 3 * 3600
```

## systemd timer (Linux LAN box)

`/etc/systemd/system/yaklite-lan.service`

```ini
[Unit]
Description=yaklite LAN change check

[Service]
Type=oneshot
User=yaklite
ExecStart=/usr/local/bin/yaklite watch -t 192.168.1.0/24 --once --syn -q --inventory /etc/yaklite/home.yaml --webhook https://ntfy.sh/your-topic
SuccessExitStatus=3
AmbientCapabilities=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
StateDirectory=yaklite
Environment=XDG_STATE_HOME=/var/lib
```

`/etc/systemd/system/yaklite-lan.timer`

```ini
[Timer]
OnCalendar=hourly
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now yaklite-lan.timer`. Drop `--syn` and
`AmbientCapabilities` to run without raw sockets.

For the dashboard, add `/etc/systemd/system/yaklite-web.service` with
`User=yaklite`, `Environment=XDG_STATE_HOME=/var/lib`,
`ExecStart=/usr/local/bin/yaklite serve --inventory /etc/yaklite/home.yaml`,
`Restart=on-failure` and an `[Install]` section with
`WantedBy=multi-user.target`.

## What was not extracted, and what to pair it with

These parts of yaklang were tested and were too weak to carry over:

- **Traffic analysis (pcap + Suricata rules).** `yak pcap --suricata` is a
  no-op, only HTTP flows reach the matcher, and core keywords such as
  `dsize`, `flags`, `flow`, `threshold`, `flowbits` and `byte_test` are parsed
  but never enforced, so rules over-fire. The statically linked libpcap 1.8.1
  could not open the repo's own test capture. Use **Suricata** (signatures)
  or **Zeek** (connection logs, protocol metadata) on a mirror/SPAN port
  instead. yaklite's inventory complements them by telling you which hosts
  and services should exist.
- **Host monitoring (HIDS).** Well-tested code, but it only reports to the
  closed-source Legion platform, is excluded from normal builds, and its eBPF
  exec events carry no arguments. Use **Wazuh**, **osquery** or **Falco**.
- **Host metrics.** yaklang has none. yaklite exports network inventory
  metrics; for CPU, disk and uptime use Prometheus node_exporter or Uptime Kuma.

## Licence

yaklite is part of this AGPL-3.0 repository and stays AGPL-3.0. Running it on
your own machines and LAN needs nothing extra. If you give others access to a
modified version over a network, you must offer them its source.
