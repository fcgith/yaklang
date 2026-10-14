# yaklite

A small network inventory and change-monitoring tool built from the parts of
yaklang that held up in testing: the port scanner (connect and SYN) and the
service fingerprinter (nmap-derived probes plus ~11.8k web/CPE rules).

It answers these questions for a network you own:

- **What is on my network right now?** `yaklite scan`
- **What changed since last time?** `yaklite watch` / `yaklite diff`
- **Is anyone from the internet talking to this computer, or is it talking
  to known attackers?** `yaklite conns` / `yaklite connwatch`
- **Is my router, Wi-Fi, DNS or this computer set up safely?** `yaklite check`
- **What does the internet see of me?** `yaklite outside`
- **Has anything changed inside this computer?** `yaklite check --only host`
- **How safe am I overall, and what should I fix first?** `yaklite score`
- **Are my passwords in a data leak?** `yaklite password-check`, `yaklite breaches`

It detects and warns. It can block a device or site only through an AdGuard
Home or Pi-hole you already run (`yaklite block`).

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
  (launchd watches the network configuration), including the safety checks
  below,
- a watch on this computer's own connections every 30 seconds
  (`--no-connwatch` to skip it),
- a weekly summary on Monday at 9:00 (`--no-summary` to skip it), and
- the dashboard on <http://127.0.0.1:9842/>.

Optional extras, each one flag on `install`:

| Flag | Adds |
| --- | --- |
| `--router-log` | Reads the router's own log (the router sends it to this computer): failed and successful admin logins, new port forwards, settings changes, floods of blocked connections. See [Router log](#router-log) |
| `--tripwire` | Fake services (Telnet, file sharing, remote desktop, printer, ...) that nothing should ever touch; anything on your network that tries them raises an alert |
| `--tailscale` | The dashboard on your phone, over your own [Tailscale](https://tailscale.com) network, with a password |
| `--accept-reports` | Other computers in the house send their results to this dashboard |
| `--report-to URL --report-token T` | This computer sends its results to another computer's dashboard |

Problems show up as normal macOS notifications. Add
`--webhook https://ntfy.sh/your-topic` to also get them on your phone, with
buttons to acknowledge, snooze or re-check (see [Alerts](#alerts-on-your-phone-email-and-chat)).
`yaklite update` later fetches the newest build and checks its checksum.

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
- **Unsigned binary, for now.** Downloading with `curl` as above avoids the
  Gatekeeper prompt. If you download it in a browser, macOS will block the
  first run. Allow it under System Settings > Privacy & Security, or run
  `xattr -d com.apple.quarantine yaklite`. The release workflow signs and
  notarizes the Mac build as soon as an Apple Developer ID is added to the
  repository's secrets (see the top of `.github/workflows/yaklite-release.yml`).
- **Local Network permission (macOS 15 and later).** macOS may ask whether
  yaklite can find devices on your local network. Say yes; without it,
  trusted-network scans see nothing beyond the router.
- On Linux, `install` creates systemd user units (`yaklite-auto.timer`,
  `yaklite-web.service`) that check every hour; notifications use
  `notify-send`.
- On Windows, see [Windows](#windows).
- yaklite detects and warns. Each alert says what changed and, where it
  can, how to fix it. Blocking needs AdGuard Home or Pi-hole (`yaklite block`).

## What it leaves out, on purpose

The full `yak` binary is 310 MB and ships an AI agent, gRPC engine, MITM CA,
plugin store and self-updater. Testing found unsafe defaults in several of
these. yaklite links none of them:

| Full yak | yaklite |
| --- | --- |
| Resets umask to 0, so files and the CA key end up world-readable or world-writable | Leaves your umask alone. State dir is `0700`, files are `0600` |
| Creates `~/yakit-projects` | Keeps yaklang's working files in `~/.local/state/yaklite/engine` (`0700`) |
| gRPC, MCP, AI gateway and reverse listeners, some on `0.0.0.0` | Opens no listening sockets except the optional dashboard, which is localhost-only unless you set a password. `yaklite mcp` talks over stdin/stdout only and is read-only |
| Self-update and plugin downloads with TLS verification off | Every download uses Go's default client with certificate checks. `yaklite update` only accepts GitHub hosts, verifies the SHA-256 and test-runs the new binary before swapping it in. No plugins. Plain `http://` is refused except to localhost |
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

### Recognising devices with rules

Rules in the inventory label devices yaklite cannot name on its own. The
label shows first on the dashboard and in alerts, and the `iot` check uses it.

```yaml
rules:
  - kind: Security camera
    vendor: Hikvision         # MAC maker contains this (any case)
  - kind: NAS
    ports: [5000, 5001]       # all of these are open
  - kind: Printer
    banner: "(?i)laserjet"    # a fingerprint or banner matches this regex
    hostname: printer         # optional, name contains this
```

### Alerts on your phone, email and chat

`--webhook` takes an `https://` URL (plain `http://` only to localhost) or an
email address. Several destinations can be given, comma separated. The
body is picked from the URL, or set it with `--webhook-format`:

| Service | Example URL | Format |
| --- | --- | --- |
| ntfy | `https://ntfy.sh/your-topic` | text with title, priority and tags headers |
| Discord | `https://discord.com/api/webhooks/<id>/<token>` | `content` |
| Telegram | `https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>` | `text` |
| Slack, Mattermost | `https://hooks.slack.com/services/...` | `text` |
| Gotify | `https://gotify.example/message?token=<APP_TOKEN>` | title, message, priority |
| Pushover | `https://api.pushover.net/1/messages.json?token=APP&user=USER` | title, message, priority |
| Home Assistant | `https://homeassistant.local:8123/api/webhook/<ID>` | `json` |
| Email | `smtps://you@smtp.example.com:465/you@example.com` or `smtp://...:587/...` (STARTTLS) | plain text |
| Anything else | your own endpoint | `{"text": "...", "changes": [...]}` (`json`) |

Priorities follow the worst severity in the batch, so a phone can ring for
`high` and stay quiet for `low`. Webhook URLs contain secrets, so keep them in
a root-owned unit file or environment file rather than shell history. The
email password is never part of the URL: put it in `YAKLITE_SMTP_PASSWORD` or
`~/.config/yaklite/smtp-password` (`chmod 600`). Email must use TLS.

**Phone buttons (ntfy).** ntfy alerts carry three buttons: *Acknowledge*,
*Snooze 1 week* and *Check again*. A press posts a signed message to
`<your-topic>-actions`, which yaklite reads on its next run. The signature
uses a secret in `~/.config/yaklite/action-secret`, so someone who knows the
topic name cannot acknowledge alerts for you. Use a long, unguessable topic
name all the same, because anyone who knows it can read your alerts.

### Acknowledging and snoozing

Each alert has a key. Acknowledging it stops that alert repeating; anything
new still alerts.

```sh
yaklite alerts --since 7d                     # recent alerts with their keys
yaklite ack port_open:192.168.1.10:tcp/23     # for good
yaklite ack upnp:enabled --for 1w             # snooze (h, d, w, or forever)
```

The dashboard has the same buttons on each problem, and a box to name a
device.

### Weekly summary and device history

`yaklite summary` prints a short report of the last week: devices, new ones,
open problems and the worst alerts. `install` sends it every Monday at 9:00
to the same destinations as the alerts (`summary --send` does it by hand).
`yaklite history` lists every device ever seen, with first and last seen
times.

## Dashboard and Prometheus metrics

`yaklite serve` shows a web page with each watched network's devices, open
ports, certificate status, open problems and recent changes, plus a
Prometheus `/metrics` endpoint and a small JSON summary at `/api/summary`. It reads the state directory on every
request, so it works next to a systemd timer that runs `watch --once`.
`watch --listen ADDR` serves the same thing from a long-running watch.

```sh
./yaklite serve --inventory home.yaml                # http://127.0.0.1:9842/
YAKLITE_WEB_PASSWORD=change-me ./yaklite serve --listen 0.0.0.0:9842
```

It listens on localhost only by default. Any other address is refused unless
`YAKLITE_WEB_PASSWORD` is set, because the page is a map of your network; the
browser or Prometheus then logs in with HTTP basic auth (any user name). The
page runs no JavaScript and sets a strict Content-Security-Policy. Its only
forms (acknowledge, snooze, name a device) need a per-run token, a same-site
`Origin` and, without a password, a localhost `Host` header, so other web
sites and DNS rebinding cannot use them.

Metrics:

| Metric | Meaning |
| --- | --- |
| `yaklite_hosts`, `yaklite_open_ports` | Totals in the last snapshot, per `watch` |
| `yaklite_host_open_ports{host,name}` | Open ports per device |
| `yaklite_host_missed_scans{host,name}` | Scans in a row a known device did not answer |
| `yaklite_service_info{host,port,service,product,version,verified}` | One series per open port |
| `yaklite_tls_cert_expiry_timestamp_seconds{host,port,subject}` | When each certificate expires |
| `yaklite_changes_total{kind,severity}` | Counter of logged changes |
| `yaklite_findings{watch,severity}` | Open problems from the safety checks |
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

## This computer's connections

`yaklite conns` lists this computer's internet connections with the program,
the remote address's owner (network operator) and country, using an IP table
built into the binary, so no lookup leaves the machine. Connections to
addresses on public lists of known attackers are marked.

`yaklite connwatch` checks the same every 30 seconds and alerts on:

| Alert | Severity |
| --- | --- |
| Someone on the internet connected **in** to this computer | high |
| A connection to or from an address on a known-attackers list | high |
| The first connection to a country not seen before (after 7 days of learning) | low (`--new-country-severity`) |

The known-attacker lists are abuse.ch Feodo Tracker, Spamhaus DROP, DShield,
blocklist.de and CINS Army. They are downloaded at most every 12 hours
(`--no-threat-lists` to skip). `install` runs `connwatch` in the background
on macOS and Linux.

## Safety checks

`yaklite check` runs these once and prints what it finds; `install` and
`watch --checks` run them on every scan and alert when something new shows
up. `--only` picks some, `--list` shows them all.

| Check | Looks for |
| --- | --- |
| `self` | This computer: firewall off, stealth mode, FileVault or disk encryption, SIP, Gatekeeper, automatic updates, guest account, SSH password logins, file or screen sharing listening on the network (Windows: firewall, Defender, drive encryption, UAC, Remote Desktop) |
| `host` | Changes inside this computer since the first check: new startup programs (launch agents, login items, system extensions, cron, systemd, Run keys), newly trusted root certificates, a proxy or DNS server set behind your back, new configuration profiles or device management, new user or admin accounts, and many failed logins from one address. The first check asks you to look over what is already there; `yaklite check --accept` records the current state as normal |
| `routeradmin` | Whether the router's admin page can be reached from the internet, and whether it only offers it unencrypted (trusted networks) |
| `router` | With the router's admin login (`yaklite router setup`): its device list, log and settings. See [Router login](#router-login) |
| `upnp` | Ports the router forwards from the internet through UPnP, and whether UPnP is on at all (trusted networks) |
| `exposure` | What internet scanners recorded about your public address: open ports and known flaws, from Shodan InternetDB (trusted networks) |
| `dns` | Whether this network tampers with name lookups: fake answers for missing names, answers that differ from DNS-over-HTTPS, the DNS server changing on a network you trust |
| `dhcp` | Which device hands out network settings, and a second one appearing |
| `wifi` | Open or WEP Wi-Fi, and a network with your Wi-Fi's name but a different router (a fake copy) |
| `kev` | Devices running software on CISA's list of flaws attackers are actively using |
| `tls` | Devices and sites still accepting TLS 1.0/1.1, or using RSA keys under 2048 bits |
| `ipv6` | Devices with public IPv6 addresses and risky ports open on them (trusted networks) |
| `iot` | Cameras, TVs and smart plugs on the same network as your computers (trusted networks) |
| `ids` | Alerts from Suricata, if it runs on this machine (`/var/log/suricata/eve.json` or `$YAKLITE_SURICATA_EVE`) |
| `conns` | As `connwatch` above, when run by hand, plus programs talking to the internet that are unsigned or run from odd places (Downloads, temporary folders) |

`yaklite outside` also checks each domain's email protection (SPF, DMARC),
when it expires, subdomains pointing at deleted cloud services (takeover
risk), certificates issued in the last 14 days, look-alike domains that
exist, whether the website forces HTTPS, and whether the domain is listed in
a data leak (see [Leaked passwords](#leaked-passwords)).

Every alert carries a **What to do** line with plain steps for that problem.

## Score, quiet hours and outages

```sh
yaklite score                    # a number out of 100, and the three things to fix first
yaklite quiet 22:00-07:00        # only high alerts at night; the rest arrive in the morning
yaklite quiet --group 10         # collect alerts for 10 minutes and send them as one message
yaklite quiet off
yaklite outages                  # when the internet was down
```

The score counts open problems (high costs 15 points, medium 6, low 2; any
high problem keeps it below 70). Acknowledged problems do not count. The
dashboard shows it with the top three and a button to mark each done.

The connection watch also notices internet outages (no answer from three
public DNS providers while still on Wi-Fi) and logs them; three in a day
raise an alert, and the weekly summary counts them.

## Router log

Most routers can send their log to another computer ("remote log", "syslog
server" or "remote logging" in the router's settings). Point it at the
computer running yaklite, UDP port 5514, then:

```sh
yaklite install --router-log     # or by hand: yaklite routerlog --notify
```

It alerts on repeated failed admin logins, a successful admin login from the
internet, new port forwards, settings changes, and floods of blocked
connections or blocked connections from known attackers. It only listens on
a network you trust, and only takes log lines from the router (`--from` adds
others).

## Router login

For OpenWrt, MikroTik (RouterOS 7), Fritz!Box and UniFi, yaklite can log in
to the router and read its device list, log and a few settings. It never
changes anything on the router.

```sh
yaklite router setup --type fritzbox          # or openwrt, mikrotik, unifi --user NAME
yaklite router test                           # what it can read
yaklite router forget
```

The password is asked once and kept in `~/.config/yaklite/router-password`
(owner-only). yaklite only uses it on the network where you set it up, and
for HTTPS routers it remembers the router's certificate and refuses to talk
if it changes. A separate read-only admin account is safer where the router
offers one. This was written against each router's documented API but not
yet tried on real hardware, so please report what `router test` says.

| Router | Device list | Log | Settings checked |
| --- | --- | --- | --- |
| OpenWrt | DHCP leases | system log | WAN firewall accepting connections, UPnP |
| MikroTik | DHCP leases | log | unencrypted admin services open to all, UPnP |
| Fritz!Box | all known devices | event log | remote access from the internet |
| UniFi | connected clients | events | open alarms (including IPS alerts) |

New devices in the router's list raise a low alert (yaklite names it by its
MAC); the log goes through the same analysis as the router log above.

## Tripwire

```sh
yaklite install --tripwire       # or by hand: yaklite tripwire --notify
```

Opens a few ports that look like Telnet, file sharing, remote desktop and a
printer on this computer, on networks you trust. Nothing legitimate uses
them, so any device that tries is scanning your network: a hacked gadget, a
guest's infected laptop, or someone on your Wi-Fi. The automatic scan of this
computer leaves them out.

## Hardening this computer

```sh
sudo yaklite firewall install    # block known attackers in the OS firewall, refreshed every 12 hours
yaklite firewall status
sudo yaklite firewall uninstall
yaklite private-dns              # macOS: a profile for encrypted DNS (Quad9, Cloudflare or Mullvad)
sudo yaklite private-dns --apply # Linux: the same through systemd-resolved
```

The firewall lists are the same known-attacker lists as `connwatch` (pf on
macOS, nftables on Linux, Windows Firewall). Public DNS servers are never
blocked. Encrypted DNS stops the café Wi-Fi from seeing or changing your
name lookups; open the downloaded profile and install it in System Settings.

## Your phone and the family's computers

- **Phone:** with [Tailscale](https://tailscale.com) on the computer and the
  phone, `yaklite install --tailscale` also serves the dashboard on the
  computer's Tailscale address, with a password (printed once, kept in
  `~/.config/yaklite/web-password`). Nothing is opened to the internet.
- **Other computers:** on the computer that has the dashboard,
  `yaklite install --accept-reports` prints a token. On each other computer,
  `yaklite install --report-to http://192.168.1.10:9842 --report-token TOKEN`.
  Their own check results (settings, startup programs, certificates,
  connections) then show under "Other computers" on the dashboard. Each still
  alerts on its own. Plain `http://` is only allowed to an address on your
  home network or Tailscale.

## Leaked passwords

Through [Have I Been Pwned](https://haveibeenpwned.com):

```sh
yaklite password-check           # is this password in a known leak?
yaklite breaches -d example.com  # is anything at your domain in a leak?
```

`password-check` asks for the password without showing it and sends only the
first 5 characters of its SHA-1 hash, never the password; the answer covers
hundreds of hashes, so the service cannot tell which one was yours.

`outside -d` and `breaches` check, for free, whether the service on your
domain was itself breached. With an HIBP API key (paid, from
haveibeenpwned.com/API/Key) in `~/.config/yaklite/hibp-key` or
`$HIBP_API_KEY`, they also list every address at your domain found in a leak
(the domain must be verified in your HIBP account), and the personal
addresses you list one per line in `~/.config/yaklite/watch-emails`. Leaks
that include passwords are high alerts, with which password to change.

## Windows

Windows builds are paused for now, so the release has no Windows download.
The Windows support stays in the code: building it needs MinGW and cgo
(`GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build ./cmd/yaklite`).
On Windows, `install` copies it to `%LOCALAPPDATA%\yaklite\` and registers hidden
Task Scheduler jobs for your user (no admin rights), shows problems as
Windows notifications, and runs the Windows safety checks above. Windows
Defender SmartScreen may warn on the first run because the build is
unsigned; choose "More info", then "Run anyway".

## Traffic box

`contrib/trafficbox/` sets up a small always-on computer (a Raspberry Pi is
enough) running Suricata, a free intrusion detection system, next to
`yaklite traffic`, which turns Suricata's alerts into plain alerts with what
to do. It needs to see the network's traffic, usually through a cheap switch
with port mirroring; its README explains the options.

## Blocking through AdGuard Home or Pi-hole

```sh
yaklite block site evil.example     # AdGuard Home or Pi-hole v6
yaklite block device 192.168.1.66   # AdGuard Home only: stops its name lookups
yaklite unblock site evil.example
```

Set it up once in `~/.config/yaklite/blocker.yaml` (`type: adguard` or
`pihole`, `url:`, and `user:` for AdGuard) with the admin password in
`~/.config/yaklite/blocker-password` (`chmod 600`).

## Asking Claude about your network

`yaklite mcp` is a read-only Model Context Protocol server over stdin/stdout.
It lets Claude Desktop or Claude Code read the summary, alerts, open
problems, devices and current connections. It cannot scan, change settings
or acknowledge anything.

```sh
claude mcp add yaklite -- ~/Library/Application\ Support/yaklite/yaklite mcp
```

## Menu bar, Docker and Raspberry Pi

- `contrib/swiftbar/yaklite.1m.sh` is a menu bar shield for SwiftBar or xbar.
  It reads the local dashboard and shows the worst open problem.
- `contrib/docker/compose.yaml` runs `watch --checks` on a Linux box or
  Raspberry Pi with host networking (edit the network first). The release
  has `yaklite-linux-arm64` for a Pi without Docker.

## What yaklite connects to

Scans and checks go to your own network. Beyond that, these are the only
outside services it talks to, and each can be turned off:

| Service | Why | Off switch |
| --- | --- | --- |
| abuse.ch, Spamhaus, DShield, blocklist.de, CINS Army | Known-attacker lists, at most every 12 h | `--no-threat-lists` |
| CISA (`cisa.gov`) | The actively-exploited flaws list, daily | `check --only` without `kev` |
| api.ipify.org | Your public IP, when the router does not say | `check --no-public-lookup` |
| Shodan InternetDB | What scanners recorded about your public IP | `check --no-public-lookup` |
| Cloudflare DNS-over-HTTPS | Comparing DNS answers | `check --only` without `dns` |
| rdap.org, crt.sh, certspotter | Domain expiry and new certificates (`outside` only) | `--no-rdap`, `--no-ct` |
| haveibeenpwned.com | Whether your domain (and, with a key, its addresses) is in a data leak (`outside`, `breaches`) | `--no-hibp` |
| api.pwnedpasswords.com | The first 5 characters of a password's hash, only when you run `password-check` | do not run it |
| Your router | Its device list, log and settings, only after `yaklite router setup` | `yaklite router forget` |
| Your other computers' dashboard | This computer's check results, only with `--report-to` | `install` without it |
| Your alert destinations, and `<topic>-actions` on ntfy | Alerts and phone buttons | leave `--webhook` out |
| GitHub | `yaklite update`, only when you run it | do not run it |

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
