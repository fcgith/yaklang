# yaklite

A small LAN inventory and change-monitoring tool built from the parts of
yaklang that held up in testing: the port scanner (connect and SYN) and the
service fingerprinter (nmap-derived probes plus ~11.8k web/CPE rules).

It answers two questions for a network you own:

- **What is on my network right now?** `yaklite scan`
- **What changed since last time?** `yaklite watch` / `yaklite diff`

Only scan networks you own or are authorised to test.

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

Binary size: about 58 MB (stripped) against 310 MB.

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
```

`-p` accepts `top` (default, ~80 ports common on home and office networks:
SSH, web, SMB, RDP, VNC, printers, NAS, MQTT, Home Assistant, Plex, Jellyfin,
Docker, Kubernetes, databases, WireGuard), `all`, or a list such as
`22,80,8000-8100`.

Fingerprints that come only from the port number are shown as
`(unconfirmed)` and are never reported as a service change, so a flaky probe
does not raise an alert.

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
