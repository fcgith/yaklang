package main

import (
	"bufio"

	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// sock is one TCP socket on this machine, as the OS reports it. Reading
// these needs no admin rights; process names are only known for your own
// processes unless yaklite runs as root.
type sock struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      string // LISTEN, ESTABLISHED, ...
	Process    string
	PID        int
}

func (s sock) key() string {
	return fmt.Sprintf("%s|%d|%s|%d", s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort)
}

func listSockets(ctx context.Context) ([]sock, error) {
	switch runtime.GOOS {
	case "linux":
		var out []sock
		for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			out = append(out, parseProcNetTCP(string(data))...)
		}
		if out == nil {
			return nil, fmt.Errorf("cannot read /proc/net/tcp")
		}
		procs := linuxSocketOwners()
		for i := range out {
			if p, ok := procs[out[i].inode()]; ok {
				out[i].PID, out[i].Process = p.pid, p.name
			}
		}
		return out, nil
	case "darwin", "freebsd":
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		data, err := exec.CommandContext(cctx, "netstat", "-an", "-p", "tcp").Output()
		if err != nil {
			return nil, fmt.Errorf("netstat: %w", err)
		}
		out := parseBSDNetstat(string(data))
		if lsof, err := exec.CommandContext(cctx, "lsof", "-nP", "-iTCP", "-FpcnT").Output(); err == nil {
			owners := parseLsof(string(lsof))
			for i := range out {
				if p, ok := owners[out[i].key()]; ok {
					out[i].PID, out[i].Process = p.pid, p.name
				}
			}
		}
		return out, nil
	case "windows":
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		data, err := exec.CommandContext(cctx, "netstat", "-ano", "-p", "TCP").Output()
		if err != nil {
			return nil, fmt.Errorf("netstat: %w", err)
		}
		out := parseWindowsNetstat(string(data))
		if data6, err := exec.CommandContext(cctx, "netstat", "-ano", "-p", "TCPv6").Output(); err == nil {
			out = append(out, parseWindowsNetstat(string(data6))...)
		}
		if tl, err := exec.CommandContext(cctx, "tasklist", "/fo", "csv", "/nh").Output(); err == nil {
			names := parseTasklist(string(tl))
			for i := range out {
				out[i].Process = names[out[i].PID]
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("listing connections is not supported on %s", runtime.GOOS)
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// inodes are kept in the process field until owners are resolved
func (s sock) inode() string {
	if strings.HasPrefix(s.Process, "inode:") {
		return strings.TrimPrefix(s.Process, "inode:")
	}
	return ""
}

func parseProcNetTCP(data string) []sock {
	var out []sock
	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		lip, lport, ok1 := parseHexAddr(f[1])
		rip, rport, ok2 := parseHexAddr(f[2])
		if !ok1 || !ok2 {
			continue
		}
		st := tcpStates[strings.ToUpper(f[3])]
		if st == "" {
			st = f[3]
		}
		out = append(out, sock{LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport, State: st, Process: "inode:" + f[9]})
	}
	return out
}

// parseHexAddr decodes /proc/net/tcp addresses: the IP is stored as host-order
// 32-bit words (little endian on every platform Linux runs this on).
func parseHexAddr(s string) (net.IP, int, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, 0, false
	}
	ip := make(net.IP, len(b))
	for i := 0; i < len(b); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(b[i:]))
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // v4-mapped IPv6
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	return ip, int(port), true
}

type procRef struct {
	pid  int
	name string
}

func linuxSocketOwners() map[string]procRef {
	out := map[string]procRef{}
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, pd := range pids {
		pid, err := strconv.Atoi(filepath.Base(pd))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(pd, "fd"))
		if err != nil {
			continue // not ours
		}
		var name string
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(pd, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			if name == "" {
				c, _ := os.ReadFile(filepath.Join(pd, "comm"))
				name = strings.TrimSpace(string(c))
			}
			out[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = procRef{pid, name}
		}
	}
	return out
}

// parseBSDNetstat reads `netstat -an -p tcp` on macOS, where addresses look
// like 192.168.1.5.52345, fe80::1%lo0.1024 or *.22.
func parseBSDNetstat(data string) []sock {
	var out []sock
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") {
			continue
		}
		lip, lport, ok1 := splitBSDAddr(f[3])
		rip, rport, ok2 := splitBSDAddr(f[4])
		if !ok1 || !ok2 {
			continue
		}
		out = append(out, sock{LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport, State: f[5]})
	}
	return out
}

func splitBSDAddr(s string) (net.IP, int, bool) {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return nil, 0, false
	}
	host, port := s[:i], s[i+1:]
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	p := 0
	if port != "*" {
		v, err := strconv.Atoi(port)
		if err != nil {
			return nil, 0, false
		}
		p = v
	}
	if host == "*" {
		return net.IPv4zero, p, true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, p, true
}

// parseLsof reads `lsof -nP -iTCP -FpcnT` output into socket owners keyed
// like sock.key().
func parseLsof(data string) map[string]procRef {
	out := map[string]procRef{}
	var cur procRef
	for _, line := range strings.Split(data, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			cur = procRef{}
			cur.pid, _ = strconv.Atoi(line[1:])
		case 'c':
			cur.name = line[1:]
		case 'n':
			l, r, _ := strings.Cut(line[1:], "->")
			lip, lport, ok := splitLsofAddr(l)
			if !ok {
				continue
			}
			s := sock{LocalIP: lip, LocalPort: lport, RemoteIP: net.IPv4zero}
			if r != "" {
				rip, rport, ok := splitLsofAddr(r)
				if !ok {
					continue
				}
				s.RemoteIP, s.RemotePort = rip, rport
			}
			out[s.key()] = cur
		}
	}
	return out
}

// lsof prints 192.168.1.5:52345, [fe80::1]:22 or *:22
func splitLsofAddr(s string) (net.IP, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return nil, 0, false
	}
	host := strings.Trim(s[:i], "[]")
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return nil, 0, false
	}
	if host == "*" {
		return net.IPv4zero, p, true
	}
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, p, true
}

var windowsStates = map[string]string{"LISTENING": "LISTEN", "SYN_RECEIVED": "SYN_RECV"}

// parseWindowsNetstat reads `netstat -ano -p TCP`:
//
//	TCP    192.168.1.5:50000      1.2.3.4:443      ESTABLISHED     1234
func parseWindowsNetstat(data string) []sock {
	var out []sock
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) != 5 || f[0] != "TCP" {
			continue
		}
		lip, lport, ok1 := splitHostPortIP(f[1])
		rip, rport, ok2 := splitHostPortIP(f[2])
		pid, err := strconv.Atoi(f[4])
		if !ok1 || !ok2 || err != nil {
			continue
		}
		st := f[3]
		if w, ok := windowsStates[st]; ok {
			st = w
		}
		out = append(out, sock{LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport, State: st, PID: pid})
	}
	return out
}

func splitHostPortIP(s string) (net.IP, int, bool) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, false
	}
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	ip := net.ParseIP(h)
	port, err := strconv.Atoi(p)
	if ip == nil || err != nil {
		return nil, 0, false
	}
	return ip, port, true
}

// parseTasklist reads `tasklist /fo csv /nh`: "name.exe","1234","Console",...
func parseTasklist(data string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Split(strings.TrimSpace(line), `","`)
		if len(f) < 2 {
			continue
		}
		if pid, err := strconv.Atoi(strings.Trim(f[1], `"`)); err == nil {
			out[pid] = strings.Trim(f[0], `"`)
		}
	}
	return out
}
