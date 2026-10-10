package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// `yaklite mcp` lets Claude (desktop app or Claude Code) read yaklite's
// results and answer questions like "what changed this week?". It speaks
// the Model Context Protocol over stdin/stdout, so it is only reachable by
// the app that started it, and every tool is read-only.
//
//	claude mcp add yaklite -- ~/Library/Application\ Support/yaklite/yaklite mcp

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	run         func(ctx context.Context, args map[string]any) (string, error)
}

func mcpTools(stateDir string) []mcpTool {
	obj := func(props map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": props}
	}
	return []mcpTool{
		{Name: "network_summary", Description: "Summary of everything yaklite watches: networks, device counts, alerts in a period and problems still to fix.",
			InputSchema: obj(map[string]any{"days": map[string]any{"type": "integer", "description": "period in days (default 7)"}}),
			run: func(ctx context.Context, a map[string]any) (string, error) {
				states, err := (&stateReader{dir: stateDir, invFromConfig: true}).load()
				if err != nil {
					return "", err
				}
				nf, _ := loadNetworks()
				t, b := buildSummary(states, nf, loadAcks(), time.Now(), time.Duration(intArg(a, "days", 7))*24*time.Hour)
				return t + "\n\n" + b, nil
			}},
		{Name: "list_alerts", Description: "Alerts (changes) recorded in a period, newest last, with the key used to acknowledge each.",
			InputSchema: obj(map[string]any{"days": map[string]any{"type": "integer"}, "min_severity": map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high"}}}),
			run: func(ctx context.Context, a map[string]any) (string, error) {
				min := sevLow
				if s, ok := a["min_severity"].(string); ok {
					if v, err := parseSeverity(s); err == nil {
						min = v
					}
				}
				states, err := (&stateReader{dir: stateDir, invFromConfig: true}).load()
				if err != nil {
					return "", err
				}
				cut := time.Now().Add(-time.Duration(intArg(a, "days", 7)) * 24 * time.Hour)
				var lines []string
				for _, st := range states {
					for _, c := range st.Changes {
						if c.Time.After(cut) && sevRank[c.Severity] >= sevRank[min] {
							lines = append(lines, c.Time.Local().Format("2006-01-02 15:04")+"  ["+st.Name+"] "+c.String()+"  key="+c.Key())
						}
					}
				}
				sort.Strings(lines)
				if len(lines) > 300 {
					lines = lines[len(lines)-300:]
				}
				return orNone(strings.Join(lines, "\n")), nil
			}},
		{Name: "list_problems", Description: "Standing problems found by yaklite's checks (router port forwards, firewall off, DNS tampering, connections from the internet, ...), with how to fix each.",
			InputSchema: obj(map[string]any{}),
			run: func(ctx context.Context, a map[string]any) (string, error) {
				states, err := (&stateReader{dir: stateDir}).load()
				if err != nil {
					return "", err
				}
				acks := loadAcks()
				var b strings.Builder
				for _, st := range states {
					for _, f := range st.Snap.Findings {
						ack := ""
						if acks.matches(f.ID, time.Now()) {
							ack = " (acknowledged by the user)"
						}
						fmt.Fprintf(&b, "[%s] %s: %s%s\n  detail: %s\n  fix: %s\n  id: %s\n", st.Name, strings.ToUpper(f.Severity), f.Title, ack, f.Detail, f.Fix, f.ID)
					}
				}
				return orNone(b.String()), nil
			}},
		{Name: "list_devices", Description: "Devices seen on each watched network, with first and last time seen, IP, MAC, maker and open ports.",
			InputSchema: obj(map[string]any{}),
			run: func(ctx context.Context, a map[string]any) (string, error) {
				h := loadHistory(stateDir)
				data, err := json.MarshalIndent(h, "", " ")
				return string(data), err
			}},
		{Name: "current_connections", Description: "This computer's current internet connections, with owner and country of each remote address and whether it is on a public blocklist.",
			InputSchema: obj(map[string]any{}),
			run: func(ctx context.Context, a map[string]any) (string, error) {
				socks, err := listSockets(ctx)
				if err != nil {
					return "", err
				}
				threats, _ := loadThreats(ctx, stateDir, false)
				var b strings.Builder
				for _, v := range classify(socks, threats) {
					dir := "out"
					if v.Inbound {
						dir = "IN"
					}
					fmt.Fprintf(&b, "%s %s:%d local port %d %s %s %s\n", dir, v.RemoteIP, v.RemotePort, v.LocalPort, v.proc(), v.Owner.String(), v.Threat)
				}
				return orNone(b.String()), nil
			}},
	}
}

func intArg(a map[string]any, k string, def int) int {
	if v, ok := a[k].(float64); ok && v > 0 && v < 3650 {
		return int(v)
	}
	return def
}

func cmdMCP(ctx context.Context, args []string) error {
	return serveMCP(ctx, os.Stdin, os.Stdout, defaultStateDir())
}

func serveMCP(ctx context.Context, in io.Reader, out io.Writer, stateDir string) error {
	tools := mcpTools(stateDir)
	enc := json.NewEncoder(out)
	reply := func(id json.RawMessage, result any, rpcErr map[string]any) {
		m := map[string]any{"jsonrpc": "2.0", "id": id}
		if rpcErr != nil {
			m["error"] = rpcErr
		} else {
			m["result"] = result
		}
		enc.Encode(m)
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m rpcMsg
		if err := json.Unmarshal(line, &m); err != nil {
			reply(json.RawMessage("null"), nil, map[string]any{"code": -32700, "message": "parse error"})
			continue
		}
		if len(m.ID) == 0 {
			continue // a notification
		}
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			json.Unmarshal(m.Params, &p)
			if p.ProtocolVersion == "" {
				p.ProtocolVersion = "2025-06-18"
			}
			reply(m.ID, map[string]any{
				"protocolVersion": p.ProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "yaklite", "version": version},
				"instructions":    "Read-only access to yaklite's home network monitoring: alerts, problems found, devices and this computer's connections.",
			}, nil)
		case "ping":
			reply(m.ID, map[string]any{}, nil)
		case "tools/list":
			reply(m.ID, map[string]any{"tools": tools}, nil)
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			json.Unmarshal(m.Params, &p)
			var tool *mcpTool
			for i := range tools {
				if tools[i].Name == p.Name {
					tool = &tools[i]
				}
			}
			if tool == nil {
				reply(m.ID, nil, map[string]any{"code": -32602, "message": "unknown tool " + p.Name})
				continue
			}
			text, err := tool.run(ctx, p.Arguments)
			if err != nil {
				reply(m.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": "error: " + err.Error()}}, "isError": true}, nil)
				continue
			}
			reply(m.ID, map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}, nil)
		default:
			reply(m.ID, nil, map[string]any{"code": -32601, "message": "method not found"})
		}
	}
	return sc.Err()
}
