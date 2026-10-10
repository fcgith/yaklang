package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Blocking, through a DNS filter you already run. yaklite itself cannot
// block anything; AdGuard Home and Pi-hole can stop a device resolving names
// (which cuts off most of what it does) or stop everyone reaching a site.
//
// ~/.config/yaklite/blocker.yaml:
//
//	type: adguard            # or pihole (v6)
//	url: http://192.168.1.2:3000
//	user: admin              # AdGuard Home only
//	# the password goes in ~/.config/yaklite/blocker-password (owner-only)

type blockerConfig struct {
	Type string `yaml:"type"`
	URL  string `yaml:"url"`
	User string `yaml:"user,omitempty"`
}

func loadBlocker() (*blockerConfig, string, error) {
	data, err := os.ReadFile(filepath.Join(configDir(), "blocker.yaml"))
	if err != nil {
		return nil, "", errors.New("no blocker set up: create ~/.config/yaklite/blocker.yaml (see yaklite block --help)")
	}
	var c blockerConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, "", err
	}
	if c.Type != "adguard" && c.Type != "pihole" {
		return nil, "", errors.New("blocker.yaml: type must be adguard or pihole")
	}
	pw, _ := os.ReadFile(filepath.Join(configDir(), "blocker-password"))
	return &c, strings.TrimSpace(string(pw)), nil
}

func blockerDo(ctx context.Context, c *blockerConfig, pw, method, path string, body any, headers map[string]string, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.URL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Type == "adguard" {
		req.SetBasicAuth(c.User, pw)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%s %s: %s %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func cmdBlock(ctx context.Context, args []string, block bool) error {
	fs := flag.NewFlagSet("block", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: yaklite block device IP | yaklite block site DOMAIN   (and yaklite unblock ...)

Uses AdGuard Home or Pi-hole (v6). Set it up once:
  ~/.config/yaklite/blocker.yaml       type: adguard|pihole, url: http://..., user: (AdGuard only)
  ~/.config/yaklite/blocker-password   the admin password (chmod 600)
Blocking a device works with AdGuard Home only, and stops its name lookups.
`)
	}
	fs.Parse(args)
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}
	what, target := fs.Arg(0), strings.ToLower(strings.TrimSpace(fs.Arg(1)))
	c, pw, err := loadBlocker()
	if err != nil {
		return err
	}
	switch what {
	case "device":
		if net.ParseIP(target) == nil && normalizeMAC(target) == "" {
			return fmt.Errorf("%q is not an IP or MAC address", target)
		}
		if c.Type != "adguard" {
			return errors.New("blocking a device needs AdGuard Home; Pi-hole can only block sites here")
		}
		err = adguardClient(ctx, c, pw, target, block)
	case "site":
		if strings.ContainsAny(target, " /:") || !strings.Contains(target, ".") {
			return fmt.Errorf("%q is not a domain name", target)
		}
		if c.Type == "adguard" {
			err = adguardRule(ctx, c, pw, target, block)
		} else {
			err = piholeDomain(ctx, c, pw, target, block)
		}
	default:
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s %s %s via %s.\n", map[bool]string{true: "Blocked", false: "Unblocked"}[block], what, target, c.Type)
	return nil
}

func adguardClient(ctx context.Context, c *blockerConfig, pw, client string, block bool) error {
	var acc map[string]any
	if err := blockerDo(ctx, c, pw, http.MethodGet, "/control/access/list", nil, nil, &acc); err != nil {
		return err
	}
	var list []string
	if v, ok := acc["disallowed_clients"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok && s != client {
				list = append(list, s)
			}
		}
	}
	if block {
		list = append(list, client)
	}
	acc["disallowed_clients"] = list
	return blockerDo(ctx, c, pw, http.MethodPost, "/control/access/set", acc, nil, nil)
}

func adguardRule(ctx context.Context, c *blockerConfig, pw, domain string, block bool) error {
	var st struct {
		UserRules []string `json:"user_rules"`
	}
	if err := blockerDo(ctx, c, pw, http.MethodGet, "/control/filtering/status", nil, nil, &st); err != nil {
		return err
	}
	rule := "||" + domain + "^"
	var rules []string
	for _, r := range st.UserRules {
		if r != rule {
			rules = append(rules, r)
		}
	}
	if block {
		rules = append(rules, rule)
	}
	return blockerDo(ctx, c, pw, http.MethodPost, "/control/filtering/set_rules", map[string]any{"rules": rules}, nil, nil)
}

func piholeDomain(ctx context.Context, c *blockerConfig, pw, domain string, block bool) error {
	var auth struct {
		Session struct {
			SID string `json:"sid"`
		} `json:"session"`
	}
	if err := blockerDo(ctx, c, pw, http.MethodPost, "/api/auth", map[string]string{"password": pw}, nil, &auth); err != nil {
		return err
	}
	h := map[string]string{"X-FTL-SID": auth.Session.SID}
	defer blockerDo(ctx, c, pw, http.MethodDelete, "/api/auth", nil, h, nil)
	if block {
		return blockerDo(ctx, c, pw, http.MethodPost, "/api/domains/deny/exact", map[string]any{"domain": domain, "comment": "blocked by yaklite"}, h, nil)
	}
	return blockerDo(ctx, c, pw, http.MethodDelete, "/api/domains/deny/exact/"+domain, nil, h, nil)
}
