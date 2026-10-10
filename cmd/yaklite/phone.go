package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Phone buttons for ntfy alerts. Each ntfy notification gets an
// "I know about this" and a "Snooze 1 week" button. Pressing one makes the
// ntfy app post a short signed message to a second topic (yours plus
// "-actions"); yaklite reads that topic on its next run and records the
// acknowledgement. Nothing has to listen for connections from the internet.
// The signature uses a secret kept in the config directory, so someone who
// guesses the topic name cannot silence your alerts.

func actionTopicURL(webhook string) string {
	u, err := url.Parse(webhook)
	if err != nil {
		return ""
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "-actions"
	u.RawQuery = ""
	return u.String()
}

func actionSecret() []byte {
	p := filepath.Join(configDir(), "action-secret")
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b
	}
	b := make([]byte, 32)
	rand.Read(b)
	b = []byte(hex.EncodeToString(b))
	writeFilePrivate(p, b)
	return b
}

func signAction(secret []byte, msg string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))[:24]
}

// ntfyActions builds the ntfy "Actions" header for a batch of changes.
func ntfyActions(webhook string, changes []Change) string {
	target := actionTopicURL(webhook)
	if target == "" {
		return ""
	}
	var keys []string
	for _, c := range changes {
		if k := c.Key(); !contains(keys, k) && !strings.ContainsAny(k, " ;,") {
			keys = append(keys, k)
		}
		if len(keys) == 8 {
			break
		}
	}
	if len(keys) == 0 {
		return ""
	}
	secret := actionSecret()
	body := func(verb string) string {
		msg := verb + " " + strings.Join(keys, " ")
		return msg + " sig=" + signAction(secret, msg)
	}
	label := "I know about this"
	if len(keys) > 1 {
		label = "I know about these"
	}
	return fmt.Sprintf("http, %s, %s, method=POST, body=%s, clear=true; http, Snooze 1 week, %s, method=POST, body=%s, clear=true; http, Check again, %s, method=POST, body=%s",
		label, target, body("ack"), target, body("snooze"), target, body("scan"))
}

// pollPhoneActions applies button presses posted since the last poll.
// It returns true when a check was asked for.
func pollPhoneActions(ctx context.Context, webhook, stateDir string) bool {
	if webhook == "" || detectFormat(webhook) != "ntfy" {
		return false
	}
	target := actionTopicURL(webhook)
	sincePath := filepath.Join(stateDir, ".actions-since")
	since := "12h"
	if b, err := os.ReadFile(sincePath); err == nil {
		since = strings.TrimSpace(string(b))
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+"/json?poll=1&since="+url.QueryEscape(since), nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	secret := actionSecret()
	last := since
	scanAsked := false
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var m struct {
			ID      string `json:"id"`
			Time    int64  `json:"time"`
			Event   string `json:"event"`
			Message string `json:"message"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Event != "message" {
			continue
		}
		last = m.ID
		verb, keys, ok := verifyAction(secret, m.Message)
		if !ok {
			continue
		}
		switch verb {
		case "ack":
			for _, k := range keys {
				addAck(k, 0, "from phone")
			}
		case "snooze":
			for _, k := range keys {
				addAck(k, 7*24*time.Hour, "from phone")
			}
		case "scan":
			scanAsked = true
		}
	}
	if last != since {
		writeFilePrivate(sincePath, []byte(last))
	}
	return scanAsked
}

func verifyAction(secret []byte, msg string) (verb string, keys []string, ok bool) {
	i := strings.LastIndex(msg, " sig=")
	if i < 0 {
		return "", nil, false
	}
	body, sig := msg[:i], msg[i+5:]
	if !hmac.Equal([]byte(sig), []byte(signAction(secret, body))) {
		return "", nil, false
	}
	f := strings.Fields(body)
	if len(f) == 0 {
		return "", nil, false
	}
	return f[0], f[1:], true
}

// kickAuto starts the installed background check now.
func kickAuto() {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("launchctl", "kickstart", "gui/"+strconv.Itoa(os.Getuid())+"/"+agentLabel).Run()
	case "linux":
		exec.Command("systemctl", "--user", "start", "--no-block", "yaklite-auto.service").Run()
	}
}
