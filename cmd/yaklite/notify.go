package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var webhookFormats = []string{"auto", "json", "slack", "discord", "telegram", "gotify", "ntfy"}

// detectFormat picks a webhook body format from the URL when the user did not
// choose one.
func detectFormat(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "json"
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "discord.com" || host == "discordapp.com" || strings.HasSuffix(host, ".discord.com"):
		return "discord"
	case host == "api.telegram.org":
		return "telegram"
	case host == "hooks.slack.com":
		return "slack"
	case host == "ntfy.sh" || strings.HasPrefix(host, "ntfy."):
		return "ntfy"
	case strings.HasSuffix(u.Path, "/message") && u.Query().Get("token") != "":
		return "gotify"
	}
	return "json"
}

func summaryText(changes []Change) (title, body string) {
	worst := sevInfo
	for _, c := range changes {
		if sevRank[c.Severity] > sevRank[worst] {
			worst = c.Severity
		}
	}
	title = fmt.Sprintf("yaklite: %d network change(s), worst %s", len(changes), worst)
	var b strings.Builder
	for _, c := range changes {
		b.WriteString(c.String() + "\n")
	}
	return title, b.String()
}

func worstSeverity(changes []Change) string {
	worst := sevInfo
	for _, c := range changes {
		if sevRank[c.Severity] > sevRank[worst] {
			worst = c.Severity
		}
	}
	return worst
}

// buildWebhook returns the request body and content type for a format.
func buildWebhook(format string, changes []Change) ([]byte, string, map[string]string) {
	title, text := summaryText(changes)
	worst := worstSeverity(changes)
	switch format {
	case "slack":
		b, _ := json.Marshal(map[string]any{"text": title + "\n" + text})
		return b, "application/json", nil
	case "discord":
		msg := title + "\n" + text
		if len(msg) > 1900 { // Discord rejects content over 2000 characters
			msg = msg[:1900] + "\n…"
		}
		b, _ := json.Marshal(map[string]any{"content": msg})
		return b, "application/json", nil
	case "telegram":
		msg := title + "\n" + text
		if len(msg) > 4000 {
			msg = msg[:4000] + "\n…"
		}
		// the chat_id goes in the URL: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>
		b, _ := json.Marshal(map[string]any{"text": msg})
		return b, "application/json", nil
	case "gotify":
		prio := map[string]int{sevInfo: 2, sevLow: 4, sevMedium: 6, sevHigh: 8}[worst]
		b, _ := json.Marshal(map[string]any{"title": title, "message": text, "priority": prio})
		return b, "application/json", nil
	case "ntfy":
		prio := map[string]string{sevInfo: "2", sevLow: "3", sevMedium: "4", sevHigh: "5"}[worst]
		return []byte(text), "text/plain; charset=utf-8", map[string]string{"Title": title, "Priority": prio, "Tags": "satellite"}
	}
	b, _ := json.Marshal(map[string]any{"text": title + "\n" + text, "changes": changes})
	return b, "application/json", nil
}

func postWebhook(ctx context.Context, rawURL, format string, changes []Change) error {
	if format == "" || format == "auto" {
		format = detectFormat(rawURL)
	}
	body, ctype, headers := buildWebhook(format, changes)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// default client: system CA store, certificate verification on
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
