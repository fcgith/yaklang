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

var webhookFormats = []string{"auto", "json", "slack", "discord", "telegram", "gotify", "ntfy", "pushover"}

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
	case host == "api.pushover.net":
		return "pushover"
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
		if c.Fix != "" && sevRank[c.Severity] >= sevRank[sevMedium] {
			b.WriteString("  What to do: " + c.Fix + "\n")
		}
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
	return buildWebhookText(format, changes, title, text)
}

func truncText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…"
	}
	return s
}

func buildWebhookText(format string, changes []Change, title, text string) ([]byte, string, map[string]string) {
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
	title, text := summaryText(changes)
	return postBody(ctx, rawURL, format, changes, title, text)
}

// postText sends a plain message, such as the weekly summary.
func postText(ctx context.Context, rawURL, title, text string) error {
	format := detectFormat(rawURL)
	return postBody(ctx, rawURL, format, []Change{{Severity: sevInfo, Kind: "summary", After: title}}, title, text)
}

func postBody(ctx context.Context, rawURL, format string, changes []Change, title, text string) error {
	if format == "" || format == "auto" {
		format = detectFormat(rawURL)
	}
	body, ctype, headers := buildWebhookText(format, changes, title, text)
	if format == "pushover" {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		q := u.Query()
		q.Set("title", title)
		q.Set("message", truncText(text, 1000))
		q.Set("priority", map[string]string{sevInfo: "-1", sevLow: "0", sevMedium: "0", sevHigh: "1"}[worstSeverity(changes)])
		u.RawQuery = ""
		rawURL = u.String()
		body, ctype, headers = []byte(q.Encode()), "application/x-www-form-urlencoded", nil
	}
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
	if format == "ntfy" && changes[0].Kind != "summary" {
		if a := ntfyActions(rawURL, changes); a != "" {
			req.Header.Set("Actions", a)
		}
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
