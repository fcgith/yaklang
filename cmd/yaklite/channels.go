package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Alerts can go to several places at once: --webhook takes a comma
// separated list. Besides the chat and push services in notify.go:
//
//	smtps://user@smtp.example.com:465/you@example.com   email (password in YAKLITE_SMTP_PASSWORD or ~/.config/yaklite/smtp-password)
//	smtp://user@smtp.example.com:587/you@example.com    email with STARTTLS
//	https://api.pushover.net/1/messages.json?token=APP&user=USER
//	https://homeassistant.local:8123/api/webhook/ID     (any JSON webhook)

func splitWebhooks(s string) []string {
	var out []string
	for _, u := range strings.Split(s, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

func validateWebhooks(s string) error {
	for _, u := range splitWebhooks(s) {
		switch {
		case strings.HasPrefix(u, "smtp://"), strings.HasPrefix(u, "smtps://"):
			if _, err := parseSMTP(u); err != nil {
				return err
			}
		case strings.HasPrefix(u, "https://"), strings.HasPrefix(u, "http://127.0.0.1"), strings.HasPrefix(u, "http://localhost"):
		default:
			return fmt.Errorf("alert destination %q must use https:// (plain http is only allowed to localhost) or smtp(s):// for email", u)
		}
	}
	return nil
}

// sendAlerts delivers changes to every configured destination.
func sendAlerts(ctx context.Context, webhooks, format string, changes []Change) []error {
	var errs []error
	for _, u := range splitWebhooks(webhooks) {
		var err error
		if strings.HasPrefix(u, "smtp://") || strings.HasPrefix(u, "smtps://") {
			title, body := summaryText(changes)
			err = sendEmail(ctx, u, title, body)
		} else {
			f := format
			if len(splitWebhooks(webhooks)) > 1 {
				f = "auto" // one format cannot fit several services
			}
			err = postWebhook(ctx, u, f, changes)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", redactURL(u), err))
		}
	}
	return errs
}

// sendText delivers a plain message (the weekly summary) everywhere.
func sendText(ctx context.Context, webhooks, title, body string) []error {
	var errs []error
	for _, u := range splitWebhooks(webhooks) {
		var err error
		if strings.HasPrefix(u, "smtp://") || strings.HasPrefix(u, "smtps://") {
			err = sendEmail(ctx, u, title, body)
		} else {
			err = postText(ctx, u, title, body)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", redactURL(u), err))
		}
	}
	return errs
}

func redactURL(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "(alert destination)"
	}
	p.User = nil
	p.RawQuery = ""
	if strings.HasPrefix(p.Path, "/bot") { // Telegram tokens live in the path
		p.Path = "/bot…"
	}
	return p.String()
}

type smtpTarget struct {
	host, port, user, to string
	implicitTLS          bool
}

func parseSMTP(raw string) (*smtpTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	t := &smtpTarget{host: u.Hostname(), port: u.Port(), to: strings.TrimPrefix(u.Path, "/"), implicitTLS: u.Scheme == "smtps"}
	if u.User != nil {
		t.user = u.User.Username()
	}
	if t.port == "" {
		t.port = map[bool]string{true: "465", false: "587"}[t.implicitTLS]
	}
	if t.host == "" || !strings.Contains(t.to, "@") {
		return nil, fmt.Errorf("email destination should look like smtps://user@smtp.example.com/you@example.com")
	}
	if _, pw := u.User.Password(); pw {
		return nil, errors.New("do not put the email password in the URL; set YAKLITE_SMTP_PASSWORD instead")
	}
	return t, nil
}

func sendEmail(ctx context.Context, raw, subject, body string) error {
	t, err := parseSMTP(raw)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(t.host, t.port)
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if t.implicitTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: t.host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	c, err := smtp.NewClient(conn, t.host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if !t.implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS; refusing to send in clear text")
		}
		if err := c.StartTLS(&tls.Config{ServerName: t.host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	from := t.user
	if !strings.Contains(from, "@") {
		from = t.to
	}
	if t.user != "" {
		if err := c.Auth(smtp.PlainAuth("", t.user, smtpPassword(), t.host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(t.to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: yaklite <" + from + ">\r\nTo: " + t.to + "\r\nSubject: " + strings.ReplaceAll(subject, "\n", " ") +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n")
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// smtpPassword comes from YAKLITE_SMTP_PASSWORD, or for background jobs from
// the owner-only file ~/.config/yaklite/smtp-password.
func smtpPassword() string {
	if p := os.Getenv("YAKLITE_SMTP_PASSWORD"); p != "" {
		return p
	}
	b, _ := os.ReadFile(filepath.Join(configDir(), "smtp-password"))
	return strings.TrimSpace(string(b))
}
