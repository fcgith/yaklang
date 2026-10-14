package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// Leaked-password watch, through Have I Been Pwned:
//
//   - free: whether the service on your own domain was itself breached
//     (yaklite outside -d), and whether a password is in known leaks
//     (yaklite password-check, which sends only the first 5 characters of
//     the password's SHA-1 hash, never the password)
//   - with an HIBP API key (paid): every address at your domain found in a
//     breach (the domain must be verified in the HIBP dashboard), and the
//     personal addresses you list in watch-emails

const hibpBase = "https://haveibeenpwned.com/api/v3"

var hibpBaseURL = hibpBase // tests point this elsewhere
var pwnedPasswordsURL = "https://api.pwnedpasswords.com/range/"

func hibpKey() string {
	if k := strings.TrimSpace(os.Getenv("HIBP_API_KEY")); k != "" {
		return k
	}
	data, _ := os.ReadFile(filepath.Join(configDir(), "hibp-key"))
	return strings.TrimSpace(string(data))
}

// watchEmails are personal addresses to check (one per line), with a key.
func watchEmails() []string {
	data, _ := os.ReadFile(filepath.Join(configDir(), "watch-emails"))
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") && strings.Contains(l, "@") {
			out = append(out, strings.ToLower(l))
		}
	}
	return out
}

type hibpBreach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	AddedDate   string   `json:"AddedDate"`
	PwnCount    int      `json:"PwnCount"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
}

func hibpGet(ctx context.Context, path, key string, v any) (found bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hibpBaseURL+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "yaklite-home-monitor")
	if key != "" {
		req.Header.Set("hibp-api-key", key)
	}
	for attempt := 0; ; attempt++ {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return false, nil
		case resp.StatusCode == http.StatusTooManyRequests && attempt < 3:
			wait, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			if wait < 1 || wait > 60 {
				wait = 7
			}
			select {
			case <-time.After(time.Duration(wait) * time.Second):
			case <-ctx.Done():
				return false, ctx.Err()
			}
			continue
		case resp.StatusCode == http.StatusUnauthorized:
			return false, errors.New("Have I Been Pwned refused the API key (check hibp-key)")
		case resp.StatusCode == http.StatusForbidden && strings.Contains(path, "breacheddomain"):
			return false, errors.New("Have I Been Pwned: this domain is not verified on your account (verify it at haveibeenpwned.com/DomainSearch)")
		case resp.StatusCode >= 300:
			return false, fmt.Errorf("Have I Been Pwned answered %s", resp.Status)
		}
		return true, json.Unmarshal(data, v)
	}
}

func hasClass(b hibpBreach, class string) bool {
	for _, c := range b.DataClasses {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}

func breachWhat(b hibpBreach) string {
	classes := b.DataClasses
	if len(classes) > 5 {
		classes = append(append([]string{}, classes[:5]...), "…")
	}
	return fmt.Sprintf("%s (%s): %s", orStr(b.Title, b.Name), b.BreachDate, strings.Join(classes, ", "))
}

// ownSiteBreachFindings: was the service on this domain itself breached?
func ownSiteBreachFindings(domain string, breaches []hibpBreach) []*Finding {
	var out []*Finding
	for _, b := range breaches {
		sev := sevHigh
		if t, err := time.Parse("2006-01-02T15:04:05Z", b.AddedDate); err == nil && time.Since(t) > 365*24*time.Hour {
			sev = sevMedium
		}
		out = append(out, &Finding{ID: "breach:site:" + strings.ToLower(b.Name), Severity: sev, Host: domain,
			Title:  fmt.Sprintf("%s itself is listed as breached: %s", domain, breachWhat(b)),
			Detail: fmt.Sprintf("%d accounts were leaked.", b.PwnCount),
			Fix:    "If this is news to you, find out what happened, tell your users and make everyone change their password."})
	}
	return out
}

// accountBreachFindings turns "address -> breach names" into findings.
func accountBreachFindings(accounts map[string][]string, catalog map[string]hibpBreach, now time.Time) []*Finding {
	var out []*Finding
	for addr, names := range accounts {
		for _, n := range names {
			b, ok := catalog[strings.ToLower(n)]
			if !ok {
				b = hibpBreach{Name: n}
			}
			sev := sevMedium
			if hasClass(b, "Passwords") {
				sev = sevHigh
				if t, err := time.Parse("2006-01-02T15:04:05Z", b.AddedDate); err == nil && now.Sub(t) > 365*24*time.Hour {
					sev = sevMedium // old news, but still worth knowing
				}
			}
			fix := "Change the password for " + orStr(b.Domain, b.Name) + " and anywhere you used the same password; turn on two-factor login."
			if !hasClass(b, "Passwords") {
				fix = "No password leaked, but expect more spam and phishing to " + addr + ". Be wary of messages that mention " + orStr(b.Title, b.Name) + "."
			}
			out = append(out, &Finding{ID: "breach:" + addr + ":" + strings.ToLower(n), Severity: sev,
				Title: addr + " is in a data leak: " + breachWhat(b),
				Fix:   fix})
		}
	}
	return out
}

func breachCatalog(ctx context.Context) map[string]hibpBreach {
	var all []hibpBreach
	if ok, err := hibpGet(ctx, "/breaches", "", &all); !ok || err != nil {
		return map[string]hibpBreach{}
	}
	m := make(map[string]hibpBreach, len(all))
	for _, b := range all {
		m[strings.ToLower(b.Name)] = b
	}
	return m
}

// breachFindings runs the breach checks for the domains (and the personal
// addresses in watch-emails, with a key).
func breachFindings(ctx context.Context, domains []string) ([]*Finding, []string) {
	var out []*Finding
	var errs []string
	key := hibpKey()
	for _, d := range domains {
		var bs []hibpBreach
		if _, err := hibpGet(ctx, "/breaches?domain="+url.QueryEscape(d), "", &bs); err != nil {
			errs = append(errs, "breach lookup for "+d+": "+err.Error())
		}
		out = append(out, ownSiteBreachFindings(d, bs)...)
	}
	if key == "" {
		return out, errs
	}
	catalog := breachCatalog(ctx)
	accounts := map[string][]string{}
	for _, d := range domains {
		var r map[string][]string
		if _, err := hibpGet(ctx, "/breacheddomain/"+url.PathEscape(d), key, &r); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		for alias, names := range r {
			accounts[strings.ToLower(alias)+"@"+d] = names
		}
	}
	for i, e := range watchEmails() {
		if i > 0 {
			time.Sleep(6500 * time.Millisecond) // the smallest key allows 10 lookups a minute
		}
		var bs []hibpBreach
		if _, err := hibpGet(ctx, "/breachedaccount/"+url.PathEscape(e)+"?truncateResponse=true", key, &bs); err != nil {
			errs = append(errs, "breach lookup for "+e+": "+err.Error())
			continue
		}
		for _, b := range bs {
			accounts[e] = append(accounts[e], b.Name)
		}
	}
	out = append(out, accountBreachFindings(accounts, catalog, time.Now())...)
	return out, errs
}

// ---- yaklite password-check ----

func sha1Upper(s string) string {
	sum := sha1.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// pwnedCount looks a password up by the first 5 characters of its hash.
func pwnedCount(ctx context.Context, password string) (int, error) {
	h := sha1Upper(password)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pwnedPasswordsURL+h[:5], nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "yaklite-home-monitor")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Pwned Passwords answered %s", resp.Status)
	}
	return matchPwnedRange(resp.Body, h[5:])
}

func matchPwnedRange(r io.Reader, suffix string) (int, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		s, c, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && strings.EqualFold(s, suffix) {
			n, _ := strconv.Atoi(c)
			return n, nil // padding lines have a count of 0
		}
	}
	return 0, sc.Err()
}

func cmdPasswordCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("password-check", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: yaklite password-check\n\nAsks for a password (not shown) and says whether it is in known data leaks.\nOnly the first 5 characters of its SHA-1 hash leave this computer; the password never does.")
	}
	fs.Parse(args)
	fmt.Fprint(os.Stderr, "Password to check (not shown): ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pw = []byte(strings.TrimRight(line, "\r\n"))
	}
	if len(pw) == 0 {
		return errors.New("no password given")
	}
	n, err := pwnedCount(ctx, string(pw))
	for i := range pw {
		pw[i] = 0
	}
	if err != nil {
		return err
	}
	if n > 0 {
		fmt.Printf("Leaked: this password appears %d times in known data leaks. Stop using it everywhere, and use a password manager to make a new one.\n", n)
		os.Exit(3)
	}
	fmt.Println("Not found in known data leaks. (That does not make it strong: use a long, unique password for each site.)")
	return nil
}

// cmdBreaches checks domains and addresses now.
func cmdBreaches(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("breaches", flag.ExitOnError)
	domains := fs.String("d", "", "your domains, comma separated")
	fs.Parse(args)
	var ds []string
	for _, d := range strings.Split(*domains, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			ds = append(ds, d)
		}
	}
	if len(ds) == 0 && (hibpKey() == "" || len(watchEmails()) == 0) {
		return errors.New("usage: yaklite breaches -d example.com (personal addresses need an HIBP key in " + filepath.Join(configDir(), "hibp-key") + " and a list in " + filepath.Join(configDir(), "watch-emails") + ")")
	}
	fsnd, errs := breachFindings(ctx, ds)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "warning:", e)
	}
	if len(fsnd) == 0 {
		fmt.Println("No leaks found.")
		if hibpKey() == "" {
			fmt.Println("Without an HIBP API key only the domains themselves are checked, not the addresses at them.")
		}
		return nil
	}
	for _, f := range fsnd {
		fmt.Printf("[%s] %s\n   What to do: %s\n", strings.ToUpper(f.Severity), f.Title, f.Fix)
	}
	return nil
}
