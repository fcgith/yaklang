package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

// `yaklite update` replaces the installed binary with the latest build from
// this project's GitHub releases. It only runs when you ask; it checks the
// download against the published SHA-256 checksum (both fetched from GitHub
// with certificate verification on) and that the new binary starts before
// swapping it in.

const updateRepo = "fcgith/yaklang"

var updateHosts = []string{"github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}

func releaseAssetName() (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64", "darwin/amd64":
		return "yaklite-macos", nil
	case "linux/amd64":
		return "yaklite-linux-amd64", nil
	case "linux/arm64":
		return "yaklite-linux-arm64", nil
	case "windows/amd64":
		return "yaklite-windows.exe", nil
	}
	return "", fmt.Errorf("no published build for %s/%s", runtime.GOOS, runtime.GOARCH)
}

var updateClient = &http.Client{
	Timeout: 5 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || !contains(updateHosts, req.URL.Hostname()) {
			return fmt.Errorf("refusing redirect to %s", req.URL.Host)
		}
		return nil
	},
}

type releaseInfo struct {
	Body   string `json:"body"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func latestRelease(ctx context.Context) (*releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+updateRepo+"/releases/tags/yaklite-latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := updateClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub: %s", resp.Status)
	}
	var r releaseInfo
	return &r, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r)
}

// releaseVersion pulls the short commit out of the release notes: "... (abc1234)."
func releaseVersion(body string) string {
	i := strings.LastIndex(body, "(")
	j := strings.LastIndex(body, ")")
	if i < 0 || j < i {
		return ""
	}
	return body[i+1 : j]
}

func download(ctx context.Context, u string, limit int64) ([]byte, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || !contains(updateHosts, p.Hostname()) {
		return nil, fmt.Errorf("unexpected download URL %s", u)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := updateClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func cmdUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "only say whether a newer build exists")
	fs.Parse(args)
	asset, err := releaseAssetName()
	if err != nil {
		return err
	}
	rel, err := latestRelease(ctx)
	if err != nil {
		return err
	}
	latest := releaseVersion(rel.Body)
	if latest != "" && latest == version {
		fmt.Println("yaklite is up to date (" + version + ").")
		return nil
	}
	if *check {
		fmt.Printf("A newer yaklite is available: %s (you have %s). Run: yaklite update\n", orNone(latest), version)
		return nil
	}
	var binURL, sumURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case asset:
			binURL = a.URL
		case asset + ".sha256":
			sumURL = a.URL
		}
	}
	if binURL == "" || sumURL == "" {
		return errors.New("the release has no " + asset + " build with a checksum")
	}
	sumFile, err := download(ctx, sumURL, 4096)
	if err != nil {
		return err
	}
	want := strings.Fields(string(sumFile))
	if len(want) == 0 || len(want[0]) != 64 {
		return errors.New("checksum file is malformed")
	}
	fmt.Println("Downloading", asset, latest)
	bin, err := download(ctx, binURL, 512<<20)
	if err != nil {
		return err
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != strings.ToLower(want[0]) {
		return errors.New("checksum does not match: the download was not installed")
	}
	target := installedBinPath()
	if _, err := os.Stat(target); err != nil {
		if target, err = os.Executable(); err != nil {
			return err
		}
	}
	tmp := filepath.Join(filepath.Dir(target), ".yaklite-update")
	if runtime.GOOS == "windows" {
		tmp += ".exe"
	}
	if err := os.WriteFile(tmp, bin, 0o700); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		exec.Command("xattr", "-d", "com.apple.quarantine", tmp).Run()
	}
	if out, err := exec.CommandContext(ctx, tmp, "version").Output(); err != nil || !strings.HasPrefix(string(out), "yaklite") {
		os.Remove(tmp)
		return errors.New("the new build did not start; keeping the current one")
	}
	if runtime.GOOS == "windows" {
		// a running program cannot be replaced on Windows, but it can be renamed
		os.Remove(target + ".old")
		if err := os.Rename(target, target+".old"); err != nil && !errors.Is(err, os.ErrNotExist) {
			os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Println("Updated", target)
	restartAgents()
	return nil
}

// restartAgents restarts the always-on background jobs so they run the new binary.
func restartAgents() {
	switch runtime.GOOS {
	case "darwin":
		uid := strconv.Itoa(os.Getuid())
		for _, l := range []string{webLabel, connLabel, routerLabel, tripLabel} {
			exec.Command("launchctl", "kickstart", "-k", "gui/"+uid+"/"+l).Run()
		}
	case "linux":
		exec.Command("systemctl", "--user", "try-restart", "yaklite-web.service", "yaklite-conn.service", "yaklite-routerlog.service", "yaklite-tripwire.service").Run()
	case "windows":
		exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			`Get-ScheduledTask -TaskPath '\yaklite\' -ErrorAction SilentlyContinue | Where-Object State -eq 'Running' | ForEach-Object { Stop-ScheduledTask -InputObject $_; Start-ScheduledTask -InputObject $_ }`).Run()
	}
}
