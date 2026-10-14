package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appReq(method, path, token, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Host = "127.0.0.1:9842"
	req.RemoteAddr = "127.0.0.1:50000"
	if token != "" {
		req.Header.Set("X-Yaklite-App-Token", token)
	}
	return req
}

func TestAppAPIToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := writeTestState(t)
	h := newWebHandler(&stateReader{dir: dir}, "")

	// no token file yet: always refused
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, appReq(http.MethodGet, "/api/app/summary", "anything", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("without a token file: %d", rec.Code)
	}
	tok, err := ensureAppToken()
	if err != nil || len(tok) != 64 {
		t.Fatalf("token %q %v", tok, err)
	}
	if st, err := os.Stat(appTokenPath()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode: %v %v", st, err)
	}
	for _, bad := range []string{"", "wrong", tok + "x"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, appReq(http.MethodGet, "/api/app/summary", bad, ""))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("token %q: %d", bad, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, appReq(http.MethodGet, "/api/app/summary", tok, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("with token: %d %s", rec.Code, rec.Body)
	}
	var s appSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Status != "warn" || len(s.Alerts) != 1 || s.Alerts[0].AckKey != "port_open:192.168.1.10:tcp/23" || s.Alerts[0].Fix == "" || s.Score == 0 {
		t.Fatalf("summary: %+v", s)
	}

	// another computer is refused even with the token
	req := appReq(http.MethodGet, "/api/app/summary", tok, "")
	req.RemoteAddr = "192.168.1.50:50000"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback: %d", rec.Code)
	}
	// and a rebinding Host header too
	req = appReq(http.MethodGet, "/api/app/summary", tok, "")
	req.Host = "evil.example:9842"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad host: %d", rec.Code)
	}
}

func TestAppAPIAckAndEvent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := writeTestState(t)
	h := newWebHandler(&stateReader{dir: dir}, "")
	tok, _ := ensureAppToken()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, appReq(http.MethodPost, "/api/app/ack", tok, `{"key":"port_open:192.168.1.10:tcp/23","for":"1d"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", rec.Code, rec.Body)
	}
	if !loadAcks().matches("port_open:192.168.1.10:tcp/23", time.Now()) {
		t.Fatal("ack not saved")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, appReq(http.MethodGet, "/api/app/summary", tok, ""))
	var s appSummary
	json.Unmarshal(rec.Body.Bytes(), &s)
	if len(s.Alerts) != 0 || s.Status != "ok" {
		t.Fatalf("acked alert still shown: %+v", s)
	}
	for _, bad := range []string{`{"key":"","for":"1d"}`, `{"key":"x","for":"soon"}`, `not json`} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, appReq(http.MethodPost, "/api/app/ack", tok, bad))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("ack %s: %d", bad, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, appReq(http.MethodGet, "/api/app/ack", tok, ""))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET ack: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, appReq(http.MethodPost, "/api/app/event", tok, `{"kind":"camera","app":"FaceTime","on":true}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("event: %d %s", rec.Code, rec.Body)
	}
	data, _ := os.ReadFile(appEventsPath(dir))
	if !strings.Contains(string(data), `"app":"FaceTime"`) {
		t.Fatalf("event not saved: %s", data)
	}
	for _, bad := range []string{`{"kind":"screen","app":"x","on":true}`, `{"kind":"mic","app":"` + strings.Repeat("a", 101) + `","on":true}`, `{"kind":"mic","app":"a\nb"}`} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, appReq(http.MethodPost, "/api/app/event", tok, bad))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("event %s: %d", bad, rec.Code)
		}
	}
}

func TestAppendCapped(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.jsonl")
	for i := 0; i < 15; i++ {
		if err := appendCapped(p, []byte(`{"n":1}`), 10); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(p)
	if n := strings.Count(string(data), "\n"); n != 10 {
		t.Fatalf("%d lines", n)
	}
}

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		hdr.SetMode(0o644)
		if strings.HasSuffix(name, "/MacOS/YakliteBar") {
			hdr.SetMode(0o755)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

func TestExtractMenubarApp(t *testing.T) {
	for _, name := range []string{"../evil", "YakliteBar.app/../../evil", "/etc/evil", "YakliteBar.app\\..\\evil", "Other.app/x"} {
		dir := t.TempDir()
		err := extractMenubarApp(makeZip(t, map[string]string{"YakliteBar.app/Contents/Info.plist": "x", name: "bad"}), dir)
		if err == nil {
			t.Fatalf("%q accepted", name)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); err == nil {
			t.Fatalf("%q wrote outside", name)
		}
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "YakliteBar.app", "old"), 0o755)
	z := makeZip(t, map[string]string{"YakliteBar.app/Contents/Info.plist": "plist", "YakliteBar.app/Contents/MacOS/YakliteBar": "bin", "__MACOSX/._x": "junk"})
	if err := extractMenubarApp(z, dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "YakliteBar.app", "Contents", "MacOS", "YakliteBar"))
	if err != nil || st.Mode().Perm()&0o100 == 0 {
		t.Fatalf("binary not executable: %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "YakliteBar.app", "old")); err == nil {
		t.Fatal("old copy not replaced")
	}
	if _, err := os.Stat(filepath.Join(dir, "__MACOSX")); err == nil {
		t.Fatal("junk extracted")
	}
}
