package lane

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
)

func TestExtractNumber(t *testing.T) {
	en := config.DefaultNumberRegex
	nlen := `(?:tik vervolgens op|tap)\s+(\d{1,3})`
	tests := []struct {
		name, re, text, want string
	}{
		{"english", en, "Push notification sent. On your phone, tap 42 in Okta Verify", "42"},
		{"case insensitive", en, "TAP 7 now", "7"},
		{"dutch", nlen, "Open Okta Verify en tik vervolgens op 13", "13"},
		{"none", en, "Enter your password", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractNumber(tt.re, tt.text); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOnChallenge(t *testing.T) {
	re := `push notification sent|pushmelding verzonden|tap [0-9]`
	if !OnChallenge(re, "Pushmelding verzonden") || OnChallenge(re, "Sign in") {
		t.Fatal("challenge detection wrong")
	}
}

func TestParseWhoami(t *testing.T) {
	long := `{"id":"x","profile":{"login":"me@example.com","bio":"` + strings.Repeat("x", 4000) + `"},"lastLogin":"2026-10-01T08:00:00.000Z"}`
	tests := []struct {
		name, body, want string
	}{
		{"live, profile longer than the text cap", long, "LIVE as me@example.com (last login 2026-10-01T08:00:00.000Z)"},
		{"invalid session", `{"errorCode":"E0000005","errorSummary":"Invalid session"}`, "DEAD, Invalid session"},
		{"html", "<html>login</html>", "DEAD, <html>login</html>"},
		{"empty", "", "DEAD, empty reply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseWhoami(tt.body).String(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSafeOutFile(t *testing.T) {
	for _, bad := range []string{"../x", "/etc/passwd", "a/b", "..", "."} {
		if _, err := SafeOutFile("/s/out", bad, "d"); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	got, err := SafeOutFile("/s/out", "", "sessions.json")
	if err != nil || got != "/s/out/sessions.json" {
		t.Fatalf("default: %q %v", got, err)
	}
}

func TestResultJSONRoundTrip(t *testing.T) {
	in := Result{OK: true, URL: "about:blank", Extra: map[string]any{"bytes": 12.0, "text": "hi"}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"bytes":12`) {
		t.Fatalf("extra not flattened: %s", b)
	}
	var out Result
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.URL != "about:blank" || out.String() != "hi" || out.Extra["bytes"] != 12.0 {
		t.Fatalf("round trip: %+v", out)
	}
}

func TestProbeWithoutDriver(t *testing.T) {
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	t.Setenv("PLAYWRIGHT_NODEJS_PATH", "")
	t.Run("missing driver", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("AUTH_REFRESH_TEST_SYNTHETIC_DRIVER", "1")
		oldVerify := verifyRuntime
		verifyRuntime = func(string) error { return nil }
		t.Cleanup(func() { verifyRuntime = oldVerify })
		t.Setenv("PLAYWRIGHT_DRIVER_PATH", dir)
		_, err := Probe(5*time.Second, nil)
		if err == nil || !strings.Contains(err.Error(), "not installed") || !strings.Contains(err.Error(), "auth-refresh setup") {
			t.Fatalf("got %v", err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("a check must not create files, got %v", entries)
		}
	})
	fakeDriver := func(t *testing.T, script string) {
		t.Helper()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "package"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package", "cli.js"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		node := filepath.Join(dir, "node")
		if err := os.WriteFile(node, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AUTH_REFRESH_TEST_SYNTHETIC_DRIVER", "1")
		oldVerify := verifyRuntime
		verifyRuntime = func(string) error { return nil }
		t.Cleanup(func() { verifyRuntime = oldVerify })
		t.Setenv("PLAYWRIGHT_DRIVER_PATH", dir)
		t.Setenv("PLAYWRIGHT_NODEJS_PATH", node)
	}
	t.Run("a driver of another version is refused", func(t *testing.T) {
		fakeDriver(t, "echo Version 1.0.0")
		_, err := Probe(10*time.Second, nil)
		if err == nil || !strings.Contains(err.Error(), "version not "+DriverVersion()) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a hung driver is bounded", func(t *testing.T) {
		fakeDriver(t, "sleep 2")
		start := time.Now()
		_, err := Probe(300*time.Millisecond, nil)
		if err == nil || !strings.Contains(err.Error(), "did not start within") || time.Since(start) > 2*time.Second {
			t.Fatalf("got %v after %s", err, time.Since(start))
		}
	})
}

func TestShortErrDropsTheNpxBanner(t *testing.T) {
	err := errors.New("BrowserType.launch: Executable doesn't exist at /x/chrome-headless-shell\n╔════╗\n║ Looks like Playwright was just installed or updated. ║\n║ Please run the following command to download new browsers: ║\n║     npx playwright install ║\n╚════╝")
	got := shortErr(err)
	if strings.Contains(got, "npx") || !strings.Contains(got, "Executable doesn't exist") {
		t.Fatalf("got %q", got)
	}
}
