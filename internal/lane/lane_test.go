package lane

import (
	"encoding/json"
	"strings"
	"testing"

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
