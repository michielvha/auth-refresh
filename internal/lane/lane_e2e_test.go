package lane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
)

// fakeIdP serves a login form, a number-match challenge and an Okta-shaped
// users/me that answers only when the session cookie is set.
func fakeIdP() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body><form><input name="identifier"><input type="password" name="pw"><input type="submit"></form></body></html>`)
	})
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body><p>Push notification sent. On your phone, tap 42 in Okta Verify.</p></body></html>`)
	})
	mux.HandleFunc("/bounce", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<html><body>wait<script>setTimeout(()=>location.href="/challenge",30)</script></body></html>`)
	})
	mux.HandleFunc("/signin", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/", Expires: time.Now().Add(time.Hour)})
		_, _ = fmt.Fprint(w, `<html><body>signed in</body></html>`)
	})
	mux.HandleFunc("/api/v1/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if c, err := r.Cookie("sid"); err == nil && c.Value == "ok" {
			_, _ = fmt.Fprint(w, `{"profile":{"login":"alice@example.com"},"lastLogin":"2026-10-22T00:00:00.000Z"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"errorCode":"E0000005","errorSummary":"Invalid session"}`)
	})
	return httptest.NewServer(mux)
}

func startServe(t *testing.T, cfg *config.Config, state string) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { done <- Serve(ctx, cfg, "work", state, log) }()
	c := &Client{Cfg: cfg, StateDir: state}
	for i := 0; i < 300; i++ {
		if _, err := c.Ping(context.Background(), "work"); err == nil {
			return cancel, done
		}
		select {
		case err := <-done:
			cancel()
			if err != nil && strings.Contains(err.Error(), "install") {
				t.Skipf("browser not installed (run `auth-refresh setup`): %v", err)
			}
			t.Fatalf("serve exited early: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	cancel()
	t.Fatal("driver never answered ping")
	return nil, nil
}

func TestLaneEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a real headless browser")
	}
	idp := fakeIdP()
	defer idp.Close()

	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	credsFile := filepath.Join(dir, "creds")
	if err := os.WriteFile(credsFile, []byte("[work]\nuser=alice@example.com\npass=hunter2\n[other]\nuser=bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`{"creds_file":%q,"idp":{"org_url":%q},
		"lanes":{"work":{"account":"alice@example.com"},"other":{"account":"bob@example.com"}}}`, credsFile, idp.URL)), "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := &Client{Cfg: cfg, StateDir: state}
	send := func(cmd Command) Result {
		t.Helper()
		r, err := c.Send(ctx, "work", cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd.Action, err)
		}
		return r
	}

	cancel, done := startServe(t, cfg, state)

	if st, err := os.Stat(PathsFor(state, "work").Socket); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket must be 0600: %v %v", st, err)
	}

	t.Run("fillcred fills its own lane and never echoes the password", func(t *testing.T) {
		send(Command{Action: "goto", URL: idp.URL + "/login"})
		if r := send(Command{Action: "fillcred", Selector: "input[name=identifier]", Field: "user"}); !r.OK {
			t.Fatalf("fillcred user: %+v", r)
		}
		if r := send(Command{Action: "fillcred", Selector: "input[type=password]", Field: "pass"}); !r.OK {
			t.Fatalf("fillcred pass: %+v", r)
		}
		r := send(Command{Action: "controls"})
		got := fmt.Sprint(r.Extra["controls"])
		if !strings.Contains(got, "alice@example.com") || !strings.Contains(got, "(filled)") || strings.Contains(got, "hunter2") {
			t.Fatalf("controls: %s", got)
		}
	})

	t.Run("cross-lane credentials are refused", func(t *testing.T) {
		r := send(Command{Action: "fillcred", Selector: "input", Field: "user", Section: "other"})
		if r.OK || !strings.Contains(r.Error, "LANE MISMATCH") {
			t.Fatalf("got %+v", r)
		}
	})

	t.Run("out files cannot escape the lane", func(t *testing.T) {
		if r := send(Command{Action: "textfull", File: "../../escape.txt"}); r.OK {
			t.Fatalf("path traversal allowed: %+v", r)
		}
	})

	t.Run("text survives a client-side redirect", func(t *testing.T) {
		for range 5 {
			send(Command{Action: "goto", URL: idp.URL + "/bounce"})
			send(Command{Action: "wait", MS: 30})
			if r := send(Command{Action: "textfull", File: "bounce.txt"}); !r.OK {
				t.Fatalf("textfull across a redirect: %+v", r)
			}
		}
	})

	t.Run("mfa finds the number and status does not kill the challenge", func(t *testing.T) {
		send(Command{Action: "goto", URL: idp.URL + "/challenge"})
		n, err := c.MFA(ctx, "work", 3, 100*time.Millisecond)
		if err != nil || n != "42" {
			t.Fatalf("mfa: %q %v", n, err)
		}
		hist, _ := os.ReadFile(filepath.Join(state, "mfa-number.txt"))
		if !strings.Contains(string(hist), "lane=work tap 42") {
			t.Fatalf("history: %q", hist)
		}
		rows := c.Status(ctx)
		var work LaneStatus
		for _, r := range rows {
			if r.Lane == "work" {
				work = r
			}
		}
		if !work.Challenge {
			t.Fatalf("status missed the challenge: %+v", work)
		}
		if r := send(Command{Action: "text"}); !strings.Contains(r.String(), "tap 42") {
			t.Fatalf("status navigated away from the challenge, page is now %q", r.URL)
		}
		if r, _ := c.Park(ctx, "work"); r.URL != "about:blank" {
			t.Fatalf("park: %+v", r)
		}
	})

	t.Run("whoami reflects the session and state persists it", func(t *testing.T) {
		who, err := c.Whoami(ctx, "work")
		if err != nil || who.Live {
			t.Fatalf("before sign-in: %+v %v", who, err)
		}
		send(Command{Action: "goto", URL: idp.URL + "/signin"})
		who, err = c.Whoami(ctx, "work")
		if err != nil || !who.Live || who.Login != "alice@example.com" {
			t.Fatalf("after sign-in: %+v %v", who, err)
		}
		r := send(Command{Action: "state"})
		if b, _ := r.Extra["bytes"].(float64); !r.OK || b < 50 {
			t.Fatalf("state: %+v", r)
		}
		if st, err := os.Stat(PathsFor(state, "work").Session); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("session file must be 0600: %v", err)
		}
	})

	if r := send(Command{Action: "quit"}); !r.OK {
		t.Fatalf("quit: %+v", r)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not exit after quit")
	}
	cancel()
	if _, err := c.Ping(ctx, "work"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("ping after quit: %v", err)
	}

	t.Run("a restarted lane comes back warm from the saved session", func(t *testing.T) {
		cancel, done := startServe(t, cfg, state)
		defer func() { cancel(); <-done }()
		who, err := c.Whoami(ctx, "work")
		if err != nil || !who.Live {
			t.Fatalf("restart lost the session: %+v %v", who, err)
		}
	})
}
