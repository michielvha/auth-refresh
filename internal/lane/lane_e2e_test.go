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
	"sync"
	"testing"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
)

// requireBrowser skips without the pinned driver, unless AUTH_REFRESH_E2E=1
// (CI) makes a missing browser a failure instead of a silent skip.
func requireBrowser(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts a real headless browser")
	}
	if _, err := CheckDriver(); err != nil {
		if os.Getenv("AUTH_REFRESH_E2E") == "1" {
			t.Fatalf("AUTH_REFRESH_E2E=1 but %v", err)
		}
		t.Skipf("%v (AUTH_REFRESH_E2E=1 turns this skip into a failure)", err)
	}
}

// fakeIdP serves the pages a real login passes through, each with a "probe"
// input whose typed value only survives if nothing reloads the page, plus an
// Okta-shaped users/me that answers only when the session cookie is set. It
// counts hits per path, so a test can prove nothing was (re)requested.
type fakeIdP struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func (f *fakeIdP) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

const probeInput = `<input name="probe">`

var idpPages = map[string]string{
	"/login":     `<form><input name="identifier"><input type="password" name="pw"><input type="submit"></form>`,
	"/password":  `<h2>Verify with your password</h2><input type="password" name="credentials.passcode"><input type="submit" value="Verify">`,
	"/device":    `<h1>Enter code</h1><p>Enter the code displayed on your app or device.</p><input name="otc"><input type="submit" id="idSIButton9" value="Next">`,
	"/confirm":   `<h1>Are you trying to sign in to Microsoft Azure CLI?</h1><input type="submit" id="idSIButton9" value="Continue">`,
	"/challenge": `<p>Push notification sent. On your phone, tap 42 in Okta Verify.</p>`,
	// Reading the body text throws, as a hostile or broken page can.
	"/unreadable": `<p>secret</p><script>Object.defineProperty(document.body,'innerText',{get(){throw new Error('no text for you')}})</script>`,
	// The button starts a 5s busy loop shortly after the click returns.
	"/busy": `<button id="go" onclick="setTimeout(()=>{const e=Date.now()+5000;while(Date.now()<e){}},300)">go</button>`,
}

func newFakeIdP() *fakeIdP {
	f := &fakeIdP{hits: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		f.mu.Unlock()
		switch r.URL.Path {
		case "/bounce":
			_, _ = fmt.Fprint(w, `<html><body>wait<script>setTimeout(()=>location.href="/challenge",30)</script></body></html>`)
		case "/signin":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/", Expires: time.Now().Add(time.Hour)})
			_, _ = fmt.Fprint(w, `<html><body>signed in</body></html>`)
		case "/api/v1/users/me":
			w.Header().Set("Content-Type", "application/json")
			if c, err := r.Cookie("sid"); err == nil && c.Value == "ok" {
				_, _ = fmt.Fprint(w, `{"profile":{"login":"alice@example.com"},"lastLogin":"2026-10-22T00:00:00.000Z"}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"errorCode":"E0000005","errorSummary":"Invalid session"}`)
		default:
			body, ok := idpPages[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprintf(w, `<html><body>%s%s</body></html>`, probeInput, body)
		}
	})
	f.Server = httptest.NewServer(mux)
	return f
}

func startServe(t *testing.T, cfg *config.Config, state string) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { done <- Serve(ctx, cfg, "work", state, log) }()
	c := &Client{Cfg: cfg, StateDir: state}
	for range 300 {
		if _, err := c.Ping(context.Background(), "work"); err == nil {
			return cancel, done
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("serve exited early: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	cancel()
	t.Fatal("driver never answered ping")
	return nil, nil
}

func workRow(t *testing.T, rows []LaneStatus) LaneStatus {
	t.Helper()
	for _, r := range rows {
		if r.Lane == "work" {
			return r
		}
	}
	t.Fatalf("no work lane in %+v", rows)
	return LaneStatus{}
}

func TestLaneEndToEnd(t *testing.T) {
	requireBrowser(t)
	idp := newFakeIdP()
	defer idp.Close()

	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	credsFile := filepath.Join(dir, "creds")
	if err := os.WriteFile(credsFile, []byte("[work]\nuser=alice@example.com\npass=hunter2\n[other]\nuser=bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(fmt.Appendf(nil, `{"creds_file":%q,"idp":{"org_url":%q},
		"lanes":{"work":{"account":"alice@example.com"},"other":{"account":"bob@example.com"}}}`, credsFile, idp.URL), "test")
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

	t.Run("removed actions are gone", func(t *testing.T) {
		for _, a := range []string{"download", "upload", "netdump", "labels", "typelines"} {
			if r := send(Command{Action: a}); r.OK || !strings.Contains(r.Error, "unknown action") {
				t.Errorf("%s: %+v", a, r)
			}
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

	t.Run("mfa finds the number", func(t *testing.T) {
		send(Command{Action: "goto", URL: idp.URL + "/challenge"})
		n, err := c.MFA(ctx, "work", 3, 100*time.Millisecond)
		if err != nil || n != "42" {
			t.Fatalf("mfa: %q %v", n, err)
		}
		hist, _ := os.ReadFile(filepath.Join(state, "mfa-number.txt"))
		if !strings.Contains(string(hist), "lane=work tap 42") {
			t.Fatalf("history: %q", hist)
		}
	})

	// Every page a login passes through, not just a recognised MFA screen:
	// status and whoami must leave each exactly as it was.
	for _, tc := range []struct {
		path      string
		challenge bool
		readErr   bool
	}{
		{"/login", false, false},
		{"/password", false, false},
		{"/device", false, false},
		{"/confirm", false, false},
		{"/challenge", true, false},
		{"/unreadable", false, true},
		{"/busy", false, true},
	} {
		t.Run("status and whoami leave "+tc.path+" untouched", func(t *testing.T) {
			url := idp.URL + tc.path
			send(Command{Action: "goto", URL: url})
			marker := "typed-on-" + strings.TrimPrefix(tc.path, "/")
			if r := send(Command{Action: "fill", Selector: "input[name=probe]", Text: marker}); !r.OK {
				t.Fatalf("fill: %+v", r)
			}
			if tc.path == "/busy" {
				send(Command{Action: "click", Selector: "#go"})
				time.Sleep(700 * time.Millisecond)
			}
			pageHits, meHits := idp.count(tc.path), idp.count("/api/v1/users/me")

			start := time.Now()
			row := workRow(t, c.Status(ctx))
			if took := time.Since(start); took > peekBudget+3*time.Second {
				t.Fatalf("status took %s", took)
			}
			if row.PID == 0 || row.Page != url || row.Challenge != tc.challenge || (row.PageError != "") != tc.readErr {
				t.Fatalf("status row: %+v", row)
			}
			if _, err := c.Whoami(ctx, "work"); err == nil || !strings.Contains(err.Error(), "REFUSED") {
				t.Fatalf("whoami on %s must be refused, got %v", tc.path, err)
			}

			r := send(Command{Action: "controls"}) // waits out the busy loop
			if r.URL != url || !strings.Contains(fmt.Sprint(r.Extra["controls"]), marker) {
				t.Fatalf("page changed: url %q controls %v", r.URL, r.Extra["controls"])
			}
			if idp.count(tc.path) != pageHits || idp.count("/api/v1/users/me") != meHits {
				t.Fatalf("status or whoami made requests: page %d->%d, users/me %d->%d",
					pageHits, idp.count(tc.path), meHits, idp.count("/api/v1/users/me"))
			}
		})
	}

	t.Run("status answers while an action holds the page", func(t *testing.T) {
		send(Command{Action: "goto", URL: idp.URL + "/password"})
		held := make(chan Result, 1)
		go func() {
			r, _ := c.Send(ctx, "work", Command{Action: "waiturl", Pattern: "never-matches", MS: 4000})
			held <- r
		}()
		time.Sleep(300 * time.Millisecond)
		start := time.Now()
		row := workRow(t, c.Status(ctx))
		if took := time.Since(start); took > 2*time.Second || row.Page != idp.URL+"/password" {
			t.Fatalf("status blocked %s or wrong page: %+v", took, row)
		}
		if r := <-held; r.OK || r.URL != idp.URL+"/password" {
			t.Fatalf("waiturl: %+v", r)
		}
	})

	t.Run("park, then whoami probes without moving the page", func(t *testing.T) {
		if r, _ := c.Park(ctx, "work"); r.URL != "about:blank" {
			t.Fatalf("park: %+v", r)
		}
		row := workRow(t, c.Status(ctx))
		if row.Page != "about:blank" || row.Challenge || row.PageError != "" {
			t.Fatalf("parked status: %+v", row)
		}
		me := idp.count("/api/v1/users/me")
		who, err := c.Whoami(ctx, "work")
		if err != nil || who.Live || who.Reason != "Invalid session" {
			t.Fatalf("before sign-in: %+v %v", who, err)
		}
		if idp.count("/api/v1/users/me") != me+1 {
			t.Fatal("whoami did not ask the IdP exactly once")
		}
		if r := send(Command{Action: "text"}); r.URL != "about:blank" {
			t.Fatalf("whoami moved the page to %q", r.URL)
		}
	})

	t.Run("login lands, state, park, whoami", func(t *testing.T) {
		send(Command{Action: "goto", URL: idp.URL + "/signin"})
		if _, err := c.Whoami(ctx, "work"); err == nil || !strings.Contains(err.Error(), "park the lane") {
			t.Fatalf("whoami before park must be refused: %v", err)
		}
		r := send(Command{Action: "state"})
		if b, _ := r.Extra["bytes"].(float64); !r.OK || b < 50 {
			t.Fatalf("state: %+v", r)
		}
		if st, err := os.Stat(PathsFor(state, "work").Session); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("session file must be 0600: %v", err)
		}
		if _, err := c.Park(ctx, "work"); err != nil {
			t.Fatal(err)
		}
		who, err := c.Whoami(ctx, "work")
		if err != nil || !who.Live || who.Login != "alice@example.com" {
			t.Fatalf("after sign-in: %+v %v", who, err)
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
	if row := workRow(t, c.Status(ctx)); row.PID != 0 || row.Page != "" || !strings.HasPrefix(row.Session, "saved ") {
		t.Fatalf("stopped status: %+v", row)
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

func TestProbeStartsThePinnedBrowser(t *testing.T) {
	requireBrowser(t)
	detail, err := Probe(90*time.Second, nil)
	if err != nil || !strings.Contains(detail, "driver "+DriverVersion()+", chromium ") {
		t.Fatalf("probe: %q %v", detail, err)
	}
	t.Run("a missing browser is a clear failure", func(t *testing.T) {
		t.Setenv("PLAYWRIGHT_BROWSERS_PATH", t.TempDir())
		_, err := Probe(90*time.Second, nil)
		if err == nil || !strings.Contains(err.Error(), "runtime file missing: browser/") || strings.Contains(err.Error(), "npx") {
			t.Fatalf("got %v", err)
		}
	})
}
