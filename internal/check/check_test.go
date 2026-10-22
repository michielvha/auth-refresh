package check

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
)

// fakeRunner answers by the longest configured prefix of the full command
// line, e.g. "az account" or "gh auth status --json".
func fakeRunner(t *testing.T, answers map[string]Output, gotEnv *[]string) Runner {
	t.Helper()
	return func(_ context.Context, env []string, name string, args ...string) Output {
		full := strings.Join(append([]string{name}, args...), " ")
		if gotEnv != nil {
			*gotEnv = env
		}
		best := ""
		for k := range answers {
			if strings.HasPrefix(full, k) && len(k) > len(best) {
				best = k
			}
		}
		if best == "" {
			return Output{Code: 127, Stderr: "unexpected command " + full}
		}
		return answers[best]
	}
}

func deps(t *testing.T, answers map[string]Output) Deps {
	return Deps{
		Run:  fakeRunner(t, answers, nil),
		HTTP: func(bool) *http.Client { return http.DefaultClient },
		Home: t.TempDir(),
		Now:  func() time.Time { return time.Date(2026, 10, 22, 2, 0, 0, 0, time.UTC) },
	}
}

type cliCase struct {
	name    string
	id      config.Identity
	answers map[string]Output
	want    Status
	detail  string
}

func runCases(t *testing.T, tests []cliCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := One(context.Background(), tt.id, deps(t, tt.answers))
			if r.Status != tt.want || !strings.Contains(r.Detail, tt.detail) {
				t.Fatalf("got %s %q, want %s containing %q", r.Status, r.Detail, tt.want, tt.detail)
			}
			if !r.Bad() && r.Fix != "" {
				t.Fatalf("a %s result must not offer a fix, got %q", r.Status, r.Fix)
			}
		})
	}
}

func TestCLIIdentities(t *testing.T) {
	aadsts := "WARNING: AADSTS70043: The refresh token has expired\nWARNING: Interactively acquiring token"
	runCases(t, []cliCase{
		{
			"azure live",
			config.Identity{Name: "az", Type: "azure"},
			map[string]Output{"az account": {Stdout: "2026-10-22 13:00:00.000000", Stderr: "WARNING: a deprecation"}},
			OK, "until 2026-10-22 13:00",
		},
		{
			"azure hangs on expired refresh token",
			config.Identity{Name: "az", Type: "azure"},
			map[string]Output{"az account": {Code: 124, Stderr: aadsts}},
			Dead, "AADSTS70043",
		},
		{
			"azure timeout without output",
			config.Identity{Name: "az", Type: "azure"},
			map[string]Output{"az account": {Code: 124}},
			Dead, "timed out",
		},
		{
			"docker ok",
			config.Identity{Name: "r", Type: "docker", ProbeImage: "reg.example.com/a/b:1"},
			map[string]Output{"docker manifest": {Stdout: "{}"}},
			OK, "reg.example.com",
		},
		{
			"docker denied",
			config.Identity{Name: "r", Type: "docker", ProbeImage: "reg.example.com/a/b:1"},
			map[string]Output{"docker manifest": {Code: 1, Stderr: "unauthorized"}},
			Dead, "unauthorized",
		},
	})
}

func TestKube(t *testing.T) {
	const whoami = "kubectl --context dev auth whoami"
	id := config.Identity{Name: "k", Type: "kube", Context: "dev", RidesOn: "az", Lane: "work"}
	review := `{"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1","status":{"userInfo":{"username":"me@example.com"}}}`
	runCases(t, []cliCase{
		{"ok", id, map[string]Output{whoami: {Stdout: review}}, OK, "context dev as me@example.com"},
		{
			"warnings on stderr do not spoil valid output", id,
			map[string]Output{whoami: {Stdout: review, Stderr: "W1022 02:00:00 warnings.go:70] kubelogin: deprecated flag\nWarning: unrecognized format"}},
			OK, "as me@example.com",
		},
		{
			"expired token is dead and names the parent", id,
			map[string]Output{whoami: {Code: 1, Stderr: "error: You must be logged in to the server (Unauthorized)"}},
			Dead, "rides on az",
		},
		{
			"a failed credential plugin inside 'Unable to connect' is auth", id,
			map[string]Output{whoami: {Code: 1, Stderr: "Unable to connect to the server: getting credentials: exec: executable kubelogin failed with exit code 1"}},
			Dead, "getting credentials",
		},
		{
			"aws exec plugin with an expired SSO token is auth", id,
			map[string]Output{whoami: {Code: 1, Stderr: "Error when retrieving token from sso: Token has expired and refresh failed\nUnable to connect to the server: getting credentials: exec: executable aws failed with exit code 255"}},
			Dead, "Token has expired",
		},
		{
			"RBAC forbidden is authenticated, not dead", id,
			map[string]Output{whoami: {Code: 1, Stderr: `Error from server (Forbidden): selfsubjectreviews.authentication.k8s.io is forbidden: User "me@example.com" cannot create resource "selfsubjectreviews"`}},
			Warn, "RBAC forbids",
		},
		{
			"network outage is not a login", id,
			map[string]Output{whoami: {Code: 1, Stderr: "Unable to connect to the server: dial tcp 10.0.0.1:443: i/o timeout"}},
			Warn, "unreachable, not an auth failure",
		},
		{
			"server outage is not a login", id,
			map[string]Output{whoami: {Code: 1, Stderr: "Error from server (ServiceUnavailable): the server is currently unable to handle the request"}},
			Warn, "unreachable",
		},
		{
			"expired server certificate is not a login", id,
			map[string]Output{whoami: {Code: 1, Stderr: "Unable to connect to the server: x509: certificate has expired or is not yet valid"}},
			Warn, "TLS problem",
		},
		{"timeout is not a login", id, map[string]Output{whoami: {Code: 124}}, Warn, "timed out"},
		{
			"old cluster without SelfSubjectReview", id,
			map[string]Output{whoami: {Code: 1, Stderr: "error: the server doesn't have a resource type \"selfsubjectreviews\""}},
			Warn, "cannot tell",
		},
		{
			"unrecognised failure is a warning, not a login", id,
			map[string]Output{whoami: {Code: 1, Stderr: "error: something odd"}},
			Warn, "not recognised",
		},
	})
}

func TestKubePassesAWSProfile(t *testing.T) {
	var env []string
	d := deps(t, nil)
	d.Run = fakeRunner(t, map[string]Output{"kubectl --context": {Stdout: "{}"}}, &env)
	One(context.Background(), config.Identity{Name: "e", Type: "kube", Context: "eks", AWSProfile: "dev"}, d)
	if len(env) != 1 || env[0] != "AWS_PROFILE=dev" {
		t.Fatalf("env = %v", env)
	}
}

func TestGH(t *testing.T) {
	const js, text = "gh auth status --json", "gh auth status --hostname"
	me := config.Identity{Name: "gh", Type: "gh", Host: "github.com", Account: "me"}
	anyone := config.Identity{Name: "gh", Type: "gh", Host: "github.com"}
	noJSON := Output{Code: 1, Stderr: "unknown flag: --json\n\nUsage:  gh auth status [flags]"}
	hosts := func(entries string) Output {
		return Output{Stdout: `{"hosts":{"github.com":[` + entries + `]}}`, Stderr: "noise on stderr"}
	}
	runCases(t, []cliCase{
		// structured output
		{"json: account ok", me, map[string]Output{js: hosts(`{"state":"success","active":true,"host":"github.com","login":"me"}`)}, OK, "me"},
		{
			"json: another account bad does not matter", me,
			map[string]Output{js: hosts(`{"state":"error","error":"bad","active":true,"host":"github.com","login":"other"},{"state":"success","active":false,"host":"github.com","login":"me"}`)},
			OK, "not the active account",
		},
		{
			"json: invalid token for the account", me,
			map[string]Output{js: hosts(`{"state":"error","error":"non-200 OK status code: 401 Unauthorized","active":true,"host":"github.com","login":"me"}`)},
			Dead, "401",
		},
		{"json: prefix me is not meow", me, map[string]Output{js: hosts(`{"state":"success","active":true,"host":"github.com","login":"meow"}`)}, Dead, "me not logged in"},
		{"json: timeout is not a login", me, map[string]Output{js: hosts(`{"state":"timeout","active":true,"host":"github.com","login":"me"}`)}, Warn, "timed out"},
		{"json: nobody logged in", me, map[string]Output{js: {Stdout: `{"hosts":{}}`, Stderr: "You are not logged into any GitHub hosts."}}, Dead, "me not logged in"},
		{"json: no account configured uses the active one", anyone, map[string]Output{js: hosts(`{"state":"success","active":true,"host":"github.com","login":"me"}`)}, OK, "me"},
		{
			"json: no account configured, active token invalid", anyone,
			map[string]Output{js: hosts(`{"state":"error","error":"non-200 OK status code: 401","active":true,"host":"github.com","login":""}`)},
			Dead, "401",
		},
		// older gh without --json: one exact success line
		{
			"text: invalid token line naming the account", me,
			map[string]Output{js: noJSON, text: {Code: 1, Stderr: "github.com\n  X Failed to log in to github.com account me (keyring)\n  - The token in keyring is invalid."}},
			Dead, "me not logged in",
		},
		{
			"text: prefix me is not meow", me,
			map[string]Output{js: noJSON, text: {Stdout: "github.com\n  ✓ Logged in to github.com account meow (keyring)"}},
			Dead, "me not logged in",
		},
		{
			"text: host boundary", me,
			map[string]Output{js: noJSON, text: {Stdout: "  ✓ Logged in to github.com.evil account me (keyring)"}},
			Dead, "me not logged in",
		},
		{
			"text: another account failing keeps ours ok", me,
			map[string]Output{js: noJSON, text: {Code: 1, Stderr: "github.com\n  X Failed to log in to github.com account other (keyring)\n  ✓ Logged in to github.com account me (keyring)\n  - Active account: false"}},
			OK, "me",
		},
		{
			"text: legacy 'as' wording", me,
			map[string]Output{js: noJSON, text: {Stdout: "github.com\n  ✓ Logged in to github.com as me (oauth_token)"}},
			OK, "me",
		},
	})
}

func TestAWSSSO(t *testing.T) {
	const start = "https://d-1.awsapps.com/start"
	write := func(t *testing.T, home, name, body string) {
		t.Helper()
		dir := filepath.Join(home, ".aws", "sso", "cache")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	token := func(url, expires string) string {
		return `{"accessToken":"x","startUrl":"` + url + `","region":"eu-west-1","expiresAt":"` + expires + `"}`
	}
	// sha1("s"), the AWS CLI's cache key for sso_session "s".
	const ours = "a0f1490a20d0211c997b44bc357e1972deab8ae3.json"
	id := config.Identity{Name: "aws", Type: "aws_sso", SSOSession: "s", StartURL: start}
	probe := id
	probe.ProbeProfile = "dev"
	type setup func(t *testing.T, home string)
	tests := []struct {
		name    string
		id      config.Identity
		cache   setup
		answers map[string]Output
		want    Status
		detail  string
	}{
		{"alive, no probe", id, func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-22T03:30:00Z")) }, nil, OK, "1h30m left"},
		{"legacy UTC timestamp", id, func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-22T03:30:00UTC")) }, nil, OK, "1h30m left"},
		{"start URL trailing slash and #", id, func(t *testing.T, h string) { write(t, h, ours, token(start+"/#", "2026-10-22T03:30:00Z")) }, nil, OK, "left"},
		{"expired, no probe", id, func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-21T00:00:00Z")) }, nil, Dead, "expired"},
		{
			"another session's newer token is not ours", id,
			func(t *testing.T, h string) {
				write(t, h, ours, token(start, "2026-10-21T00:00:00Z"))
				write(t, h, "ffffffffffffffffffffffffffffffffffffffff.json", token(start, "2099-01-01T00:00:00Z"))
			},
			nil, Dead, "expired",
		},
		{
			"only another session cached", id,
			func(t *testing.T, h string) { write(t, h, "other.json", token(start, "2099-01-01T00:00:00Z")) },
			nil, Dead, "no SSO token cached for sso_session s",
		},
		{"wrong start URL", id, func(t *testing.T, h string) {
			write(t, h, ours, token("https://d-2.awsapps.com/start", "2099-01-01T00:00:00Z"))
		}, nil, Dead, "config says"},
		{"malformed cache is reported", id, func(t *testing.T, h string) { write(t, h, ours, `{"accessToken":`) }, nil, Dead, "malformed"},
		{"cache without a token is reported", id, func(t *testing.T, h string) { write(t, h, ours, `{"clientId":"c"}`) }, nil, Dead, "no accessToken"},
		{"unreadable expiry is reported", id, func(t *testing.T, h string) { write(t, h, ours, token(start, "tomorrow")) }, nil, Dead, "unreadable expiresAt"},
		{
			"probe ok even though the cached access token expired (CLI refreshed it)", probe,
			func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-21T00:00:00Z")) },
			map[string]Output{"aws sts": {Stdout: "arn:aws:sts::1:assumed-role/dev/me"}},
			OK, "dev -> arn:aws:sts::1:assumed-role/dev/me",
		},
		{
			"probe auth failure", probe,
			func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-22T03:30:00Z")) },
			map[string]Output{"aws sts": {Code: 255, Stderr: "Error when retrieving token from sso: Token has expired and refresh failed"}},
			Dead, "Token has expired",
		},
		{
			"probe fails and the token is expired", probe,
			func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-21T00:00:00Z")) },
			map[string]Output{"aws sts": {Code: 255, Stderr: "some error"}},
			Dead, "expired",
		},
		{
			"probe network failure with a live token is not a login", probe,
			func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-22T03:30:00Z")) },
			map[string]Output{"aws sts": {Code: 255, Stderr: `Could not connect to the endpoint URL: "https://sts.amazonaws.com/"`}},
			Warn, "unreachable",
		},
		{
			"probe denied by permissions with a live token is not a login", probe,
			func(t *testing.T, h string) { write(t, h, ours, token(start, "2026-10-22T03:30:00Z")) },
			map[string]Output{"aws sts": {Code: 255, Stderr: "An error occurred (ForbiddenException) when calling the GetRoleCredentials operation: No access"}},
			Warn, "not recognised",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := deps(t, tt.answers)
			tt.cache(t, d.Home)
			r := One(context.Background(), tt.id, d)
			if r.Status != tt.want || !strings.Contains(r.Detail, tt.detail) {
				t.Fatalf("got %s %q, want %s containing %q", r.Status, r.Detail, tt.want, tt.detail)
			}
		})
	}
	t.Run("cache file name is sha1 of the session name", func(t *testing.T) {
		if got := filepath.Base(ssoCacheFile("/h", "s")); got != ours {
			t.Fatalf("got %s", got)
		}
	})
	t.Run("default fix comes from the lane", func(t *testing.T) {
		withLane := id
		withLane.Lane = "work"
		r := One(context.Background(), withLane, deps(t, nil))
		if r.Status != Dead || r.Fix != "start aws" {
			t.Fatalf("got %+v", r)
		}
	})
}

func TestHTTPToken(t *testing.T) {
	const tok = "squ_supersecret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "" && pass == tok {
			_, _ = w.Write([]byte(`{"authenticatedUser":{"providerDisplayName":"Me"}}`))
			return
		}
		if r.Header.Get("Authorization") == "Bearer "+tok {
			_, _ = w.Write([]byte(`{"valid":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(good, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loose, []byte(tok), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		id   config.Identity
		want Status
	}{
		{"basic_pass PAT", config.Identity{Type: "http_token", File: good, URL: srv.URL, Auth: "basic_pass", Expect: "authenticatedUser", Retries: 1}, OK},
		{"bearer", config.Identity{Type: "http_token", File: good, URL: srv.URL, Expect: `"valid":true`, Retries: 1}, OK},
		{"wrong scheme rejected", config.Identity{Type: "http_token", File: good, URL: srv.URL, Auth: "basic_user", Retries: 1}, Dead},
		{"loose permissions warn", config.Identity{Type: "http_token", File: loose, URL: srv.URL, Expect: "valid", Retries: 1}, Warn},
		{"missing file", config.Identity{Type: "http_token", File: filepath.Join(dir, "nope"), URL: srv.URL, Retries: 1}, Missing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := One(context.Background(), tt.id, deps(t, nil))
			if r.Status != tt.want {
				t.Fatalf("got %+v, want %s", r, tt.want)
			}
			if strings.Contains(r.Detail, tok) || strings.Contains(r.Detail, base64.StdEncoding.EncodeToString([]byte(":"+tok))) {
				t.Fatal("detail leaks the token")
			}
		})
	}
}

func TestHTTPUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if r := One(context.Background(), config.Identity{Type: "http_up", URL: srv.URL, ExpectStatus: 200}, deps(t, nil)); r.Status != OK {
		t.Fatalf("got %+v", r)
	}
	srv.Close()
	if r := One(context.Background(), config.Identity{Type: "http_up", URL: srv.URL, ExpectStatus: 200}, deps(t, nil)); r.Status != Dead {
		t.Fatalf("closed server should be DEAD, got %+v", r)
	}
}

func TestMissingBinaries(t *testing.T) {
	cfg := &config.Config{
		RequiredBinaries: []string{"git"},
		Identities:       []config.Identity{{Type: "azure"}, {Type: "kube"}, {Type: "http_up"}},
	}
	have := map[string]bool{"git": true, "kubectl": true}
	which := func(b string) (string, error) {
		if have[b] {
			return "/bin/" + b, nil
		}
		return "", errors.New("not found")
	}
	got := MissingBinaries(cfg, which)
	if strings.Join(got, ",") != "az" {
		t.Fatalf("got %v, want [az]", got)
	}
}

func TestExecRunnerReturnsPartialOutputOnTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	o := ExecRunner(ctx, nil, "sh", "-c", "echo AADSTS70043 expired >&2; sleep 5")
	if o.Code != 124 || !strings.Contains(o.Stderr, "AADSTS70043") {
		t.Fatalf("got %+v", o)
	}
	if o := ExecRunner(context.Background(), nil, "definitely-not-a-binary-xyz"); o.Code != 127 {
		t.Fatalf("missing binary: %+v", o)
	}
}

func TestExecRunnerKeepsStreamsApart(t *testing.T) {
	o := ExecRunner(context.Background(), nil, "sh", "-c", "echo out; echo warn >&2; exit 3")
	if o.Code != 3 || o.Stdout != "out" || o.Stderr != "warn" || o.Combined() != "out\nwarn" {
		t.Fatalf("got %+v", o)
	}
}

func TestExecRunnerKillsGrandchildrenOnTimeout(t *testing.T) {
	marker := fmt.Sprintf("%d.%d", 30+time.Now().Nanosecond()%9, time.Now().Nanosecond())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if o := ExecRunner(ctx, nil, "sh", "-c", "sleep "+marker+" & wait"); o.Code != 124 {
		t.Fatalf("got %+v, want code 124", o)
	}
	time.Sleep(200 * time.Millisecond)
	if out, err := exec.Command("pgrep", "-f", "sleep "+marker).Output(); err == nil {
		t.Fatalf("grandchild survived the timeout: %s", out)
	}
}
