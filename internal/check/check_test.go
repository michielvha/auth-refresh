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

type call struct {
	rc  int
	out string
}

// fakeRunner answers by the command's first two words, e.g. "az account".
func fakeRunner(t *testing.T, answers map[string]call, gotEnv *[]string) Runner {
	t.Helper()
	return func(_ context.Context, env []string, name string, args ...string) (int, string) {
		key := name
		if len(args) > 0 {
			key += " " + args[0]
		}
		if gotEnv != nil {
			*gotEnv = env
		}
		c, ok := answers[key]
		if !ok {
			return 127, "unexpected command " + key
		}
		return c.rc, c.out
	}
}

func deps(t *testing.T, answers map[string]call) Deps {
	return Deps{
		Run:  fakeRunner(t, answers, nil),
		HTTP: func(bool) *http.Client { return http.DefaultClient },
		Home: t.TempDir(),
		Now:  func() time.Time { return time.Date(2026, 10, 22, 2, 0, 0, 0, time.UTC) },
	}
}

func TestCLIIdentities(t *testing.T) {
	aadsts := "WARNING: AADSTS70043: The refresh token has expired\nWARNING: Interactively acquiring token"
	tests := []struct {
		name    string
		id      config.Identity
		answers map[string]call
		want    Status
		detail  string
	}{
		{
			"azure live",
			config.Identity{Name: "az", Type: "azure"},
			map[string]call{"az account": {0, "2026-10-22 13:00:00.000000"}},
			OK, "until 2026-10-22 13:00",
		},
		{
			"azure hangs on expired refresh token",
			config.Identity{Name: "az", Type: "azure"},
			map[string]call{"az account": {124, aadsts}},
			Dead, "AADSTS70043",
		},
		{
			"azure timeout without output",
			config.Identity{Name: "az", Type: "azure"},
			map[string]call{"az account": {124, ""}},
			Dead, "timed out",
		},
		{
			"kube ok",
			config.Identity{Name: "k", Type: "kube", Context: "dev"},
			map[string]call{"kubectl --context": {0, "namespace/default\nnamespace/x"}},
			OK, "context dev",
		},
		{
			"kube dead names parent",
			config.Identity{Name: "k", Type: "kube", Context: "dev", RidesOn: "az"},
			map[string]call{"kubectl --context": {1, "error: token expired"}},
			Dead, "rides on az",
		},
		{
			"gh account present",
			config.Identity{Name: "gh", Type: "gh", Host: "github.com", Account: "me"},
			map[string]call{"gh auth": {1, "Logged in to github.com account me (keyring)\nX other failed"}},
			OK, "me",
		},
		{
			"gh account absent",
			config.Identity{Name: "gh", Type: "gh", Host: "github.com", Account: "me"},
			map[string]call{"gh auth": {0, "Logged in to github.com account other"}},
			Dead, "me not logged in",
		},
		{
			"docker ok",
			config.Identity{Name: "r", Type: "docker", ProbeImage: "reg.example.com/a/b:1"},
			map[string]call{"docker manifest": {0, "{}"}},
			OK, "reg.example.com",
		},
		{
			"docker denied",
			config.Identity{Name: "r", Type: "docker", ProbeImage: "reg.example.com/a/b:1"},
			map[string]call{"docker manifest": {1, "unauthorized"}},
			Dead, "unauthorized",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := One(context.Background(), tt.id, deps(t, tt.answers))
			if r.Status != tt.want || !strings.Contains(r.Detail, tt.detail) {
				t.Fatalf("got %s %q, want %s containing %q", r.Status, r.Detail, tt.want, tt.detail)
			}
		})
	}
}

func TestKubePassesAWSProfile(t *testing.T) {
	var env []string
	d := deps(t, nil)
	d.Run = fakeRunner(t, map[string]call{"kubectl --context": {0, "namespace/a"}}, &env)
	One(context.Background(), config.Identity{Name: "e", Type: "kube", Context: "eks", AWSProfile: "dev"}, d)
	if len(env) != 1 || env[0] != "AWS_PROFILE=dev" {
		t.Fatalf("env = %v", env)
	}
}

func TestAWSSSO(t *testing.T) {
	writeCache := func(t *testing.T, home, expires string) {
		dir := filepath.Join(home, ".aws", "sso", "cache")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		body := `{"accessToken":"x","startUrl":"https://d-1.awsapps.com/start","expiresAt":"` + expires + `"}`
		if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		// A client registration file has no accessToken and must be ignored.
		if err := os.WriteFile(filepath.Join(dir, "reg.json"), []byte(`{"clientId":"c","expiresAt":"2099-01-01T00:00:00Z"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id := config.Identity{Name: "aws", Type: "aws_sso", SSOSession: "s", StartURL: "https://d-1.awsapps.com/start"}

	t.Run("token alive, no probe", func(t *testing.T) {
		d := deps(t, nil)
		writeCache(t, d.Home, "2026-10-22T03:30:00Z")
		r := One(context.Background(), id, d)
		if r.Status != OK || !strings.Contains(r.Detail, "1h30m left") {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("token expired, probe fails", func(t *testing.T) {
		withProbe := id
		withProbe.ProbeProfile = "dev"
		d := deps(t, map[string]call{"aws sts": {255, "Error when retrieving token from sso: Token has expired"}})
		writeCache(t, d.Home, "2026-10-21T00:00:00Z")
		r := One(context.Background(), withProbe, d)
		if r.Status != Dead || !strings.Contains(r.Detail, "expired") {
			t.Fatalf("got %+v", r)
		}
		if r.Fix != "" {
			t.Fatalf("no lane, so no default fix; got %q", r.Fix)
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
	rc, out := ExecRunner(ctx, nil, "sh", "-c", "echo AADSTS70043 expired; sleep 5")
	if rc != 124 || !strings.Contains(out, "AADSTS70043") {
		t.Fatalf("rc=%d out=%q", rc, out)
	}
	if rc, out := ExecRunner(context.Background(), nil, "definitely-not-a-binary-xyz"); rc != 127 {
		t.Fatalf("missing binary: rc=%d out=%q", rc, out)
	}
}

func TestExecRunnerKillsGrandchildrenOnTimeout(t *testing.T) {
	marker := fmt.Sprintf("%d.%d", 30+time.Now().Nanosecond()%9, time.Now().Nanosecond())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if rc, _ := ExecRunner(ctx, nil, "sh", "-c", "sleep "+marker+" & wait"); rc != 124 {
		t.Fatalf("rc=%d, want 124", rc)
	}
	time.Sleep(200 * time.Millisecond)
	if out, err := exec.Command("pgrep", "-f", "sleep "+marker).Output(); err == nil {
		t.Fatalf("grandchild survived the timeout: %s", out)
	}
}
