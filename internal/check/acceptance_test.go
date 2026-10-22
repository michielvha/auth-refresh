package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/michielvha/auth-refresh/internal/config"
)

// These acceptance cases run through a Go overlay in the standalone component.
// They use its production One entry point and its existing fake CLI runner.
func TestProviderCLIProbeFailures(t *testing.T) {
	runCases(t, []cliCase{
		{"azure silent timeout", config.Identity{Name: "az", Type: "azure", Lane: "admin"}, map[string]Output{"az account": {Code: 124}}, Warn, ""},
		{"azure DNS failure", config.Identity{Name: "az", Type: "azure", Lane: "admin"}, map[string]Output{"az account": {Code: 1, Stderr: "Failed to resolve login.example.invalid"}}, Warn, ""},
		{"azure permission failure", config.Identity{Name: "az", Type: "azure", Lane: "admin"}, map[string]Output{"az account": {Code: 1, Stderr: "Permission denied reading local cache"}}, Warn, ""},
		{"azure expired refresh token", config.Identity{Name: "az", Type: "azure", Lane: "admin"}, map[string]Output{"az account": {Code: 1, Stderr: "AADSTS70043: The refresh token has expired"}}, Dead, "AADSTS70043"},
		{"azure conditional access", config.Identity{Name: "az", Type: "azure", Lane: "admin"}, map[string]Output{"az account": {Code: 1, Stderr: "AADSTS53003: Access blocked by Conditional Access policies"}}, Warn, ""},
		{"AWS transport failure with missing SSO cache", config.Identity{Name: "aws", Type: "aws_sso", Lane: "admin", SSOSession: "test", ProbeProfile: "test"}, map[string]Output{"aws sts": {Code: 1, Stderr: "Could not connect to the endpoint URL"}}, Warn, ""},
		{"kube missing credential executable", config.Identity{Name: "aks", Type: "kube", RidesOn: "az", Fix: "start az", Context: "test"}, map[string]Output{"kubectl": {Code: 1, Stderr: "getting credentials: exec: executable kubelogin not found"}}, Warn, ""},
		{"kube expired credential", config.Identity{Name: "aks", Type: "kube", RidesOn: "az", Fix: "start az", Context: "test"}, map[string]Output{"kubectl": {Code: 1, Stderr: "AADSTS70043: The refresh token has expired"}}, Dead, "AADSTS70043"},
		{"GitHub service outage", config.Identity{Name: "gh", Type: "gh", Host: "github.com", Account: "fixture", Fix: "gh auth login --web"}, map[string]Output{"gh auth status --json": {Stdout: `{"hosts":{"github.com":[{"state":"error","error":"failed to connect to github.com: service unavailable","active":true,"login":"fixture"}]}}`}}, Warn, ""},
		{"GitHub timeout", config.Identity{Name: "gh", Type: "gh", Host: "github.com", Account: "fixture", Fix: "gh auth login --web"}, map[string]Output{"gh auth status --json": {Code: 124}}, Warn, ""},
		{"registry timeout", config.Identity{Name: "registry", Type: "docker", ProbeImage: "registry.example.invalid/a:1", Fix: "docker login"}, map[string]Output{"docker manifest": {Code: 124}}, Warn, ""},
		{"registry DNS failure", config.Identity{Name: "registry", Type: "docker", ProbeImage: "registry.example.invalid/a:1", Fix: "docker login"}, map[string]Output{"docker manifest": {Code: 1, Stderr: "dial tcp: lookup registry.example.invalid: no such host"}}, Warn, ""},
		{"registry authorization failure", config.Identity{Name: "registry", Type: "docker", ProbeImage: "registry.example.invalid/a:1", Fix: "docker login"}, map[string]Output{"docker manifest": {Code: 1, Stderr: "denied: requested access to the resource is denied"}}, Warn, ""},
		{"registry authentication failure", config.Identity{Name: "registry", Type: "docker", ProbeImage: "registry.example.invalid/a:1", Fix: "docker login"}, map[string]Output{"docker manifest": {Code: 1, Stderr: "unauthorized: authentication required"}}, Dead, "unauthorized"},
	})
}

func TestProviderHTTPProbeFailures(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("fixture-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		code int
		body string
		want Status
	}{
		{"valid token", 200, `{"valid":true}`, OK},
		{"rejected token", 401, "unauthorized", Dead},
		{"permission failure", 403, "forbidden", Warn},
		{"throttling", 429, "rate limited", Warn},
		{"service outage", 503, "unavailable", Warn},
		{"unexpected success body", 200, "unexpected response", Warn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			id := config.Identity{Name: "pat", Type: "http_token", File: file, URL: srv.URL, Expect: `"valid":true`, Retries: 1, Fix: "person renews token"}
			r := One(context.Background(), id, deps(t, nil))
			if r.Status != tc.want || (tc.want == Warn && r.Fix != "") {
				t.Fatalf("got %+v, want %s with no fix on warnings", r, tc.want)
			}
		})
	}
	t.Run("transport failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.Close()
		for _, kind := range []string{"http_token", "http_up"} {
			id := config.Identity{Name: "service", Type: kind, File: file, URL: srv.URL, ExpectStatus: 200, Retries: 1, Fix: "start service"}
			r := One(context.Background(), id, deps(t, nil))
			if r.Status != Warn || r.Fix != "" {
				t.Errorf("%s got %+v, want WARN without a login fix", kind, r)
			}
		}
	})
}
