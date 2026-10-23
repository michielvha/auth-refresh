package check

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/michielvha/auth-refresh/internal/config"
)

func TestWrappedCredentialPluginFailuresDoNotOfferLogin(t *testing.T) {
	id := config.Identity{Name: "kube", Type: "kube", Context: "fixture", RidesOn: "azure", Lane: "admin"}
	const wrapper = "\nUnable to connect to the server: getting credentials: exec: executable kubelogin failed with exit code 1"
	for _, tc := range []struct {
		name   string
		output string
	}{
		{"network", "Could not connect to the endpoint URL: https://oidc.example.invalid/token"},
		{"permission", "ERROR: Permission denied reading cache"},
		{"policy", "AADSTS53003: Access blocked by Conditional Access policies"},
		{"unknown cause", "credential plugin stopped unexpectedly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := One(context.Background(), id, deps(t, map[string]Output{"kubectl": {Code: 1, Stderr: tc.output + wrapper}}))
			if r.Status != Warn || r.Fix != "" {
				t.Fatalf("got %+v, want WARN without a login fix", r)
			}
		})
	}
}

func TestAWSCertificateFailureDoesNotOfferLogin(t *testing.T) {
	id := config.Identity{Name: "aws", Type: "aws_sso", SSOSession: "fixture", ProbeProfile: "fixture", Lane: "admin"}
	for _, expiredCache := range []bool{false, true} {
		name := "missing cache"
		if expiredCache {
			name = "expired cache"
		}
		t.Run(name, func(t *testing.T) {
			d := deps(t, map[string]Output{"aws sts": {Code: 1, Stderr: "SSL validation failed for https://sts.example.invalid/ [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"}})
			if expiredCache {
				file := ssoCacheFile(d.Home, id.SSOSession)
				if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(`{"accessToken":"fixture","expiresAt":"2026-10-21T00:00:00Z"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r := One(context.Background(), id, d)
			if r.Status != Warn || r.Fix != "" {
				t.Fatalf("got %+v, want WARN without a login fix", r)
			}
		})
	}
}
