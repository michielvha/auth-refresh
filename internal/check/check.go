// Package check reports whether each configured identity is still usable.
// It never prints a secret: token files are read only to build a request header.
package check

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
)

// Status of one identity.
type Status string

// Statuses, from good to bad.
const (
	OK      Status = "OK"
	Warn    Status = "WARN"
	Dead    Status = "DEAD"
	Missing Status = "MISSING"
)

// Result is one line of the report.
type Result struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Lane   string `json:"lane,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Bad reports whether the identity needs action.
func (r Result) Bad() bool { return r.Status == Dead || r.Status == Missing }

// Runner runs an external command and returns its exit code and combined output.
// On timeout it returns the output gathered so far and exit code 124.
type Runner func(ctx context.Context, env []string, name string, args ...string) (int, string)

// Deps are the side effects a checker may use.
type Deps struct {
	Run   Runner
	HTTP  func(verifyTLS bool) *http.Client
	Home  string
	Now   func() time.Time
	Which func(string) (string, error)
}

// DefaultDeps uses the real OS.
func DefaultDeps() Deps {
	home, _ := os.UserHomeDir()
	return Deps{Run: ExecRunner, HTTP: httpClient, Home: home, Now: time.Now, Which: exec.LookPath}
}

// ExecRunner is the production Runner. Each command gets its own process group
// and a timeout kills the whole group: kubectl's exec plugin (kubelogin -> az)
// otherwise outlives it, stuck on az's interactive fallback forever.
func ExecRunner(ctx context.Context, env []string, name string, args ...string) (int, string) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = nil
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return 124, out
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out
	case errors.As(err, &ee):
		return ee.ExitCode(), out
	default:
		return 127, err.Error()
	}
}

func httpClient(verify bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !verify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in per identity for TLS-intercepting proxies
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

// binaryFor names the CLI each identity type shells out to.
var binaryFor = map[string]string{"azure": "az", "aws_sso": "aws", "kube": "kubectl", "gh": "gh", "docker": "docker"}

// MissingBinaries lists required CLIs not on PATH. A missing binary is a host
// fault, never an expired credential, so callers must stop before any login.
func MissingBinaries(cfg *config.Config, which func(string) (string, error)) []string {
	want := map[string]bool{}
	for _, b := range cfg.RequiredBinaries {
		want[b] = true
	}
	for _, id := range cfg.Identities {
		if b, ok := binaryFor[id.Type]; ok {
			want[b] = true
		}
	}
	var missing []string
	for b := range want {
		if _, err := which(b); err != nil {
			missing = append(missing, b)
		}
	}
	slices.Sort(missing)
	return missing
}

// All checks every identity concurrently and returns results in config order.
func All(ctx context.Context, cfg *config.Config, d Deps) []Result {
	out := make([]Result, len(cfg.Identities))
	var wg sync.WaitGroup
	for i, id := range cfg.Identities {
		wg.Go(func() { out[i] = One(ctx, id, d) })
	}
	wg.Wait()
	return out
}

// One checks a single identity.
func One(ctx context.Context, id config.Identity, d Deps) Result {
	var st Status
	var detail string
	switch id.Type {
	case "azure":
		st, detail = azure(ctx, id, d)
	case "aws_sso":
		st, detail = awsSSO(ctx, id, d)
	case "kube":
		st, detail = kube(ctx, id, d)
	case "gh":
		st, detail = gh(ctx, id, d)
	case "docker":
		st, detail = docker(ctx, id, d)
	case "http_token":
		st, detail = httpToken(ctx, id, d)
	case "http_up":
		st, detail = httpUp(ctx, id, d)
	default:
		st, detail = Warn, "unknown type "+id.Type
	}
	fix := id.Fix
	if fix == "" && id.Lane != "" {
		fix = "start " + id.Name
	}
	return Result{Name: id.Name, Status: st, Detail: detail, Lane: id.Lane, Fix: fix}
}

func runT(ctx context.Context, d Deps, timeout time.Duration, env []string, name string, args ...string) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.Run(ctx, env, name, args...)
}

func lastLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > n {
		s = s[:n]
	}
	return s
}

var aadstsRe = regexp.MustCompile(`AADSTS\d+`)

func azure(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	last := "never"
	if st, err := os.Stat(filepath.Join(d.Home, ".azure", "azureProfile.json")); err == nil {
		last = st.ModTime().Format("2006-01-02 15:04")
	}
	args := []string{"account", "get-access-token", "--query", "expiresOn", "-o", "tsv"}
	if id.Tenant != "" {
		args = append(args, "--tenant", id.Tenant)
	}
	// On an expired refresh token newer az does not exit: it falls back to an
	// interactive browser login and blocks. So bound it and read the AADSTS code.
	rc, out := runT(ctx, d, 25*time.Second, nil, "az", args...)
	if rc != 0 {
		why := aadstsRe.FindString(out)
		if why == "" {
			why = lastLine(out, 90)
		}
		if rc == 124 && why == "" {
			why = "timed out"
		}
		return Dead, fmt.Sprintf("needs `start %s` (last login %s): %s", id.Name, last, why)
	}
	return OK, fmt.Sprintf("access token until %s (last login %s)", lastLine(out, 40), last)
}

func awsSSO(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	var best string
	files, _ := filepath.Glob(filepath.Join(d.Home, ".aws", "sso", "cache", "*.json"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var c struct {
			AccessToken string `json:"accessToken"`
			StartURL    string `json:"startUrl"`
			ExpiresAt   string `json:"expiresAt"`
		}
		if json.Unmarshal(raw, &c) != nil || c.AccessToken == "" {
			continue
		}
		if id.StartURL != "" && c.StartURL != id.StartURL {
			continue
		}
		if c.ExpiresAt > best {
			best = c.ExpiresAt
		}
	}
	sso := "no SSO token cached"
	alive := false
	if best != "" {
		var left string
		left, alive = until(best, d.Now())
		sso = "SSO token " + left
	}
	if id.ProbeProfile == "" {
		if alive {
			return OK, sso
		}
		return Dead, sso
	}
	rc, out := runT(ctx, d, 25*time.Second, nil, "aws", "sts", "get-caller-identity",
		"--profile", id.ProbeProfile, "--query", "Arn", "--output", "text")
	if rc == 0 {
		return OK, fmt.Sprintf("%s -> %s; %s", id.ProbeProfile, lastLine(out, 120), sso)
	}
	return Dead, fmt.Sprintf("%s: %s; %s", id.ProbeProfile, lastLine(out, 90), sso)
}

func until(iso string, now time.Time) (string, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05UTC", "2006-01-02T15:04:05Z07:00"} {
		t, err := time.Parse(layout, iso)
		if err != nil {
			continue
		}
		left := t.Sub(now)
		if left <= 0 {
			return "expired", false
		}
		return fmt.Sprintf("%dh%02dm left", int(left.Hours()), int(left.Minutes())%60), true
	}
	return iso, false
}

func kube(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	var env []string
	if id.AWSProfile != "" {
		env = []string{"AWS_PROFILE=" + id.AWSProfile}
	}
	rc, out := runT(ctx, d, 45*time.Second, env, "kubectl", "--context", id.Context,
		"get", "ns", "-o", "name", "--request-timeout=30s")
	if rc == 0 && strings.HasPrefix(out, "namespace/") {
		return OK, "context " + id.Context
	}
	rides := id.RidesOn
	if rides == "" {
		rides = "?"
	}
	why := strings.SplitN(out, "\n", 2)[0]
	if rc == 124 {
		why = "timed out"
	}
	if len(why) > 100 {
		why = why[:100]
	}
	return Dead, fmt.Sprintf("context %s: %s (rides on %s)", id.Context, why, rides)
}

func gh(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	rc, out := runT(ctx, d, 20*time.Second, nil, "gh", "auth", "status", "-h", id.Host)
	if id.Account != "" {
		if strings.Contains(out, "account "+id.Account) {
			return OK, id.Account
		}
		return Dead, fmt.Sprintf("%s not logged in on %s", id.Account, id.Host)
	}
	if rc == 0 {
		return OK, "logged in on " + id.Host
	}
	return Dead, lastLine(out, 90)
}

func docker(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	rc, out := runT(ctx, d, 30*time.Second, nil, "docker", "manifest", "inspect", id.ProbeImage)
	if rc == 0 {
		return OK, strings.SplitN(id.ProbeImage, "/", 2)[0]
	}
	return Dead, lastLine(out, 100)
}

func httpToken(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	st, err := os.Stat(id.File)
	if err != nil {
		return Missing, "no token at " + id.File
	}
	raw, err := os.ReadFile(id.File)
	if err != nil {
		return Missing, fmt.Sprintf("cannot read %s: %v", id.File, err)
	}
	header := authHeader(id.Auth, strings.TrimSpace(string(raw)))
	var code int
	var body string
	for range id.Retries {
		code, body = get(ctx, d, id.URL, header, id.TLSVerify())
		if code != 0 {
			break
		}
	}
	warn := ""
	if st.Mode().Perm()&0o077 != 0 {
		warn = fmt.Sprintf(" (file mode %#o, should be 0600)", st.Mode().Perm())
	}
	if code == http.StatusOK && strings.Contains(body, id.Expect) {
		if warn != "" {
			return Warn, "valid" + warn
		}
		return OK, "valid"
	}
	if code == 0 {
		return Dead, "unreachable: " + body + warn
	}
	return Dead, fmt.Sprintf("HTTP %d, rejected%s", code, warn)
}

func authHeader(scheme, tok string) string {
	switch scheme {
	case "basic_user": // token as username, empty password (SonarQube)
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(tok+":"))
	case "basic_pass": // empty username, token as password (Azure DevOps PAT)
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+tok))
	default:
		return "Bearer " + tok
	}
}

func httpUp(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	code, _ := get(ctx, d, id.URL, "", id.TLSVerify())
	if code == id.ExpectStatus {
		return OK, fmt.Sprintf("HTTP %d %s", code, id.URL)
	}
	return Dead, fmt.Sprintf("HTTP %d %s", code, id.URL)
}

// get returns status 0 and a short reason on a transport failure.
func get(ctx context.Context, d Deps, url, auth string, verify bool) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err.Error()
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := d.HTTP(verify).Do(req)
	if err != nil {
		msg := err.Error()
		if len(msg) > 120 {
			msg = msg[:120]
		}
		return 0, msg
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b)
}
