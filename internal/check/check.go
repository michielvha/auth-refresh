// Package check reports whether each configured identity is still usable.
// It never prints a secret: token files are read only to build a request header.
package check

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // the AWS CLI names its SSO cache files by SHA-1
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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

// Output is what a command printed and how it exited. Stdout and stderr stay
// apart so that warnings on stderr never spoil machine-readable stdout.
type Output struct {
	Code   int
	Stdout string
	Stderr string
}

// Combined returns stdout and stderr together, for error messages.
func (o Output) Combined() string {
	return strings.TrimSpace(strings.TrimSpace(o.Stdout) + "\n" + strings.TrimSpace(o.Stderr))
}

// Runner runs an external command. On timeout it returns the output gathered
// so far and exit code 124; a command that cannot start gets exit code 127.
type Runner func(ctx context.Context, env []string, name string, args ...string) Output

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
func ExecRunner(ctx context.Context, env []string, name string, args ...string) Output {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	o := Output{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String())}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		o.Code = 124
		return o
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		o.Code = ee.ExitCode()
	default:
		o.Code, o.Stderr = 127, err.Error()
	}
	return o
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
	r := Result{Name: id.Name, Status: st, Detail: detail, Lane: id.Lane}
	// A fix is only offered for an identity that is actually dead: a WARN
	// (RBAC, outage, timeout) must never send anyone into a login.
	if r.Bad() {
		r.Fix = id.Fix
		if r.Fix == "" && id.Lane != "" {
			r.Fix = "start " + id.Name
		}
	}
	return r
}

func runT(ctx context.Context, d Deps, timeout time.Duration, env []string, name string, args ...string) Output {
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

var (
	aadstsRe            = regexp.MustCompile(`AADSTS\d+`)
	azureAuthRe         = regexp.MustCompile(`(?i)AADSTS(?:70043|700082|700084|50058|50173|50076)|refresh token.*expired|please run.*az login|invalid_grant|interaction_required`)
	transportRe         = regexp.MustCompile(`(?i)timed? out|timeout|unreachable|failed to connect|could not connect|connection (?:refused|reset)|no such host|name resolution|failed to resolve|service unavailable|serviceunavailable|tls|x509|dial tcp|throttl|rate limit`)
	authenticationRe    = regexp.MustCompile(`(?i)unauthorized|authentication required|invalid.*token|token.*invalid|token.*expired|bad credentials|not logged in|status code: 401|HTTP 401`)
	setupOrPermissionRe = regexp.MustCompile(`(?i)accessdenied|forbidden|permission denied|invalidconfig|profile.*not.*found|not configured|invalid choice|unknown option`)
)

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
	o := runT(ctx, d, 25*time.Second, nil, "az", args...)
	rc, out := o.Code, o.Combined()
	if rc != 0 {
		why := aadstsRe.FindString(out)
		if why == "" {
			why = lastLine(out, 90)
		}
		if rc == 124 && why == "" {
			why = "timed out"
		}
		if azureAuthRe.MatchString(out) {
			return Dead, fmt.Sprintf("needs `start %s` (last login %s): %s", id.Name, last, why)
		}
		return Warn, fmt.Sprintf("probe failed, not recognised as an auth failure (last login %s): %s", last, why)
	}
	return OK, fmt.Sprintf("access token until %s (last login %s)", lastLine(o.Stdout, 40), last)
}

// ssoCacheFile is where the AWS CLI caches the token of an sso-session:
// ~/.aws/sso/cache/<sha1 of the session name>.json (botocore SSOTokenLoader).
func ssoCacheFile(home, session string) string {
	sum := sha1.Sum([]byte(session)) //nolint:gosec // the AWS CLI's cache key, not a security use
	return filepath.Join(home, ".aws", "sso", "cache", hex.EncodeToString(sum[:])+".json")
}

func normStartURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/#") }

// ssoToken reads the cached token of id's sso-session. alive is false with a
// reason for a missing, malformed, foreign or expired token.
func ssoToken(id config.Identity, d Deps) (alive bool, detail string) {
	file := ssoCacheFile(d.Home, id.SSOSession)
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return false, fmt.Sprintf("no SSO token cached for sso_session %s", id.SSOSession)
	}
	if err != nil {
		return false, fmt.Sprintf("cannot read SSO cache %s: %v", filepath.Base(file), err)
	}
	var c struct {
		AccessToken string `json:"accessToken"`
		StartURL    string `json:"startUrl"`
		ExpiresAt   string `json:"expiresAt"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return false, fmt.Sprintf("SSO cache %s is malformed: %v", filepath.Base(file), err)
	}
	if c.AccessToken == "" || c.ExpiresAt == "" {
		return false, fmt.Sprintf("SSO cache %s has no accessToken/expiresAt", filepath.Base(file))
	}
	if id.StartURL != "" && normStartURL(c.StartURL) != normStartURL(id.StartURL) {
		return false, fmt.Sprintf("SSO cache for sso_session %s is for start URL %s, config says %s", id.SSOSession, c.StartURL, id.StartURL)
	}
	left, alive := until(c.ExpiresAt, d.Now())
	if !alive && left != "expired" {
		return false, fmt.Sprintf("SSO cache %s has an unreadable expiresAt %q", filepath.Base(file), c.ExpiresAt)
	}
	return alive, "SSO token " + left
}

var (
	awsAuthRe = regexp.MustCompile(`(?i)token (?:has )?expired|expiredtoken|error loading sso token|sso session .*(?:expired|invalid)|unauthorizedssotoken|invalid_grant|invalidgrant|refresh failed|aws sso login`)
	awsNetRe  = regexp.MustCompile(`(?i)could not connect to the endpoint|connect timeout|read timeout|connection (?:refused|reset)|name resolution|temporary failure|max retries exceeded|serviceunavailable|throttl`)
)

func awsSSO(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	if id.ProbeProfile == "" {
		alive, sso := ssoToken(id, d)
		if alive {
			return OK, sso
		}
		return Dead, sso
	}
	// The probe first: a successful call may refresh the cached token.
	o := runT(ctx, d, 25*time.Second, nil, "aws", "sts", "get-caller-identity",
		"--profile", id.ProbeProfile, "--query", "Arn", "--output", "text")
	alive, sso := ssoToken(id, d)
	if o.Code == 0 {
		return OK, fmt.Sprintf("%s -> %s; %s", id.ProbeProfile, lastLine(o.Stdout, 120), sso)
	}
	why := lastLine(o.Combined(), 90)
	if o.Code == 124 {
		why = "timed out"
	}
	switch {
	case setupOrPermissionRe.MatchString(o.Combined()):
		return Warn, fmt.Sprintf("%s probe failed, not recognised as an auth failure: %s; %s", id.ProbeProfile, why, sso)
	case awsAuthRe.MatchString(o.Combined()):
		return Dead, fmt.Sprintf("%s: %s; %s", id.ProbeProfile, why, sso)
	case o.Code == 124 || awsNetRe.MatchString(o.Combined()):
		return Warn, fmt.Sprintf("%s unreachable, not an auth failure: %s; %s", id.ProbeProfile, why, sso)
	case !alive:
		return Dead, fmt.Sprintf("%s: %s; %s", id.ProbeProfile, why, sso)
	}
	return Warn, fmt.Sprintf("%s probe failed, not recognised as an auth failure: %s; %s", id.ProbeProfile, why, sso)
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

// Order matters: kubectl wraps a failed credential plugin in "Unable to connect
// to the server", so auth is matched before network; an expired *server*
// certificate (x509) is not a login problem, so it is matched first.
var (
	kubeTLSRe         = regexp.MustCompile(`(?i)x509:|certificate (?:has expired|signed by unknown)`)
	kubeAuthRe        = regexp.MustCompile(`(?i)\(unauthorized\)|\bunauthorized\b|must be logged in|asked for the client to provide credentials|getting credentials|exec plugin|executable \S+ failed|AADSTS\d+|invalid_grant|token (?:has )?expired|expired token|sso token|refresh token`)
	kubeForbiddenRe   = regexp.MustCompile(`(?i)\(forbidden\)|\bis forbidden\b`)
	kubeUnsupportedRe = regexp.MustCompile(`(?i)unknown command "whoami"|doesn't have a resource type|could not find the requested resource|\(notfound\)`)
	kubeNetRe         = regexp.MustCompile(`(?i)unable to connect to the server|dial tcp|i/o timeout|no such host|connection refused|connection reset|tls handshake timeout|context deadline exceeded|serviceunavailable|service unavailable|internalerror|internal error|bad gateway|gateway timeout|currently unable to handle`)
)

// kube asks the API server who the context authenticates as (SelfSubjectReview,
// GA since Kubernetes 1.28). Only an authentication failure is DEAD; RBAC,
// outages and an unsupported probe are WARN and never trigger a login.
func kube(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	var env []string
	if id.AWSProfile != "" {
		env = []string{"AWS_PROFILE=" + id.AWSProfile}
	}
	o := runT(ctx, d, 45*time.Second, env, "kubectl", "--context", id.Context,
		"auth", "whoami", "-o", "json", "--request-timeout=30s")
	if o.Code == 0 {
		var r struct {
			Status struct {
				UserInfo struct {
					Username string `json:"username"`
				} `json:"userInfo"`
			} `json:"status"`
		}
		if json.Unmarshal([]byte(o.Stdout), &r) == nil && r.Status.UserInfo.Username != "" {
			return OK, fmt.Sprintf("context %s as %s", id.Context, r.Status.UserInfo.Username)
		}
		return OK, "context " + id.Context
	}
	rides := id.RidesOn
	if rides == "" {
		rides = "?"
	}
	all := o.Combined()
	why := firstErrorLine(all, 100)
	switch {
	case o.Code == 124:
		return Warn, fmt.Sprintf("context %s: timed out, network or a credential plugin waiting for input; check %s", id.Context, rides)
	case kubeTLSRe.MatchString(all):
		return Warn, fmt.Sprintf("context %s: TLS problem, not a login: %s", id.Context, why)
	case strings.Contains(all, "executable") && (strings.Contains(all, "not found") || strings.Contains(all, "permission denied")):
		return Warn, "credential plugin setup problem: " + why
	case kubeAuthRe.MatchString(all):
		return Dead, fmt.Sprintf("context %s: %s (rides on %s)", id.Context, why, rides)
	case kubeForbiddenRe.MatchString(all):
		return Warn, fmt.Sprintf("context %s: authenticated, but RBAC forbids the probe; not a login: %s", id.Context, why)
	case kubeUnsupportedRe.MatchString(all):
		return Warn, fmt.Sprintf("context %s: cannot tell, `kubectl auth whoami` needs kubectl and cluster >= 1.28: %s", id.Context, why)
	case kubeNetRe.MatchString(all):
		return Warn, fmt.Sprintf("context %s: unreachable, not an auth failure: %s", id.Context, why)
	}
	return Warn, fmt.Sprintf("context %s: probe failed, not recognised as an auth failure: %s", id.Context, why)
}

// firstErrorLine prefers a line that looks like an error over leading warnings.
func firstErrorLine(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	pick := lines[0]
	for _, l := range lines {
		if ll := strings.ToLower(l); strings.HasPrefix(ll, "error") || strings.HasPrefix(ll, "unable") || strings.Contains(ll, "error from server") {
			pick = l
			break
		}
	}
	pick = strings.TrimSpace(pick)
	if len(pick) > n {
		pick = pick[:n]
	}
	return pick
}

type ghEntry struct {
	State  string `json:"state"`
	Error  string `json:"error"`
	Active bool   `json:"active"`
	Host   string `json:"host"`
	Login  string `json:"login"`
}

// gh prefers `gh auth status --json hosts` (newer gh; it exits 0 regardless of
// auth problems, so the per-account state decides) and falls back to matching
// one exact success line when an older gh has no --json.
func gh(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	o := runT(ctx, d, 20*time.Second, nil, "gh", "auth", "status", "--json", "hosts", "--hostname", id.Host)
	if o.Code == 124 {
		return Warn, "gh auth status timed out, not an auth failure"
	}
	var js struct {
		Hosts map[string][]ghEntry `json:"hosts"`
	}
	if json.Unmarshal([]byte(o.Stdout), &js) == nil && js.Hosts != nil {
		return ghFromJSON(id, js.Hosts[id.Host])
	}
	o = runT(ctx, d, 20*time.Second, nil, "gh", "auth", "status", "--hostname", id.Host)
	if o.Code == 124 {
		return Warn, "gh auth status timed out, not an auth failure"
	}
	return ghFromText(id, o)
}

func ghFromJSON(id config.Identity, entries []ghEntry) (Status, string) {
	var e *ghEntry
	for i := range entries {
		if (id.Account != "" && entries[i].Login == id.Account) || (id.Account == "" && entries[i].Active) {
			e = &entries[i]
			break
		}
	}
	if e == nil {
		if id.Account == "" {
			return Dead, "not logged in on " + id.Host
		}
		return Dead, fmt.Sprintf("%s not logged in on %s", id.Account, id.Host)
	}
	who := e.Login
	if who == "" {
		who = "token"
	}
	switch e.State {
	case "success":
		if !e.Active {
			return OK, who + " (logged in, not the active account)"
		}
		return OK, who
	case "timeout":
		return Warn, fmt.Sprintf("%s on %s: timed out, not an auth failure", who, id.Host)
	}
	if transportRe.MatchString(e.Error) {
		return Warn, fmt.Sprintf("%s on %s: service unavailable, not a login", who, id.Host)
	}
	if authenticationRe.MatchString(e.Error) {
		return Dead, fmt.Sprintf("%s on %s: %s", who, id.Host, lastLine(strings.SplitN(e.Error, "\n", 2)[0], 90))
	}
	return Warn, fmt.Sprintf("%s on %s: cannot establish authentication: %s", who, id.Host, lastLine(strings.SplitN(e.Error, "\n", 2)[0], 90))
}

func ghFromText(id config.Identity, o Output) (Status, string) {
	all := o.Combined()
	if transportRe.MatchString(all) {
		return Warn, "GitHub unreachable, not an auth failure"
	}
	host := regexp.QuoteMeta(id.Host)
	acct := `\S+`
	if id.Account != "" {
		acct = regexp.QuoteMeta(id.Account)
	}
	// gh >= 2.40: "✓ Logged in to HOST account LOGIN (source)"; older: "... as LOGIN (source)".
	okRe := regexp.MustCompile(`(?m)^\s*✓ Logged in to ` + host + ` (?:account|as) ` + acct + ` \(`)
	if okRe.MatchString(all) {
		if id.Account != "" {
			return OK, id.Account
		}
		return OK, "logged in on " + id.Host
	}
	if !authenticationRe.MatchString(all) && !strings.Contains(all, "Logged in to ") && !strings.Contains(all, "not logged into") {
		return Warn, "unrecognised GitHub probe output; not a login"
	}
	if id.Account == "" {
		return Dead, lastLine(all, 90)
	}
	return Dead, fmt.Sprintf("%s not logged in on %s", id.Account, id.Host)
}

func docker(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	o := runT(ctx, d, 30*time.Second, nil, "docker", "manifest", "inspect", id.ProbeImage)
	if o.Code == 0 {
		return OK, strings.SplitN(id.ProbeImage, "/", 2)[0]
	}
	if o.Code != 124 && authenticationRe.MatchString(o.Combined()) {
		return Dead, lastLine(o.Combined(), 100)
	}
	return Warn, "registry probe failed, not recognised as an auth failure: " + lastLine(o.Combined(), 100)
}

func httpToken(ctx context.Context, id config.Identity, d Deps) (Status, string) {
	st, err := os.Stat(id.File)
	if errors.Is(err, os.ErrNotExist) {
		return Missing, "no token at " + id.File
	}
	if err != nil {
		return Warn, "cannot inspect token file"
	}
	raw, err := os.ReadFile(id.File)
	if err != nil {
		return Warn, fmt.Sprintf("cannot read %s: %v", id.File, err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return Missing, "empty token file"
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
		return Warn, "unreachable: " + body + warn
	}
	if code == http.StatusUnauthorized {
		return Dead, fmt.Sprintf("HTTP %d, rejected%s", code, warn)
	}
	if code == http.StatusOK && strings.Contains(strings.ReplaceAll(body, " ", ""), `"valid":false`) {
		return Dead, "token rejected" + warn
	}
	return Warn, fmt.Sprintf("HTTP %d, cannot establish token validity%s", code, warn)
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
	return Warn, fmt.Sprintf("HTTP %d %s (service health, not a login)", code, id.URL)
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
	b, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return 0, "incomplete HTTP response"
	}
	return resp.StatusCode, string(b)
}
