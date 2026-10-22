package lane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
	"github.com/michielvha/auth-refresh/internal/creds"
	"github.com/mxschmitt/playwright-go"
)

const (
	actionTimeout = 15000.0
	peekBudget    = 3 * time.Second
)

// Install downloads the pinned Playwright driver (playwright-core plus the
// Node.js runtime it needs) and the Chromium headless shell into the current
// user's cache. It installs no system libraries and needs no root.
func Install() error {
	return playwright.Install(&playwright.RunOptions{
		Browsers: []string{"chromium"}, OnlyInstallShell: true, Verbose: false,
	})
}

// DriverVersion is the Playwright driver version this binary is pinned to.
func DriverVersion() string {
	d, err := playwright.NewDriver(&playwright.RunOptions{Verbose: false})
	if err != nil {
		return "unknown"
	}
	return d.Version
}

// DriverDir is where playwright-go looks for the driver: PLAYWRIGHT_DRIVER_PATH,
// else <user cache>/ms-playwright-go/<version> (~/.cache on Linux, as
// playwright-go computes it, independent of XDG_CACHE_HOME).
func DriverDir() (string, error) {
	if p := os.Getenv("PLAYWRIGHT_DRIVER_PATH"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(home, ".cache")
	if runtime.GOOS == "darwin" {
		base = filepath.Join(home, "Library", "Caches")
	}
	return filepath.Join(base, "ms-playwright-go", DriverVersion()), nil
}

// CheckDriver reports whether the pinned driver is on disk, without starting
// it or creating anything.
func CheckDriver() (string, error) {
	dir, err := DriverDir()
	if err != nil {
		return "", err
	}
	cli := filepath.Join(dir, "package", "cli.js")
	if p := os.Getenv("PLAYWRIGHT_CLI_PATH"); p != "" {
		cli = p
	}
	if _, err := os.Stat(cli); err != nil {
		return dir, fmt.Errorf("playwright driver %s is not installed (%s missing): run `auth-refresh setup`", DriverVersion(), cli)
	}
	return dir, nil
}

// Probe starts the pinned driver and launches the headless Chromium once, the
// same way a lane does, and reports what ran. It gives up after timeout.
//
// The attempt runs in a helper subprocess (this executable, re-run with
// probeHelperEnv set; see RunProbeHelperIfRequested) so that a timeout can end
// everything it started: the helper, the Node.js driver and every Chromium
// process, which a goroutine could not guarantee.
func Probe(timeout time.Duration, chromiumArgs []string) (string, error) {
	if _, err := CheckDriver(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	detail, err := probeInHelper(ctx, chromiumArgs)
	if err != nil && ctx.Err() != nil {
		return "", fmt.Errorf("playwright driver or chromium did not start within %s", timeout)
	}
	return detail, err
}

const (
	probeHelperEnv = "AUTH_REFRESH_PROBE_HELPER"
	probeArgsEnv   = "AUTH_REFRESH_PROBE_ARGS"
)

type probeResult struct {
	Detail string `json:"detail"`
	Error  string `json:"error,omitempty"`
}

// probeInHelper runs one probe in a helper subprocess in its own process
// group. When ctx ends first, the helper and all its descendants are killed
// and reaped before it returns.
func probeInHelper(ctx context.Context, chromiumArgs []string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("probe: find own executable: %w", err)
	}
	args, err := json.Marshal(chromiumArgs)
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), probeHelperEnv+"=1", probeArgsEnv+"="+string(args))
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = helperSysProcAttr()
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("probe: start helper: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		killTree(cmd.Process.Pid, true)
		<-done
		return "", ctx.Err()
	}
	var r probeResult
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[len(msg)-500:]
		}
		return "", fmt.Errorf("probe helper failed (%v): %s", waitErr, msg)
	}
	if r.Error != "" {
		return "", errors.New(r.Error)
	}
	return r.Detail, nil
}

// RunProbeHelperIfRequested turns this process into Probe's helper when Probe
// started it, and then exits; otherwise it returns at once. Call it first in
// main (and in TestMain of any test binary whose tests reach Probe).
func RunProbeHelperIfRequested() {
	if os.Getenv(probeHelperEnv) == "1" {
		runProbeHelper(nil)
	}
}

// runProbeHelper probes and writes the result as one JSON line to stdout.
// afterLaunch, for tests, runs while the browser is up.
func runProbeHelper(afterLaunch func()) {
	becomeSubreaper()
	var args []string
	_ = json.Unmarshal([]byte(os.Getenv(probeArgsEnv)), &args)
	var r probeResult
	dir, err := CheckDriver()
	if err == nil {
		r.Detail, err = probe(dir, args, afterLaunch)
	}
	if err != nil {
		r.Error = err.Error()
	}
	killTree(os.Getpid(), false)
	b, _ := json.Marshal(r)
	_, _ = os.Stdout.Write(append(b, '\n'))
	os.Exit(0)
}

func probe(dir string, chromiumArgs []string, afterLaunch func()) (string, error) {
	pw, err := playwright.Run(&playwright.RunOptions{Browsers: []string{"chromium"}, Verbose: false})
	if err != nil {
		return "", fmt.Errorf("start playwright driver %s from %s: %s", DriverVersion(), dir, shortErr(err))
	}
	defer func() { _ = pw.Stop() }()
	b, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(true), Args: chromiumArgs})
	if err != nil {
		return "", fmt.Errorf("launch chromium headless shell (run `auth-refresh setup`; on a fresh OS install its system libraries, see README): %s", shortErr(err))
	}
	v := b.Version()
	if afterLaunch != nil {
		afterLaunch()
	}
	_ = b.Close()
	return fmt.Sprintf("driver %s, chromium %s", DriverVersion(), v), nil
}

// shortErr keeps the informative head of a Playwright error and drops its
// banner, which advises `npx playwright install`: there is no npx here.
func shortErr(err error) string {
	var keep []string
	for _, l := range strings.Split(err.Error(), "\n") {
		l = strings.Trim(strings.TrimSpace(l), "║╔╗╚╝═ ")
		if l == "" || strings.Contains(l, "npx playwright") || strings.Contains(l, "Please run the following command") {
			continue
		}
		keep = append(keep, l)
		if len(keep) == 4 {
			break
		}
	}
	msg := strings.Join(keep, " | ")
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

type server struct {
	cfg      *config.Config
	name     string
	paths    Paths
	log      *slog.Logger
	pw       *playwright.Playwright
	browser  playwright.Browser
	ctx      playwright.BrowserContext
	page     playwright.Page
	mu       sync.Mutex // one action at a time, like a human at the keyboard
	dialogMu sync.Mutex
	accept   bool
	shutdown chan struct{}
}

// Serve runs the lane's browser until a quit command, ctx cancellation or a signal.
func Serve(ctx context.Context, cfg *config.Config, name, stateDir string, log *slog.Logger) error {
	if _, ok := cfg.Lanes[name]; !ok {
		return fmt.Errorf("unknown lane %q", name)
	}
	p := PathsFor(stateDir, name)
	if err := os.MkdirAll(p.Out, 0o700); err != nil {
		return fmt.Errorf("lane dir: %w", err)
	}
	for _, d := range []string{stateDir, filepath.Join(stateDir, "lanes"), p.Dir} {
		_ = os.Chmod(d, 0o700)
	}
	s := &server{cfg: cfg, name: name, paths: p, log: log, shutdown: make(chan struct{})}
	if err := s.startBrowser(); err != nil {
		return err
	}
	defer s.stopBrowser()

	_ = os.Remove(p.Socket)
	ln, err := net.Listen("unix", p.Socket)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.Socket, err)
	}
	if err := os.Chmod(p.Socket, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", s.ping)
	mux.HandleFunc("GET /peek", s.peek)
	mux.HandleFunc("POST /cmd", s.cmd)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	log.Info("driver ready", "lane", name, "pid", os.Getpid(), "root", p.Dir)

	select {
	case <-ctx.Done():
	case <-s.shutdown:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	_ = os.Remove(p.Socket)
	log.Info("driver stopped", "lane", name)
	return nil
}

func (s *server) startBrowser() error {
	if _, err := CheckDriver(); err != nil {
		return err
	}
	pw, err := playwright.Run(&playwright.RunOptions{Browsers: []string{"chromium"}, Verbose: false})
	if err != nil {
		return fmt.Errorf("start playwright (run `auth-refresh doctor`): %w", err)
	}
	s.pw = pw
	b, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args:     s.cfg.Browser.ChromiumArgs,
	})
	if err != nil {
		_ = pw.Stop()
		return fmt.Errorf("launch chromium: %w", err)
	}
	s.browser = b
	opts := playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: playwright.Bool(s.cfg.Browser.IgnoreHTTPSErrors),
	}
	if s.cfg.Browser.Locale != "" {
		opts.Locale = playwright.String(s.cfg.Browser.Locale)
	}
	if _, err := os.Stat(s.paths.Session); err == nil {
		opts.StorageStatePath = playwright.String(s.paths.Session)
	}
	bctx, err := b.NewContext(opts)
	if err != nil {
		s.stopBrowser()
		return fmt.Errorf("browser context: %w", err)
	}
	s.ctx = bctx
	page, err := bctx.NewPage()
	if err != nil {
		s.stopBrowser()
		return fmt.Errorf("new page: %w", err)
	}
	s.page = page
	// With a listener present Playwright no longer auto-dismisses dialogs, so
	// dismiss unless `acceptnext` armed exactly one accept.
	page.OnDialog(func(d playwright.Dialog) {
		s.dialogMu.Lock()
		accept := s.accept
		s.accept = false
		s.dialogMu.Unlock()
		if accept {
			_ = d.Accept()
		} else {
			_ = d.Dismiss()
		}
	})
	return nil
}

func (s *server) stopBrowser() {
	if s.browser != nil {
		_ = s.browser.Close()
	}
	if s.pw != nil {
		_ = s.pw.Stop()
	}
}

func (s *server) ping(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"lane": s.name, "pid": os.Getpid(), "account": s.cfg.Lanes[s.name].Account})
}

// peek deliberately skips s.mu: it must answer while a long action (waiturl,
// a click that waits) holds the page, and it only reads.
func (s *server) peek(w http.ResponseWriter, _ *http.Request) {
	p := Peek{URL: s.page.URL()}
	if p.URL != "about:blank" {
		t, err := textWithin(s.page, peekBudget)
		if err != nil {
			p.Error = firstLine(err.Error(), 200)
		} else {
			p.Challenge = OnChallenge(s.cfg.MFA.ChallengeRegex, t)
		}
	}
	writeJSON(w, p)
}

// textWithin reads the page text once, giving up after d: a busy or hung page
// must not stall a status report. It never waits for or causes a navigation.
func textWithin(p playwright.Page, d time.Duration) (string, error) {
	type result struct {
		text string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := p.Evaluate(`() => document.body ? document.body.innerText : ''`)
		t, _ := v.(string)
		ch <- result{t, err}
	}()
	select {
	case r := <-ch:
		return r.text, r.err
	case <-time.After(d):
		return "", fmt.Errorf("page text unreadable: no answer within %s (page busy or navigating)", d)
	}
}

func firstLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func (s *server) cmd(w http.ResponseWriter, r *http.Request) {
	var c Command
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		writeJSON(w, Result{Error: "bad command: " + err.Error()})
		return
	}
	s.mu.Lock()
	res := s.do(c)
	s.mu.Unlock()
	writeJSON(w, res)
	if c.Action == "quit" {
		close(s.shutdown)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) do(c Command) (res Result) {
	res.Extra = map[string]any{}
	err := s.act(c, res.Extra)
	res.OK = err == nil
	if err != nil {
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		res.Error = msg
	}
	res.URL = s.page.URL()
	return res
}

func ms(v int, def float64) *float64 {
	if v > 0 {
		return playwright.Float(float64(v))
	}
	return playwright.Float(def)
}

func (s *server) act(c Command, out map[string]any) error {
	p := s.page
	first := func() playwright.Locator { return p.Locator(c.Selector).First() }
	switch c.Action {
	case "goto":
		_, err := p.Goto(c.URL, playwright.PageGotoOptions{Timeout: ms(c.MS, 60000), WaitUntil: playwright.WaitUntilStateDomcontentloaded})
		return err
	case "click":
		return first().Click(playwright.LocatorClickOptions{Timeout: ms(c.MS, actionTimeout)})
	case "clicktext":
		return p.GetByText(c.Text).First().Click(playwright.LocatorClickOptions{Timeout: ms(c.MS, actionTimeout)})
	case "fill":
		return first().Fill(c.Text, playwright.LocatorFillOptions{Timeout: ms(c.MS, actionTimeout)})
	case "fillcred":
		return s.fillcred(c, first())
	case "select":
		v := playwright.SelectOptionValues{}
		if c.Value != "" {
			v.Values = &[]string{c.Value}
		} else {
			v.Labels = &[]string{c.Label}
		}
		sel, err := first().SelectOption(v, playwright.LocatorSelectOptionOptions{Timeout: ms(c.MS, actionTimeout)})
		out["selected"] = sel
		return err
	case "acceptnext":
		s.dialogMu.Lock()
		s.accept = true
		s.dialogMu.Unlock()
		out["armed"] = true
		return nil
	case "wait":
		d := 3 * time.Second
		if c.MS > 0 {
			d = time.Duration(c.MS) * time.Millisecond
		}
		time.Sleep(d)
		return nil
	case "waiturl":
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			return fmt.Errorf("pattern: %w", err)
		}
		return p.WaitForURL(re, playwright.PageWaitForURLOptions{Timeout: ms(c.MS, 60000)})
	case "text":
		t, err := bodyText(p)
		if len(t) > 3000 {
			t = t[:3000]
		}
		out["text"] = t
		return err
	case "textfull":
		f, err := SafeOutFile(s.paths.Out, c.File, "page.txt")
		if err != nil {
			return err
		}
		t, err := bodyText(p)
		if err != nil {
			return err
		}
		out["saved"], out["len"] = filepath.Base(f), len(t)
		return os.WriteFile(f, []byte(t), 0o600)
	case "html":
		h, err := first().InnerHTML(playwright.LocatorInnerHTMLOptions{Timeout: ms(c.MS, actionTimeout)})
		if len(h) > 6000 {
			h = h[:6000]
		}
		out["html"] = h
		return err
	case "controls":
		v, err := p.Evaluate(controlsJS)
		out["controls"] = v
		return err
	case "shot":
		f, err := SafeOutFile(s.paths.Out, c.File, "shot.png")
		if err != nil {
			return err
		}
		full := c.FullPage == nil || *c.FullPage
		_, err = p.Screenshot(playwright.PageScreenshotOptions{Path: playwright.String(f), FullPage: playwright.Bool(full)})
		out["file"] = filepath.Base(f)
		return err
	case "state":
		return s.saveState(c, out)
	case "press":
		return p.Keyboard().Press(c.Key)
	case "whoami":
		return s.whoami(out)
	case "quit":
		return nil
	}
	return fmt.Errorf("unknown action %q", c.Action)
}

// whoami asks the IdP who this lane's cookies belong to, in a throwaway page of
// the same context, so the lane's own page is never navigated. It still
// refuses unless the lane page is parked: a probe in the middle of a login can
// race the IdP's own redirects and cookie updates.
func (s *server) whoami(out map[string]any) error {
	if u := s.page.URL(); u != "about:blank" {
		return fmt.Errorf("REFUSED: lane page is on %s, a login may be in progress; finish it (waiturl, then state), park the lane, then whoami", u)
	}
	if s.cfg.IdP.OrgURL == "" {
		return errors.New("idp.org_url is not configured")
	}
	pg, err := s.ctx.NewPage()
	if err != nil {
		return fmt.Errorf("probe page: %w", err)
	}
	defer func() { _ = pg.Close() }()
	if _, err := pg.Goto(s.cfg.IdP.OrgURL+s.cfg.IdP.WhoamiPath, playwright.PageGotoOptions{
		Timeout: playwright.Float(30000), WaitUntil: playwright.WaitUntilStateDomcontentloaded,
	}); err != nil {
		return err
	}
	t, err := bodyText(pg)
	if err != nil {
		return err
	}
	w := ParseWhoami(t)
	out["live"], out["login"], out["last_login"], out["reason"] = w.Live, w.Login, w.LastLogin, w.Reason
	return nil
}

// fillcred fills a credential without it ever reaching a log, a reply or a shell.
func (s *server) fillcred(c Command, loc playwright.Locator) error {
	want := c.Section
	if want == "" {
		want = s.name
	}
	if want != s.name {
		return fmt.Errorf("LANE MISMATCH: this driver is lane %s, refused credential section %s", s.name, want)
	}
	if c.Field != "user" && c.Field != "pass" {
		return fmt.Errorf("field must be user or pass, got %q", c.Field)
	}
	v, err := creds.Lookup(s.cfg.CredsFile, want, c.Field)
	if err != nil {
		return err
	}
	return loc.Fill(v, playwright.LocatorFillOptions{Timeout: playwright.Float(actionTimeout)})
}

func (s *server) saveState(c Command, out map[string]any) error {
	f, err := SafeOutFile(s.paths.Out, c.File, "sessions.json")
	if err != nil {
		return err
	}
	if _, err := s.ctx.StorageState(playwright.BrowserContextStorageStateOptions{Path: playwright.String(f)}); err != nil {
		return err
	}
	_ = os.Chmod(f, 0o600)
	var size int64
	if st, err := os.Stat(f); err == nil {
		size = st.Size()
	}
	out["bytes"] = size
	stamp, _ := json.MarshalIndent(map[string]any{
		"lane": s.name, "saved": time.Now().UTC().Format(time.RFC3339), "file": filepath.Base(f), "bytes": size,
	}, "", " ")
	_ = os.WriteFile(filepath.Join(s.paths.Out, "lane.json"), stamp, 0o600)
	if size == 0 {
		return errors.New("state reported success but wrote nothing")
	}
	return nil
}

// bodyText reads the page text, riding out a client-side redirect that lands
// between DOMContentLoaded and the read (common on IdP pages).
func bodyText(p playwright.Page) (string, error) {
	var err error
	for range 4 {
		var v any
		v, err = p.Evaluate(`() => document.body ? document.body.innerText : ''`)
		if err == nil {
			t, _ := v.(string)
			return t, nil
		}
		if !strings.Contains(err.Error(), "context was destroyed") && !strings.Contains(err.Error(), "navigat") {
			return "", err
		}
		_ = p.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded, Timeout: playwright.Float(10000)})
	}
	return "", err
}

const controlsJS = `() => { const o = [];
  document.querySelectorAll('input,button,a,[role=button],select,textarea').forEach(el => {
    const r = el.getBoundingClientRect();
    const isSecret = el.type === 'password';
    o.push({tag: el.tagName, type: el.type || null, id: el.id || null, name: el.name || null,
      text: isSecret ? (el.value ? '(filled)' : '') : (el.innerText || el.value || el.placeholder || '').trim().slice(0, 70),
      visible: r.width > 0 && r.height > 0});
  });
  return o.filter(f => f.visible && (f.text || f.name || f.id)); }`
