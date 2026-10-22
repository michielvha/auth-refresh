package lane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
	"github.com/michielvha/auth-refresh/internal/creds"
	"github.com/mxschmitt/playwright-go"
)

const actionTimeout = 15000.0

// Install downloads the Playwright driver and the Chromium headless shell into
// the user cache. withDeps also installs Chromium's system libraries (needs root).
func Install(withDeps bool) error {
	return playwright.Install(&playwright.RunOptions{
		Browsers: []string{"chromium"}, OnlyInstallShell: true, WithDeps: withDeps, Verbose: false,
	})
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
	netMu    sync.Mutex
	netLog   []map[string]any
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
	pw, err := playwright.Run(&playwright.RunOptions{Browsers: []string{"chromium"}, Verbose: false})
	if err != nil {
		return fmt.Errorf("start playwright (run `auth-refresh setup` first): %w", err)
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
		AcceptDownloads:   playwright.Bool(true),
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
		s.netMu.Lock()
		accept := s.accept
		s.accept = false
		s.netMu.Unlock()
		if accept {
			_ = d.Accept()
		} else {
			_ = d.Dismiss()
		}
	})
	if s.cfg.Browser.CaptureSAMLAssertions {
		page.OnRequest(s.captureSAML)
	}
	bctx.OnResponse(s.recordResponse)
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

var samlRe = regexp.MustCompile(`SAMLResponse=([^&]+)`)

// captureSAML writes decoded assertions to out/. Off by default: an assertion is a bearer credential.
func (s *server) captureSAML(r playwright.Request) {
	if r.Method() != http.MethodPost || !strings.Contains(strings.ToLower(r.URL()), "sso") {
		return
	}
	body, err := r.PostData()
	if err != nil {
		return
	}
	m := samlRe.FindStringSubmatch(body)
	if m == nil {
		return
	}
	enc, err := url.QueryUnescape(m[1])
	if err != nil {
		return
	}
	xml, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return
	}
	name := fmt.Sprintf("assertion-%d.xml", time.Now().UnixMilli())
	_ = os.WriteFile(filepath.Join(s.paths.Out, name), xml, 0o600)
}

var apiRe = regexp.MustCompile(`(?i)api|graphql`)

func (s *server) recordResponse(r playwright.Response) {
	rt := r.Request().ResourceType()
	if rt != "xhr" && rt != "fetch" && r.Status() < 400 {
		return
	}
	u := r.URL()
	if len(u) > 200 {
		u = u[:200]
	}
	e := map[string]any{"status": r.Status(), "method": r.Request().Method(), "url": u}
	if s.cfg.Browser.NetlogBodies && (r.Status() >= 400 || apiRe.MatchString(r.URL())) {
		if t, err := r.Text(); err == nil {
			if len(t) > 60000 {
				t = t[:60000]
			}
			e["body"] = t
		}
	}
	s.netMu.Lock()
	s.netLog = append(s.netLog, e)
	if len(s.netLog) > 100 {
		s.netLog = s.netLog[1:]
	}
	s.netMu.Unlock()
}

func (s *server) ping(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"lane": s.name, "pid": os.Getpid(), "account": s.cfg.Lanes[s.name].Account})
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
		s.netMu.Lock()
		s.accept = true
		s.netMu.Unlock()
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
	case "labels":
		v, err := p.Evaluate(`() => Array.from(document.querySelectorAll('label')).map(l => ({for: l.htmlFor, text: (l.innerText||'').trim().slice(0,80)}))`)
		out["labels"] = v
		return err
	case "netdump":
		f, err := SafeOutFile(s.paths.Out, c.File, "net.json")
		if err != nil {
			return err
		}
		s.netMu.Lock()
		b, _ := json.MarshalIndent(s.netLog, "", " ")
		out["count"] = len(s.netLog)
		s.netMu.Unlock()
		return os.WriteFile(f, b, 0o600)
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
	case "download":
		dl, err := p.ExpectDownload(func() error {
			switch {
			case c.Selector != "":
				return first().Click()
			case c.Click != "":
				return p.GetByText(c.Click).First().Click()
			}
			return nil
		}, playwright.PageExpectDownloadOptions{Timeout: ms(c.MS, 30000)})
		if err != nil {
			return err
		}
		dest := c.Path
		if dest == "" {
			if dest, err = SafeOutFile(s.paths.Out, dl.SuggestedFilename(), "download"); err != nil {
				return err
			}
		}
		if err := dl.SaveAs(dest); err != nil {
			return err
		}
		out["path"], out["filename"] = dest, dl.SuggestedFilename()
		if st, err := os.Stat(dest); err == nil {
			out["bytes"] = st.Size()
		}
		return nil
	case "upload":
		if c.Chooser {
			fc, err := p.ExpectFileChooser(func() error { return first().Click() })
			if err != nil {
				return err
			}
			return fc.SetFiles(c.Files)
		}
		return first().SetInputFiles(c.Files)
	case "press":
		return p.Keyboard().Press(c.Key)
	case "typelines":
		for _, l := range c.Lines {
			if l != "" {
				if err := p.Keyboard().InsertText(l); err != nil {
					return err
				}
			}
			if err := p.Keyboard().Press("Enter"); err != nil {
				return err
			}
		}
		return nil
	case "quit":
		return nil
	}
	return fmt.Errorf("unknown action %q", c.Action)
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
