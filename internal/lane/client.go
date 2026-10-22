package lane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/michielvha/auth-refresh/internal/config"
)

// ErrNotRunning means the lane has no live driver.
var ErrNotRunning = errors.New("lane is not running")

// Client controls the lanes of one config.
type Client struct {
	Cfg      *config.Config
	StateDir string
	// Exe and ServeArgs start a driver process; ServeArgs gets the lane name appended.
	Exe       string
	ServeArgs []string
}

// Info is a running driver's self-description.
type Info struct {
	Lane    string `json:"lane"`
	PID     int    `json:"pid"`
	Account string `json:"account"`
}

func (c *Client) check(name string) (Paths, error) {
	if _, ok := c.Cfg.Lanes[name]; !ok {
		return Paths{}, fmt.Errorf("unknown lane %q (configured: %s)", name, strings.Join(c.Cfg.LaneNames(), " "))
	}
	return PathsFor(c.StateDir, name), nil
}

func httpOver(sock string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}
}

// Ping returns the driver's info, or ErrNotRunning.
func (c *Client) Ping(ctx context.Context, name string) (Info, error) {
	p, err := c.check(name)
	if err != nil {
		return Info{}, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://lane/ping", nil)
	resp, err := httpOver(p.Socket, 3*time.Second).Do(req)
	if err != nil {
		return Info{}, ErrNotRunning
	}
	defer func() { _ = resp.Body.Close() }()
	var info Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return Info{}, fmt.Errorf("ping %s: %w", name, err)
	}
	return info, nil
}

// Start launches the lane's driver as its own session, so it outlives the caller. Idempotent.
func (c *Client) Start(ctx context.Context, name string) (string, error) {
	p, err := c.check(name)
	if err != nil {
		return "", err
	}
	if info, err := c.Ping(ctx, name); err == nil {
		return fmt.Sprintf("lane %s already running, pid %d", name, info.PID), nil
	}
	if err := os.MkdirAll(p.Out, 0o700); err != nil {
		return "", fmt.Errorf("lane dir: %w", err)
	}
	logf, err := os.OpenFile(p.Log, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("driver log: %w", err)
	}
	defer func() { _ = logf.Close() }()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return "", err
	}
	defer func() { _ = devnull.Close() }()
	args := append(append([]string{}, c.ServeArgs...), name)
	cmd := exec.Command(c.Exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start driver: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	deadline := time.After(90 * time.Second)
	for {
		select {
		case <-exited:
			return "", fmt.Errorf("lane %s FAILED to start:\n%s", name, tail(p.Log, 8))
		case <-deadline:
			return "", fmt.Errorf("lane %s did not answer within 90s:\n%s", name, tail(p.Log, 8))
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(300 * time.Millisecond):
			if info, err := c.Ping(ctx, name); err == nil {
				return fmt.Sprintf("lane %s up, pid %d", name, info.PID), nil
			}
		}
	}
}

func tail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(no log)"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Send runs one driver action and returns its result.
func (c *Client) Send(ctx context.Context, name string, cmd Command) (Result, error) {
	p, err := c.check(name)
	if err != nil {
		return Result{}, err
	}
	body, err := json.Marshal(cmd)
	if err != nil {
		return Result{}, err
	}
	timeout := 70 * time.Second
	if d := time.Duration(cmd.MS)*time.Millisecond + 15*time.Second; d > timeout {
		timeout = d
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://lane/cmd", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpOver(p.Socket, timeout).Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return Result{}, fmt.Errorf("lane %s: no reply within %s", name, timeout)
		}
		return Result{}, fmt.Errorf("lane %s: %w (auth-refresh lane start %s)", name, ErrNotRunning, name)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, err
	}
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return Result{}, fmt.Errorf("lane %s: bad reply: %w", name, err)
	}
	return r, nil
}

// SendRaw sends a JSON command string, as typed by an agent.
func (c *Client) SendRaw(ctx context.Context, name, raw string) (Result, error) {
	var cmd Command
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cmd); err != nil {
		return Result{}, fmt.Errorf("command JSON: %w", err)
	}
	return c.Send(ctx, name, cmd)
}

// Stop asks the driver to quit and kills it if it does not.
func (c *Client) Stop(ctx context.Context, name string) (string, error) {
	info, err := c.Ping(ctx, name)
	if err != nil {
		return fmt.Sprintf("lane %s stopped", name), nil
	}
	_, _ = c.Send(ctx, name, Command{Action: "quit"})
	for range 20 {
		time.Sleep(250 * time.Millisecond)
		if _, err := c.Ping(ctx, name); err != nil {
			return fmt.Sprintf("lane %s stopped", name), nil
		}
	}
	if pr, err := os.FindProcess(info.PID); err == nil {
		_ = pr.Signal(syscall.SIGTERM)
	}
	return fmt.Sprintf("lane %s killed (pid %d)", name, info.PID), nil
}

// Park navigates to about:blank, killing any live challenge. Cookies survive.
func (c *Client) Park(ctx context.Context, name string) (Result, error) {
	return c.Send(ctx, name, Command{Action: "goto", URL: "about:blank"})
}

// Whoami asks the IdP who the lane's session belongs to. It sends no push.
// It navigates away, so never call it while a challenge is being relayed.
func (c *Client) Whoami(ctx context.Context, name string) (Who, error) {
	if c.Cfg.IdP.OrgURL == "" {
		return Who{}, errors.New("idp.org_url is not configured")
	}
	if _, err := c.Ping(ctx, name); err != nil {
		return Who{}, ErrNotRunning
	}
	p := PathsFor(c.StateDir, name)
	file := filepath.Join(p.Out, "whoami.json")
	_ = os.Remove(file)
	if _, err := c.Send(ctx, name, Command{Action: "goto", URL: c.Cfg.IdP.OrgURL + c.Cfg.IdP.WhoamiPath}); err != nil {
		return Who{}, err
	}
	// textfull, not text: `text` caps at 3000 chars and a full profile can exceed it.
	r, err := c.Send(ctx, name, Command{Action: "textfull", File: "whoami.json"})
	_, _ = c.Park(ctx, name)
	if err != nil {
		return Who{}, err
	}
	if !r.OK {
		return Who{Reason: r.Error}, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return Who{Reason: "no reply"}, nil
	}
	_ = os.Remove(file)
	return ParseWhoami(string(b)), nil
}

// PageText returns the visible text of the lane's page.
func (c *Client) PageText(ctx context.Context, name string) (string, error) {
	r, err := c.Send(ctx, name, Command{Action: "text"})
	if err != nil {
		return "", err
	}
	return r.String(), nil
}

// MFA polls the page for a number-match challenge and records the number.
func (c *Client) MFA(ctx context.Context, name string, attempts int, every time.Duration) (string, error) {
	if _, err := c.Ping(ctx, name); err != nil {
		return "", fmt.Errorf("lane %s: %w", name, ErrNotRunning)
	}
	for i := range attempts {
		t, err := c.PageText(ctx, name)
		if err != nil {
			return "", err
		}
		if n := ExtractNumber(c.Cfg.MFA.NumberRegex, t); n != "" {
			c.recordNumber(name, n)
			return n, nil
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(every):
			}
		}
	}
	return "", nil
}

func (c *Client) recordNumber(name, n string) {
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(c.StateDir, "mfa-number.txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s lane=%s tap %s\n", time.Now().UTC().Format(time.RFC3339), name, n)
}

// LaneStatus is one row of `lane status`.
type LaneStatus struct {
	Lane      string `json:"lane"`
	Expects   string `json:"expects"`
	PID       int    `json:"pid,omitempty"`
	Session   string `json:"session"`
	Who       string `json:"who"`
	Challenge bool   `json:"on_challenge"`
}

// Status reports every lane. It never probes a lane that sits on a challenge,
// because the probe navigates away and would kill the push being relayed.
func (c *Client) Status(ctx context.Context) []LaneStatus {
	var rows []LaneStatus
	for _, name := range c.Cfg.LaneNames() {
		p := PathsFor(c.StateDir, name)
		row := LaneStatus{Lane: name, Expects: c.Cfg.Lanes[name].Account, Session: "NO SESSION, cold start"}
		if st, err := os.Stat(p.Session); err == nil {
			row.Session = fmt.Sprintf("saved %s, %d bytes", st.ModTime().Format("2006-01-02 15:04"), st.Size())
		}
		info, err := c.Ping(ctx, name)
		switch {
		case err != nil:
			row.Who = "stopped, cannot probe"
		default:
			row.PID = info.PID
			if t, err := c.PageText(ctx, name); err == nil && OnChallenge(c.Cfg.MFA.ChallengeRegex, t) {
				row.Challenge = true
				row.Who = "on a challenge, not probed"
				break
			}
			if who, err := c.Whoami(ctx, name); err != nil {
				row.Who = "probe failed: " + err.Error()
			} else {
				row.Who = who.String()
			}
		}
		rows = append(rows, row)
	}
	return rows
}
