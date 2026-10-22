// Command auth-refresh checks and re-establishes the human SSO identities on a
// headless host, driving logins in per-account headless browser lanes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/michielvha/auth-refresh/internal/check"
	"github.com/michielvha/auth-refresh/internal/config"
	"github.com/michielvha/auth-refresh/internal/lane"
)

var version = "dev"

const usage = `auth-refresh: keep the human SSO identities on a headless host alive.

Usage:
  auth-refresh check [--json]                status of every identity (CLI and HTTP probes only;
                                             never touches a browser lane)
  auth-refresh doctor                        validate config, credentials, binaries, and start the
                                             pinned Playwright driver and Chromium once
  auth-refresh env                           print an export PATH line with the config's path_prepend
  auth-refresh setup                         download the Playwright driver (with its Node.js runtime)
                                             and Chromium headless shell into your user cache; run as
                                             the user that runs the lanes, not root. System libraries
                                             are separate: see the README.
  auth-refresh lane list                     configured lanes and their accounts
  auth-refresh lane start|stop <lane>        run or stop a lane's headless browser
  auth-refresh lane status [--json]          every lane, passively: pid, saved session, page URL,
                                             live challenge. Never navigates.
  auth-refresh lane send <lane> '<json>'     one driver action, prints the JSON reply
  auth-refresh lane park <lane>              about:blank: kills a live MFA challenge, keeps cookies
  auth-refresh lane whoami <lane>            ask the IdP who this lane is (no MFA, no push); refused
                                             unless the lane is parked on about:blank
  auth-refresh lane mfa <lane> [--tries N]   poll for a number-match challenge: MFA_NUMBER=NN
  auth-refresh version

Config: $AUTH_REFRESH_CONFIG (default ~/.config/auth-refresh/config.json)
State:  $AUTH_REFRESH_HOME   (default ~/.local/share/auth-refresh)
`

func main() {
	lane.RunProbeHelperIfRequested()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "auth-refresh %s\n", version)
		return 0
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	case "setup":
		return cmdSetup(args[1:], stdout, stderr)
	case "doctor":
		return cmdDoctor(stdout)
	}

	cfg, err := config.Load(config.Path())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	prependPath(cfg.PathPrepend)

	switch args[0] {
	case "check":
		return cmdCheck(ctx, cfg, args[1:], stdout, stderr)
	case "env":
		// For `eval "$(auth-refresh env)"`: the agent's own login commands need the same PATH.
		_, _ = fmt.Fprintf(stdout, "export PATH=%s\n", shellQuote(os.Getenv("PATH")))
		return 0
	case "lane":
		return cmdLane(ctx, cfg, args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

// prependPath fixes the service-launched case: systemd and cron never source the
// shell rc, so Homebrew/asdf tools are otherwise invisible.
func prependPath(dirs []string) {
	if len(dirs) == 0 {
		return
	}
	var parts []string
	for _, d := range dirs {
		parts = append(parts, config.Expand(d))
	}
	parts = append(parts, os.Getenv("PATH"))
	_ = os.Setenv("PATH", strings.Join(parts, string(os.PathListSeparator)))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func cmdCheck(ctx context.Context, cfg *config.Config, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	d := check.DefaultDeps()
	if missing := check.MissingBinaries(cfg, d.Which); len(missing) > 0 {
		// A missing binary is a host fault, never an expired credential.
		_, _ = fmt.Fprintf(stdout, "HOST PROBLEM, missing binaries: %s\n", strings.Join(missing, ", "))
		_, _ = fmt.Fprintln(stdout, "Fix PATH (config path_prepend, or the service unit's Environment=PATH=) before any login.")
		return 2
	}
	results := check.All(ctx, cfg, d)
	code := 0
	for _, r := range results {
		if r.Bad() {
			code = 1
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", " ")
		_ = enc.Encode(results)
		return code
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	for _, r := range results {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Name, r.Status, r.Detail)
	}
	_ = tw.Flush()
	var next []string
	for _, r := range results {
		if r.Bad() {
			fix := r.Fix
			if fix == "" {
				fix = "manual (see config)"
			}
			next = append(next, r.Name+" -> "+fix)
		}
	}
	if len(next) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nNext: %s\n", strings.Join(next, "; "))
	}
	return code
}

// probeTimeout bounds doctor's and setup's real driver and browser start.
var probeTimeout = 90 * time.Second

func cmdSetup(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		_, _ = fmt.Fprintf(stderr, "setup takes no arguments (got %s); --with-deps was removed: install system libraries with your OS package manager, see the README\n", strings.Join(args, " "))
		return 2
	}
	if os.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "warning: setup installs into the invoking user's cache; as root, lanes run by another user will not find it")
	}
	if err := lane.Install(); err != nil {
		_, _ = fmt.Fprintln(stderr, "setup:", err)
		return 1
	}
	dir, _ := lane.DriverDir()
	_, _ = fmt.Fprintf(stdout, "playwright driver %s (with its Node.js runtime) in %s, chromium headless shell in the Playwright browser cache\n", lane.DriverVersion(), dir)
	detail, err := lane.Probe(probeTimeout, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "setup: downloaded, but the browser does not start: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "browser starts: %s\n", detail)
	return 0
}

func cmdDoctor(stdout io.Writer) int {
	bad := 0
	report := func(ok bool, what, detail string) {
		mark := "ok  "
		if !ok {
			mark = "FAIL"
			bad++
		}
		_, _ = fmt.Fprintf(stdout, "%s  %-22s %s\n", mark, what, detail)
	}
	cfg, err := config.Load(config.Path())
	if err != nil {
		report(false, "config", err.Error())
	} else {
		report(true, "config", config.Path())
		prependPath(cfg.PathPrepend)
	}
	report(true, "state dir", config.StateDir())
	if cfg != nil {
		missing := check.MissingBinaries(cfg, exec.LookPath)
		if len(missing) == 0 {
			report(true, "binaries", "all present")
		} else {
			report(false, "binaries", "missing "+strings.Join(missing, ", "))
		}
	}
	if cfg != nil && len(cfg.Lanes) > 0 {
		st, err := os.Stat(cfg.CredsFile)
		switch {
		case err != nil:
			report(false, "credentials", cfg.CredsFile+" missing")
		case st.Mode().Perm()&0o077 != 0:
			report(false, "credentials", fmt.Sprintf("%s is %#o, must be 0600", cfg.CredsFile, st.Mode().Perm()))
		default:
			report(true, "credentials", cfg.CredsFile)
		}
		report(cfg.IdP.OrgURL != "", "idp.org_url", cfg.IdP.OrgURL)
	}
	// Without a config the browser is still checked: that is the first thing a new host needs.
	if cfg == nil || len(cfg.Lanes) > 0 {
		var args []string
		if cfg != nil {
			args = cfg.Browser.ChromiumArgs
		}
		detail, err := lane.Probe(probeTimeout, args)
		if err != nil {
			report(false, "browser", err.Error())
		} else {
			report(true, "browser", detail)
		}
	}
	if cfg != nil && cfg.NotesFile != "" {
		_, err := os.Stat(cfg.NotesFile)
		report(err == nil, "notes file", cfg.NotesFile)
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func newClient(cfg *config.Config) *lane.Client {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	return &lane.Client{Cfg: cfg, StateDir: config.StateDir(), Exe: exe, ServeArgs: []string{"lane", "serve"}}
}

func printLaneStatus(w io.Writer, rows []lane.LaneStatus) {
	for _, r := range rows {
		if r.PID == 0 {
			_, _ = fmt.Fprintf(w, "%-8s stopped      expects %s, %s\n", r.Lane, r.Expects, r.Session)
			continue
		}
		_, _ = fmt.Fprintf(w, "%-8s pid=%-8d expects %s, %s\n", r.Lane, r.PID, r.Expects, r.Session)
		switch {
		case r.Challenge:
			_, _ = fmt.Fprintf(w, "         page %s  *** PARKED ON A LIVE CHALLENGE, run: auth-refresh lane park %s ***\n", r.Page, r.Lane)
		case r.PageError != "":
			_, _ = fmt.Fprintf(w, "         page %s  (%s; not touched)\n", r.Page, r.PageError)
		case r.Page == "about:blank":
			_, _ = fmt.Fprintln(w, "         page about:blank (parked)")
		default:
			_, _ = fmt.Fprintf(w, "         page %s  (in use: a login may be in progress; park only a flow you have finished or abandoned)\n", r.Page)
		}
	}
}

func cmdLane(ctx context.Context, cfg *config.Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	c := newClient(cfg)
	need := func(n int) bool {
		if len(args) < n {
			_, _ = fmt.Fprintf(stderr, "lane %s: missing argument\n", args[0])
			return false
		}
		return true
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintln(stderr, err)
		if errors.Is(err, lane.ErrNotRunning) {
			return 3
		}
		return 1
	}
	printResult := func(r lane.Result, err error) int {
		if err != nil {
			return fail(err)
		}
		b, _ := json.MarshalIndent(r, "", " ")
		_, _ = fmt.Fprintln(stdout, string(b))
		if !r.OK {
			return 1
		}
		return 0
	}

	switch args[0] {
	case "list":
		for _, n := range cfg.LaneNames() {
			l := cfg.Lanes[n]
			_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\n", n, l.Account, strings.Join(l.Owns, ", "))
		}
		return 0
	case "serve":
		if !need(2) {
			return 2
		}
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		if err := lane.Serve(ctx, cfg, args[1], config.StateDir(), log); err != nil {
			log.Error("driver failed", "lane", args[1], "err", err)
			return 1
		}
		return 0
	case "start", "stop":
		if !need(2) {
			return 2
		}
		f := c.Start
		if args[0] == "stop" {
			f = c.Stop
		}
		msg, err := f(ctx, args[1])
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(stdout, msg)
		return 0
	case "status":
		rows := c.Status(ctx)
		if len(args) > 1 && args[1] == "--json" {
			b, _ := json.MarshalIndent(rows, "", " ")
			_, _ = fmt.Fprintln(stdout, string(b))
			return 0
		}
		printLaneStatus(stdout, rows)
		return 0
	case "send":
		if !need(3) {
			return 2
		}
		return printResult(c.SendRaw(ctx, args[1], args[2]))
	case "park":
		if !need(2) {
			return 2
		}
		return printResult(c.Park(ctx, args[1]))
	case "whoami":
		if !need(2) {
			return 2
		}
		who, err := c.Whoami(ctx, args[1])
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "%s: %v\n", args[1], err)
			return fail(err)
		}
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", args[1], who)
		if !who.Live {
			return 1
		}
		return 0
	case "mfa":
		if !need(2) {
			return 2
		}
		fs := flag.NewFlagSet("mfa", flag.ContinueOnError)
		fs.SetOutput(stderr)
		tries := fs.Int("tries", 30, "polls, 2s apart")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		n, err := c.MFA(ctx, args[1], *tries, 2*time.Second)
		if err != nil {
			return fail(err)
		}
		if n == "" {
			_, _ = fmt.Fprintln(stdout, "MFA_NUMBER=none (no challenge on screen)")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "MFA_NUMBER=%s\n", n)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "unknown lane command %q\n", args[0])
	return 2
}
