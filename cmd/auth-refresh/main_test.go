package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/michielvha/auth-refresh/internal/lane"
)

func TestMain(m *testing.M) {
	lane.RunProbeHelperIfRequested()
	os.Exit(m.Run())
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_REFRESH_CONFIG", p)
	t.Setenv("AUTH_REFRESH_HOME", filepath.Join(dir, "state"))
	return dir
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

// check must never reach a lane: a login in progress there must not be
// navigated, raced or even asked a question.
func TestCheckNeverTouchesLanes(t *testing.T) {
	dir := writeConfig(t, `{"lanes":{"work":{"account":"alice@example.com"}}}`)
	p := lane.PathsFor(filepath.Join(dir, "state"), "work")
	if err := os.MkdirAll(filepath.Dir(p.Socket), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", p.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			_ = c.Close()
		}
	}()
	for _, args := range [][]string{{"check"}, {"check", "--json"}} {
		code, out, errs := runCLI(args...)
		if code != 0 || strings.Contains(out, "lane") {
			t.Fatalf("%v: code %d out %q err %q", args, code, out, errs)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := conns.Load(); n != 0 {
		t.Fatalf("check connected to the lane socket %d times", n)
	}
}

func TestRemovedFlagsAreRejected(t *testing.T) {
	writeConfig(t, `{}`)
	if code, _, _ := runCLI("check", "--no-lanes"); code != 2 {
		t.Fatalf("check --no-lanes: code %d", code)
	}
	code, _, errs := runCLI("setup", "--with-deps")
	if code != 2 || !strings.Contains(errs, "--with-deps was removed") {
		t.Fatalf("setup --with-deps: code %d err %q", code, errs)
	}
}

func TestDoctorReportsAMissingDriver(t *testing.T) {
	writeConfig(t, `{"lanes":{"work":{"account":"alice@example.com"}}}`)
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", t.TempDir())
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	code, out, _ := runCLI("doctor")
	if code != 1 || !strings.Contains(out, "FAIL  browser") || !strings.Contains(out, "auth-refresh setup") {
		t.Fatalf("code %d out:\n%s", code, out)
	}
}

func TestDoctorStillChecksTheBrowserWithoutAConfig(t *testing.T) {
	t.Setenv("AUTH_REFRESH_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", t.TempDir())
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	code, out, _ := runCLI("doctor")
	if code != 1 || !strings.Contains(out, "FAIL  config") || !strings.Contains(out, "FAIL  browser") {
		t.Fatalf("code %d out:\n%s", code, out)
	}
}

func TestPrintLaneStatus(t *testing.T) {
	var b bytes.Buffer
	printLaneStatus(&b, []lane.LaneStatus{
		{Lane: "a", Expects: "x", Session: "NO SESSION, cold start"},
		{Lane: "b", Expects: "y", PID: 7, Session: "saved", Page: "https://idp/challenge", Challenge: true},
		{Lane: "c", Expects: "z", PID: 8, Session: "saved", Page: "https://idp/password"},
		{Lane: "d", Expects: "w", PID: 9, Session: "saved", Page: "about:blank"},
	})
	out := b.String()
	for _, want := range []string{"a        stopped", "LIVE CHALLENGE, run: auth-refresh lane park b", "https://idp/password  (in use", "about:blank (parked)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
