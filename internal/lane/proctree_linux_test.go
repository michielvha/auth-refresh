package lane

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func init() {
	probeHangHook = func(path string) func() {
		return func() {
			var b strings.Builder
			for _, p := range descendants(os.Getpid()) {
				exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", p))
				fmt.Fprintf(&b, "%d %s\n", p, filepath.Base(exe))
			}
			_ = os.WriteFile(path+".tmp", []byte(b.String()), 0o600)
			_ = os.Rename(path+".tmp", path)
			time.Sleep(time.Hour)
		}
	}
}

// readTree parses "pid name" lines.
func readTree(t *testing.T, path string) map[int]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tree := map[int]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			t.Fatalf("bad line %q", l)
		}
		tree[pid] = strings.Join(f[1:], " ")
	}
	return tree
}

func requireAllGone(t *testing.T, tree map[int]string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var alive []string
		for p, comm := range tree {
			if processAlive(p) {
				alive = append(alive, fmt.Sprintf("%d (%s)", p, comm))
			}
		}
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still running after the probe timed out: %v", alive)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A timed-out probe must end the helper's whole tree: children, grandchildren,
// a grandchild in its own session (as Chromium starts its browser) and an
// orphan whose parent already exited.
func TestProbeTimeoutKillsTheWholeTree(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("needs setsid")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "package"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package", "cli.js"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pids := filepath.Join(dir, "pids")
	script := `#!/bin/sh
p="` + pids + `"
echo "$$ driver" >> "$p"
sleep 300 & echo "$! child" >> "$p"
sh -c 'sleep 300 & echo "$! grandchild" >> "$1"; exec sleep 300' x "$p" & echo "$! child-sh" >> "$p"
setsid sleep 300 & echo "$! own-session" >> "$p"
( sleep 300 & echo "$! orphan" >> "$p" )
echo ready > "$p.ready"
sleep 300
`
	node := filepath.Join(dir, "node")
	if err := os.WriteFile(node, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_REFRESH_TEST_SYNTHETIC_DRIVER", "1")
	oldVerify := verifyRuntime
	verifyRuntime = func(string) error { return nil }
	t.Cleanup(func() { verifyRuntime = oldVerify })
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", dir)
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	t.Setenv("PLAYWRIGHT_NODEJS_PATH", node)

	start := time.Now()
	_, err := Probe(3*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "did not start within") {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Fatalf("timed-out probe took %s", took)
	}
	if _, err := os.Stat(pids + ".ready"); err != nil {
		t.Fatalf("fake driver never got going: %v", err)
	}
	tree := readTree(t, pids)
	if len(tree) != 6 {
		t.Fatalf("want 6 processes recorded, got %v", tree)
	}
	requireAllGone(t, tree)
}

// The same with the real driver and Chromium: a probe whose helper hangs with
// the browser up leaves no driver or browser process behind once cancelled.
func TestProbeCancelKillsTheRealBrowser(t *testing.T) {
	requireBrowser(t)
	path := filepath.Join(t.TempDir(), "tree")
	t.Setenv(probeHangEnv, path)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := probeInHelper(ctx, nil)
		done <- err
	}()
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("probe ended before the browser was up: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	tree := readTree(t, path)
	var browser, driver bool
	for _, exe := range tree {
		browser = browser || exe == "chrome-headless-shell"
		driver = driver || exe == "node"
	}
	if !browser || !driver {
		t.Fatalf("helper tree lacks the driver or the browser: %v", tree)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("a cancelled probe reported success")
	}
	requireAllGone(t, tree)
}
