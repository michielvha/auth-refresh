package lane

import (
	"os"
	"testing"
)

// probeHangHook, when set (on Linux), builds the hook a probe helper runs once
// Chromium is up: it records the helper's process tree to path and hangs.
var probeHangHook func(path string) func()

const probeHangEnv = "AUTH_REFRESH_TEST_PROBE_HANG"

// TestMain lets this test binary act as Probe's helper subprocess.
func TestMain(m *testing.M) {
	if os.Getenv(probeHelperEnv) == "1" {
		var hook func()
		if path := os.Getenv(probeHangEnv); path != "" && probeHangHook != nil {
			hook = probeHangHook(path)
		}
		runProbeHelper(hook)
	}
	os.Exit(m.Run())
}
