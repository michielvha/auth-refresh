//go:build !linux

package lane

import (
	"syscall"
	"time"
)

// becomeSubreaper has no equivalent here; the helper's process group is the
// boundary instead.
func becomeSubreaper() {}

func helperSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// killTree signals root's process group: TERM first, so the Playwright driver
// can close the browser it started in its own session, then KILL.
func killTree(root int, withRoot bool) {
	if !withRoot {
		return
	}
	_ = syscall.Kill(-root, syscall.SIGTERM)
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if syscall.Kill(-root, 0) != nil {
			return
		}
	}
	_ = syscall.Kill(-root, syscall.SIGKILL)
}
