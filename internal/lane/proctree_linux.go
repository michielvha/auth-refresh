package lane

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const prSetChildSubreaper = 36

// becomeSubreaper makes orphaned descendants of this process (Chromium starts
// its browser in a new session, and its helpers may double-fork) reparent to
// it instead of to init, so they stay findable from the probe helper's pid.
func becomeSubreaper() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0)
}

func helperSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// killTree ends every descendant of root, and root itself when withRoot. It
// asks politely first so the Playwright driver can close Chromium and remove
// its temporary profile, then stops the tree top-down (a stopped parent can
// neither fork nor reap, so pids stay valid) until no new process appears,
// and kills everything it stopped.
func killTree(root int, withRoot bool) {
	if kids := descendants(root); len(kids) > 0 {
		for _, p := range kids {
			_ = syscall.Kill(p, syscall.SIGTERM)
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && anyRunning(descendants(root)) {
			time.Sleep(50 * time.Millisecond)
		}
	}
	stopped := map[int]bool{}
	if withRoot {
		_ = syscall.Kill(root, syscall.SIGSTOP)
		stopped[root] = true
	}
	for {
		grew := false
		for _, p := range descendants(root) {
			if !stopped[p] {
				_ = syscall.Kill(p, syscall.SIGSTOP)
				stopped[p] = true
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	for p := range stopped {
		_ = syscall.Kill(p, syscall.SIGKILL)
	}
}

// descendants lists every process below root, parents before children.
func descendants(root int) []int {
	children := map[int][]int{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid, _, ok := procStat(pid); ok {
			children[ppid] = append(children[ppid], pid)
		}
	}
	var out []int
	queue := []int{root}
	seen := map[int]bool{root: true}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}

func anyRunning(pids []int) bool {
	for _, p := range pids {
		if processAlive(p) {
			return true
		}
	}
	return false
}

// processAlive is false for a pid that is gone or only a zombie.
func processAlive(pid int) bool {
	_, state, ok := procStat(pid)
	return ok && state != 'Z' && state != 'X'
}

func procStat(pid int) (ppid int, state byte, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 || len(f[0]) == 0 {
		return 0, 0, false
	}
	ppid, err = strconv.Atoi(f[1])
	return ppid, f[0][0], err == nil
}
