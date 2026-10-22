// Package creds reads lane credentials from an INI file without ever echoing them.
package creds

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	sectionRe = regexp.MustCompile(`^\[([A-Za-z0-9_.-]+)\]$`)
	keyRe     = regexp.MustCompile(`^(user|pass)\s*=\s*(.*)$`)
)

// ErrNoField is returned when a section lacks the requested key.
var ErrNoField = errors.New("no such field")

// Lookup returns field ("user" or "pass") from section in the INI file at path.
// The file must not be readable by group or others. Errors never contain values.
func Lookup(path, section, field string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("credentials file: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s must be mode 600, is %#o", path, st.Mode().Perm())
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("credentials file: %w", err)
	}
	defer func() { _ = f.Close() }()

	cur := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
			continue
		}
		if cur != section {
			continue
		}
		if m := keyRe.FindStringSubmatch(line); m != nil && m[1] == field {
			return m[2], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("credentials file: %w", err)
	}
	return "", fmt.Errorf("%w %q in %s section [%s] (keys are user, pass)", ErrNoField, field, path, section)
}
