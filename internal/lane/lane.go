// Package lane runs one long-lived headless browser per human account and talks
// to it over a unix socket. Separate lanes never share a cookie jar, so a cached
// IdP session for one account can never silently authenticate as another.
package lane

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Command is one driver action. Unused fields are ignored per action.
type Command struct {
	Action   string `json:"action"`
	URL      string `json:"url,omitempty"`
	Selector string `json:"selector,omitempty"`
	Text     string `json:"text,omitempty"`
	Field    string `json:"field,omitempty"`
	Section  string `json:"section,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	MS       int    `json:"ms,omitempty"`
	File     string `json:"file,omitempty"`
	FullPage *bool  `json:"fullPage,omitempty"`
	Value    string `json:"value,omitempty"`
	Label    string `json:"label,omitempty"`
	Key      string `json:"key,omitempty"`
}

// Peek is a passive look at a lane's page: it never navigates, clicks or
// waits on the page, so it is safe while a login or MFA challenge is live.
type Peek struct {
	URL       string `json:"url"`
	Challenge bool   `json:"on_challenge"`
	Error     string `json:"error,omitempty"`
}

// Result is the driver's answer. Extra holds action-specific fields.
type Result struct {
	OK    bool           `json:"ok"`
	Error string         `json:"error,omitempty"`
	URL   string         `json:"url,omitempty"`
	Extra map[string]any `json:"-"`
}

// MarshalJSON flattens Extra into the top-level object so callers see one map.
func (r Result) MarshalJSON() ([]byte, error) {
	m := map[string]any{"ok": r.OK}
	for k, v := range r.Extra {
		m[k] = v
	}
	if r.Error != "" {
		m["error"] = r.Error
	}
	if r.URL != "" {
		m["url"] = r.URL
	}
	return json.Marshal(m)
}

// UnmarshalJSON is the inverse of MarshalJSON.
func (r *Result) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	r.OK, _ = m["ok"].(bool)
	r.Error, _ = m["error"].(string)
	r.URL, _ = m["url"].(string)
	delete(m, "ok")
	delete(m, "error")
	delete(m, "url")
	r.Extra = m
	return nil
}

// String returns the text field, for the `text` action.
func (r Result) String() string {
	s, _ := r.Extra["text"].(string)
	return s
}

// Paths of one lane below the state directory.
type Paths struct {
	Dir, Socket, Log, Out, Session string
}

// PathsFor returns the file layout of lane name under stateDir.
func PathsFor(stateDir, name string) Paths {
	dir := filepath.Join(stateDir, "lanes", name)
	out := filepath.Join(dir, "out")
	return Paths{
		Dir:     dir,
		Socket:  filepath.Join(dir, "driver.sock"),
		Log:     filepath.Join(dir, "driver.log"),
		Out:     out,
		Session: filepath.Join(out, "sessions.json"),
	}
}

// SafeOutFile keeps a caller-chosen file name inside the lane's out directory.
func SafeOutFile(out, name, fallback string) (string, error) {
	if name == "" {
		name = fallback
	}
	if name != filepath.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("file %q must be a plain name inside the lane's out directory", name)
	}
	return filepath.Join(out, name), nil
}

// ExtractNumber finds the number-match digit in page text, or "".
func ExtractNumber(numberRegex, text string) string {
	re, err := regexp.Compile("(?i)" + numberRegex)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// OnChallenge reports whether the page text shows a live MFA challenge.
func OnChallenge(challengeRegex, text string) bool {
	re, err := regexp.Compile("(?i)" + challengeRegex)
	return err == nil && re.MatchString(text)
}

// Who is the identity provider's answer about a lane's session.
type Who struct {
	Live      bool
	Login     string
	LastLogin string
	Reason    string
}

// ParseWhoami reads an Okta /api/v1/users/me body.
func ParseWhoami(body string) Who {
	var u struct {
		Profile struct {
			Login string `json:"login"`
		} `json:"profile"`
		LastLogin string `json:"lastLogin"`
	}
	if err := json.Unmarshal([]byte(body), &u); err == nil && u.Profile.Login != "" {
		return Who{Live: true, Login: u.Profile.Login, LastLogin: u.LastLogin}
	}
	if strings.Contains(body, "E0000005") {
		return Who{Reason: "Invalid session"}
	}
	reason := strings.ReplaceAll(strings.TrimSpace(body), "\n", " ")
	if len(reason) > 80 {
		reason = reason[:80]
	}
	if reason == "" {
		reason = "empty reply"
	}
	return Who{Reason: reason}
}

func (w Who) String() string {
	if w.Live {
		return fmt.Sprintf("LIVE as %s (last login %s)", w.Login, w.LastLogin)
	}
	return "DEAD, " + w.Reason
}
