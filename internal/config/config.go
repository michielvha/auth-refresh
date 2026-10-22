// Package config loads the host-specific auth-refresh configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Defaults used when the config leaves a field empty.
const (
	DefaultWhoamiPath     = "/api/v1/users/me"
	DefaultChallengeRegex = `push notification sent|tap [0-9]`
	DefaultNumberRegex    = `tap\s+(\d{1,3})`
)

// Config is the whole of ~/.config/auth-refresh/config.json.
type Config struct {
	PathPrepend      []string        `json:"path_prepend"`
	RequiredBinaries []string        `json:"required_binaries"`
	CredsFile        string          `json:"creds_file"`
	IdP              IdP             `json:"idp"`
	MFA              MFA             `json:"mfa"`
	Browser          Browser         `json:"browser"`
	Lanes            map[string]Lane `json:"lanes"`
	Identities       []Identity      `json:"identities"`
	NotesFile        string          `json:"notes_file"`
}

// IdP is the identity provider the browser lanes sign in to.
type IdP struct {
	Kind       string `json:"kind"`
	OrgURL     string `json:"org_url"`
	WhoamiPath string `json:"whoami_path"`
}

// MFA holds the patterns that find a number-match challenge in page text.
type MFA struct {
	ChallengeRegex string `json:"challenge_regex"`
	NumberRegex    string `json:"number_regex"`
}

// Browser tunes the headless Chromium every lane runs.
type Browser struct {
	ChromiumArgs      []string `json:"chromium_args"`
	IgnoreHTTPSErrors bool     `json:"ignore_https_errors"`
	Locale            string   `json:"locale"`
}

// removedBrowserKeys were debugging aids of the first version. They are named
// in the error so an old config is fixed by deleting the key, not by guessing.
var removedBrowserKeys = []string{"capture_saml_assertions", "netlog_bodies"}

// Lane is one human account with its own browser and cookie jar.
type Lane struct {
	Account string   `json:"account"`
	Owns    []string `json:"owns"`
}

// Identity is one credential that auth-refresh checks.
type Identity struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Lane         string `json:"lane,omitempty"`
	Fix          string `json:"fix,omitempty"`
	RidesOn      string `json:"rides_on,omitempty"`
	Tenant       string `json:"tenant,omitempty"`
	Scope        string `json:"scope,omitempty"`
	SSOSession   string `json:"sso_session,omitempty"`
	StartURL     string `json:"start_url,omitempty"`
	ProbeProfile string `json:"probe_profile,omitempty"`
	Context      string `json:"context,omitempty"`
	AWSProfile   string `json:"aws_profile,omitempty"`
	Host         string `json:"host,omitempty"`
	Account      string `json:"account,omitempty"`
	ProbeImage   string `json:"probe_image,omitempty"`
	File         string `json:"file,omitempty"`
	Auth         string `json:"auth,omitempty"`
	URL          string `json:"url,omitempty"`
	Expect       string `json:"expect,omitempty"`
	ExpectStatus int    `json:"expect_status,omitempty"`
	VerifyTLS    *bool  `json:"verify_tls,omitempty"`
	Retries      int    `json:"retries,omitempty"`
}

// TLSVerify reports whether TLS certificates must be verified for this identity.
func (i Identity) TLSVerify() bool { return i.VerifyTLS == nil || *i.VerifyTLS }

// requiredFields maps each identity type to the fields it cannot work without.
var requiredFields = map[string][]string{
	"azure":      nil,
	"gh":         nil,
	"aws_sso":    {"sso_session"},
	"kube":       {"context"},
	"docker":     {"probe_image"},
	"http_token": {"file", "url"},
	"http_up":    {"url"},
}

var validLane = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Path returns the config path from AUTH_REFRESH_CONFIG or the default.
func Path() string {
	if p := os.Getenv("AUTH_REFRESH_CONFIG"); p != "" {
		return Expand(p)
	}
	return Expand("~/.config/auth-refresh/config.json")
}

// StateDir returns where lanes, logs and the MFA history live.
func StateDir() string {
	if p := os.Getenv("AUTH_REFRESH_HOME"); p != "" {
		return Expand(p)
	}
	if p := os.Getenv("XDG_DATA_HOME"); p != "" {
		return filepath.Join(p, "auth-refresh")
	}
	return Expand("~/.local/share/auth-refresh")
}

// Expand replaces a leading ~ with the home directory.
func Expand(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// Load reads, defaults and validates the config at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw, path)
}

// Parse decodes raw config bytes. Top-level keys starting with "_" are comments.
func Parse(raw []byte, source string) (*Config, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", source, err)
	}
	for k := range top {
		if strings.HasPrefix(k, "_") {
			delete(top, k)
		}
	}
	if err := checkRemovedKeys(top); err != nil {
		return nil, fmt.Errorf("config %s: %w", source, err)
	}
	clean, err := json.Marshal(top)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", source, err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(clean))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", source, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", source, err)
	}
	return &c, nil
}

func checkRemovedKeys(top map[string]json.RawMessage) error {
	raw, ok := top["browser"]
	if !ok {
		return nil
	}
	var b map[string]json.RawMessage
	if json.Unmarshal(raw, &b) != nil {
		return nil // the strict decode reports the real type error
	}
	var errs []error
	for _, k := range removedBrowserKeys {
		if _, ok := b[k]; ok {
			errs = append(errs, fmt.Errorf("browser.%s was removed (the feature no longer exists): delete the key", k))
		}
	}
	return errors.Join(errs...)
}

func (c *Config) applyDefaults() {
	if c.CredsFile == "" {
		c.CredsFile = "~/.config/auth-refresh/creds"
	}
	c.CredsFile = Expand(c.CredsFile)
	c.NotesFile = Expand(c.NotesFile)
	if c.IdP.WhoamiPath == "" {
		c.IdP.WhoamiPath = DefaultWhoamiPath
	}
	c.IdP.OrgURL = strings.TrimRight(c.IdP.OrgURL, "/")
	if c.MFA.ChallengeRegex == "" {
		c.MFA.ChallengeRegex = DefaultChallengeRegex
	}
	if c.MFA.NumberRegex == "" {
		c.MFA.NumberRegex = DefaultNumberRegex
	}
	for i := range c.Identities {
		id := &c.Identities[i]
		if id.Host == "" && id.Type == "gh" {
			id.Host = "github.com"
		}
		if id.ExpectStatus == 0 {
			id.ExpectStatus = 200
		}
		if id.Retries < 1 {
			id.Retries = 1
		}
		id.File = Expand(id.File)
	}
}

// Validate reports every problem at once so a new host is fixed in one pass.
func (c *Config) Validate() error {
	var errs []error
	if _, err := regexp.Compile("(?i)" + c.MFA.ChallengeRegex); err != nil {
		errs = append(errs, fmt.Errorf("mfa.challenge_regex: %w", err))
	}
	if re, err := regexp.Compile("(?i)" + c.MFA.NumberRegex); err != nil {
		errs = append(errs, fmt.Errorf("mfa.number_regex: %w", err))
	} else if re.NumSubexp() < 1 {
		errs = append(errs, errors.New("mfa.number_regex needs one capture group for the digits"))
	}
	for _, name := range c.LaneNames() {
		if !validLane.MatchString(name) {
			errs = append(errs, fmt.Errorf("lane %q: use letters, digits, '-' or '_'", name))
		}
	}
	seen := map[string]bool{}
	for i, id := range c.Identities {
		where := fmt.Sprintf("identities[%d] %q", i, id.Name)
		if id.Name == "" {
			errs = append(errs, fmt.Errorf("identities[%d]: name is required", i))
		} else if seen[id.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name", where))
		}
		seen[id.Name] = true
		if id.Lane != "" {
			if _, ok := c.Lanes[id.Lane]; !ok {
				errs = append(errs, fmt.Errorf("%s: unknown lane %q", where, id.Lane))
			}
		}
		fields, known := requiredFields[id.Type]
		if !known {
			errs = append(errs, fmt.Errorf("%s: unknown type %q", where, id.Type))
			continue
		}
		for _, f := range fields {
			if fieldValue(id, f) == "" {
				errs = append(errs, fmt.Errorf("%s: type %s needs %s", where, id.Type, f))
			}
		}
		if id.StartURL != "" {
			if u, err := url.Parse(id.StartURL); err != nil || u.Scheme != "https" || u.Host == "" {
				errs = append(errs, fmt.Errorf("%s: start_url %q must be an https URL, as in the AWS config's sso_start_url", where, id.StartURL))
			}
		}
	}
	return errors.Join(errs...)
}

func fieldValue(id Identity, f string) string {
	switch f {
	case "sso_session":
		return id.SSOSession
	case "context":
		return id.Context
	case "probe_image":
		return id.ProbeImage
	case "file":
		return id.File
	case "url":
		return id.URL
	}
	return ""
}

// LaneNames returns the configured lanes in a stable order.
func (c *Config) LaneNames() []string {
	names := make([]string, 0, len(c.Lanes))
	for n := range c.Lanes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Identity returns the identity with the given name.
func (c *Config) Identity(name string) (Identity, bool) {
	for _, id := range c.Identities {
		if id.Name == name {
			return id, true
		}
	}
	return Identity{}, false
}
