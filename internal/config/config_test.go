package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExampleConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(raw, "config.example.json")
	if err != nil {
		t.Fatalf("the shipped example must be valid: %v", err)
	}
	if len(c.Lanes) == 0 || len(c.Identities) == 0 {
		t.Fatal("example has no lanes or identities")
	}
	if c.IdP.WhoamiPath != DefaultWhoamiPath {
		t.Fatalf("whoami default not applied: %q", c.IdP.WhoamiPath)
	}
}

func TestParseDefaults(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	c, err := Parse([]byte(`{"idp":{"org_url":"https://x.okta.com/"},
		"identities":[{"name":"gh","type":"gh"},{"name":"t","type":"http_token","file":"~/.tok","url":"https://x"}]}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	if c.CredsFile != "/home/u/.config/auth-refresh/creds" {
		t.Errorf("creds default: %q", c.CredsFile)
	}
	if c.IdP.OrgURL != "https://x.okta.com" {
		t.Errorf("trailing slash kept: %q", c.IdP.OrgURL)
	}
	if c.Identities[0].Host != "github.com" || c.Identities[1].File != "/home/u/.tok" {
		t.Errorf("identity defaults: %+v", c.Identities)
	}
	if c.Identities[1].ExpectStatus != 200 || c.Identities[1].Retries != 1 {
		t.Errorf("expect/retries defaults: %+v", c.Identities[1])
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	_, err := Parse([]byte(`{
		"mfa":{"number_regex":"tap \\d+"},
		"lanes":{"bad lane":{}},
		"identities":[
			{"name":"a","type":"aws_sso","lane":"nope"},
			{"name":"a","type":"kube"},
			{"name":"x","type":"ftp"},
			{"type":"gh"}
		]}`), "t")
	if err == nil {
		t.Fatal("want errors")
	}
	for _, want := range []string{
		"capture group", `lane "bad lane"`, `unknown lane "nope"`, "needs sso_session",
		"duplicate name", "needs context", `unknown type "ftp"`, "name is required",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"identites":[]}`), "t"); err == nil || !strings.Contains(err.Error(), "identites") {
		t.Fatalf("a typo must fail loudly, got %v", err)
	}
}

func TestRemovedBrowserKeysNameTheFix(t *testing.T) {
	_, err := Parse([]byte(`{"browser":{"locale":"en-US","capture_saml_assertions":false,"netlog_bodies":true}}`), "t")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"browser.capture_saml_assertions was removed", "browser.netlog_bodies was removed", "delete the key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestStartURLValidation(t *testing.T) {
	for _, bad := range []string{"d-1.awsapps.com/start", "http://d-1.awsapps.com/start", "https://"} {
		raw := `{"identities":[{"name":"aws","type":"aws_sso","sso_session":"s","start_url":"` + bad + `"}]}`
		if _, err := Parse([]byte(raw), "t"); err == nil || !strings.Contains(err.Error(), "start_url") {
			t.Errorf("%q: want a start_url error, got %v", bad, err)
		}
	}
	ok := `{"identities":[{"name":"aws","type":"aws_sso","sso_session":"s","start_url":"https://d-1.awsapps.com/start/#"}]}`
	if _, err := Parse([]byte(ok), "t"); err != nil {
		t.Fatal(err)
	}
}
