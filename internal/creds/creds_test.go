package creds

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds")
	body := "[work]\nuser = alice@example.com\npass=s3cr=t\n\n[home]\nuser=bob\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		section, field, want string
		wantErr              error
	}{
		{"work", "user", "alice@example.com", nil},
		{"work", "pass", "s3cr=t", nil},
		{"home", "user", "bob", nil},
		{"home", "pass", "", ErrNoField},
		{"work", "username", "", ErrNoField},
		{"missing", "user", "", ErrNoField},
	}
	for _, tt := range tests {
		t.Run(tt.section+"/"+tt.field, func(t *testing.T) {
			got, err := Lookup(path, tt.section, tt.field)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLookupRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds")
	if err := os.WriteFile(path, []byte("[work]\npass=topsecret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Lookup(path, "work", "pass")
	if err == nil || !strings.Contains(err.Error(), "mode 600") {
		t.Fatalf("want a mode error, got %v", err)
	}
	if strings.Contains(err.Error(), "topsecret") {
		t.Fatal("error leaks the secret")
	}
}
