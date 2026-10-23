package browserruntime

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveIsVerifiedBeforeExtraction(t *testing.T) {
	root := t.TempDir()
	err := installArchive(asset{Name: "browser", Format: "zip", SHA: strings.Repeat("0", 64)}, []byte("corrupt"), filepath.Join(root, "driver"), filepath.Join(root, "browser"))
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("unverified archive was extracted")
	}
}

func TestArchiveTraversalIsRejected(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, err := z.Create("../../outside")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	err = installArchive(asset{Name: "browser", Format: "zip", SHA: digest(b.Bytes())}, b.Bytes(), filepath.Join(root, "driver"), filepath.Join(root, "browser"))
	if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("got %v", err)
	}
}

func TestExternalExecutableOverridesAreRefused(t *testing.T) {
	t.Setenv("PLAYWRIGHT_NODEJS_PATH", "/unverified/node")
	if _, err := load(); err == nil {
		t.Fatal("external Node accepted without provenance")
	}
}
