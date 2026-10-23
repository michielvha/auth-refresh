// Package browserruntime provisions and checks the pinned executable dependencies.
package browserruntime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed lock.json
var lockJSON []byte

type asset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA    string `json:"sha256"`
	Format string `json:"format"`
	Prefix string `json:"prefix"`
}
type entry struct {
	SHA        string `json:"sha256"`
	PatchedSHA string `json:"patched_sha256"`
	Mode       uint32 `json:"mode"`
}
type manifest struct {
	Platform   string           `json:"platform"`
	BrowserDir string           `json:"browser_dir"`
	Assets     []asset          `json:"assets"`
	Files      map[string]entry `json:"files"`
}

func load() (manifest, error) {
	var m manifest
	if err := json.Unmarshal(lockJSON, &m); err != nil {
		return m, err
	}
	if runtime.GOOS+"_"+runtime.GOARCH != m.Platform {
		return m, fmt.Errorf("verified browser runtime unavailable for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if os.Getenv("PLAYWRIGHT_CLI_PATH") != "" || os.Getenv("PLAYWRIGHT_NODEJS_PATH") != "" {
		return m, fmt.Errorf("external driver/Node overrides are not verified; unset PLAYWRIGHT_CLI_PATH and PLAYWRIGHT_NODEJS_PATH")
	}
	return m, nil
}

// BrowserDir honors the managed Playwright browser cache override.
func BrowserDir() (string, error) {
	if p := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); p != "" {
		if p == "0" {
			return "", fmt.Errorf("browser path 0 is not supported by verified provisioning")
		}
		return p, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "ms-playwright"), nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func location(key, driver, browser string) string {
	if strings.HasPrefix(key, "driver/") {
		return filepath.Join(driver, filepath.FromSlash(strings.TrimPrefix(key, "driver/")))
	}
	return filepath.Join(browser, filepath.FromSlash(strings.TrimPrefix(key, "browser/")))
}

func verify(m manifest, driver, browser string) error {
	for key, e := range m.Files {
		p := location(key, driver, browser)
		st, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("runtime file missing: %s; run auth-refresh setup", key)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("runtime file is not regular: %s", key)
		}
		got, err := fileDigest(p)
		if err != nil {
			return err
		}
		if got != e.SHA && (e.PatchedSHA == "" || got != e.PatchedSHA) {
			return fmt.Errorf("runtime checksum mismatch: %s; refusing execution", key)
		}
	}
	// Check the full driver tree and browser subtree for injected executable code.
	for _, tree := range []struct{ root, prefix string }{{driver, "driver/"}, {filepath.Join(browser, m.BrowserDir), "browser/" + m.BrowserDir + "/"}} {
		err := filepath.WalkDir(tree.root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(tree.root, p)
			if err != nil {
				return err
			}
			key := tree.prefix + filepath.ToSlash(rel)
			if _, ok := m.Files[key]; ok {
				return nil
			}
			if tree.prefix != "driver/" && (rel == "INSTALLATION_COMPLETE" || rel == "DEPENDENCIES_VALIDATED") {
				return nil
			}
			return fmt.Errorf("unrecognised runtime file: %s", key)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Verify checks every pinned runtime file before Node or Chromium starts.
func Verify(driver string) error {
	m, err := load()
	if err != nil {
		return err
	}
	browser, err := BrowserDir()
	if err != nil {
		return err
	}
	return verify(m, driver, browser)
}

// Install downloads pinned archives and checks them before extraction. Existing
// invalid caches fail closed; they are never executed or silently overwritten.
func Install(driver string) error {
	m, err := load()
	if err != nil {
		return err
	}
	browser, err := BrowserDir()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(driver, "package", "cli.js")); err == nil {
		return verify(m, driver, browser)
	}
	stage, err := os.MkdirTemp("", "auth-refresh-runtime-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	driverStage, browserStage := filepath.Join(stage, "driver"), filepath.Join(stage, "browser")
	client := &http.Client{Timeout: 2 * time.Minute}
	for _, a := range m.Assets {
		resp, err := client.Get(a.URL)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("runtime download %s: HTTP %d", a.Name, resp.StatusCode)
		}
		if err := installArchive(a, body, driverStage, browserStage); err != nil {
			return err
		}
	}
	if err := verify(m, driverStage, browserStage); err != nil {
		return err
	}
	// Each destination is committed from a sibling directory so rename is atomic.
	for _, pair := range [][2]string{{driverStage, driver}, {filepath.Join(browserStage, m.BrowserDir), filepath.Join(browser, m.BrowserDir)}} {
		if err := publish(pair[0], pair[1]); err != nil {
			return err
		}
	}
	return verify(m, driver, browser)
}

func publish(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(target); err == nil {
		// Reuse an identical existing cache without overwriting it.
		return filepath.WalkDir(source, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			r, err := filepath.Rel(source, p)
			if err != nil {
				return err
			}
			want, err := fileDigest(p)
			if err != nil {
				return err
			}
			got, err := fileDigest(filepath.Join(target, r))
			if err != nil || got != want {
				return fmt.Errorf("runtime destination differs: %s; select an empty cache", target)
			}
			return nil
		})
	}
	tmp, err := os.MkdirTemp(filepath.Dir(target), ".auth-refresh-stage-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.CopyFS(tmp, os.DirFS(source)); err != nil {
		return err
	}
	// CopyFS retains executable bits; never execute until the final verification.
	return os.Rename(tmp, target)
}

func installArchive(a asset, body []byte, driver, browser string) error {
	if digest(body) != a.SHA {
		return fmt.Errorf("runtime archive checksum mismatch: %s", a.Name)
	}
	write := func(name string, mode os.FileMode, r io.Reader) error {
		if !filepath.IsLocal(filepath.FromSlash(name)) {
			return fmt.Errorf("unsafe archive path")
		}
		var key string
		switch a.Name {
		case "node":
			if name != a.Prefix {
				return nil
			}
			key = "driver/node"
		case "driver":
			if !strings.HasPrefix(name, "package/") {
				return nil
			}
			key = "driver/" + name
		case "browser":
			key = "browser/chromium_headless_shell-1234/" + name
		default:
			return fmt.Errorf("unknown runtime asset")
		}
		if !filepath.IsLocal(filepath.FromSlash(key)) {
			return fmt.Errorf("unsafe archive path")
		}
		p := location(key, driver, browser)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, r)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	if a.Format == "zip" {
		z, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return err
		}
		for _, f := range z.File {
			if f.FileInfo().IsDir() {
				continue
			}
			if !f.Mode().IsRegular() {
				return fmt.Errorf("archive contains non-regular file")
			}
			r, err := f.Open()
			if err != nil {
				return err
			}
			err = write(f.Name, f.Mode(), r)
			_ = r.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if err := write(h.Name, h.FileInfo().Mode(), tr); err != nil {
			return err
		}
	}
}
