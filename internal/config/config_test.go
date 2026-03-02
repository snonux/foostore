package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeUserConfig creates the ~/.config/foostore.json file inside the given
// HOME directory (which must already exist).  Used to exercise Load() directly.
func writeUserConfig(t *testing.T, home, content string) {
	t.Helper()
	cfgDir := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(cfgDir, "foostore.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// captureStderr redirects os.Stderr to a pipe, calls fn, then returns whatever
// was written to the pipe and restores the original os.Stderr.
func captureStderr(fn func()) string {
	orig := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// ---- expandTilde -----------------------------------------------------------

// TestExpandTilde verifies the three expansion cases: tilde prefix, no tilde, empty.
func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"tilde only", "~", home},
		{"tilde with subpath", "~/foo/bar", home + "/foo/bar"},
		{"absolute path unchanged", "/etc/passwd", "/etc/passwd"},
		{"relative path unchanged", "relative/path", "relative/path"},
		{"empty string unchanged", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandTilde(tc.input)
			if got != tc.want {
				t.Errorf("expandTilde(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolveHomeDirFrom(t *testing.T) {
	lookupErr := errors.New("lookup failed")

	cases := []struct {
		name            string
		userHome        string
		userErr         error
		envHome         string
		tempDir         string
		wantHome        string
		wantErrContains string
	}{
		{
			name:     "user home success",
			userHome: "/users/alice",
			tempDir:  "/tmp",
			wantHome: "/users/alice",
		},
		{
			name:            "falls back to absolute HOME when user lookup fails",
			userErr:         lookupErr,
			envHome:         "/env/home",
			tempDir:         "/tmp",
			wantHome:        "/env/home",
			wantErrContains: "using HOME",
		},
		{
			name:            "falls back to absolute HOME when user lookup is empty",
			envHome:         "/env/home",
			tempDir:         "/tmp",
			wantHome:        "/env/home",
			wantErrContains: "returned empty home",
		},
		{
			name:            "relative HOME falls back to temp-based path",
			userErr:         lookupErr,
			envHome:         "relative/home",
			tempDir:         "/tmp/runtime",
			wantHome:        "/tmp/runtime/foostore-home",
			wantErrContains: "HOME is not absolute",
		},
		{
			name:            "missing HOME falls back to temp-based path",
			userErr:         lookupErr,
			tempDir:         "/tmp/runtime",
			wantHome:        "/tmp/runtime/foostore-home",
			wantErrContains: "HOME is unavailable",
		},
		{
			name:            "empty user home and missing HOME falls back to temp-based path",
			tempDir:         "/tmp/runtime",
			wantHome:        "/tmp/runtime/foostore-home",
			wantErrContains: "returned empty home and HOME is unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotHome, err := resolveHomeDirFrom(
				func() (string, error) { return tc.userHome, tc.userErr },
				tc.envHome,
				tc.tempDir,
			)
			if gotHome != tc.wantHome {
				t.Fatalf("home = %q; want %q", gotHome, tc.wantHome)
			}

			if tc.wantErrContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", tc.wantErrContains)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error = %q; want substring %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}

// ---- Load() ----------------------------------------------------------------

// TestLoad_defaults verifies all 10 default values when no config file exists.
// HOME is redirected to a temp dir so Load() looks for a file that will not exist.
// EDITOR is unset so EditCmd falls back to "vi".
func TestLoad_defaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("EDITOR", "") // ensure fallback to "vi"

	cfg := Load()

	cases := []struct{ name, got, want string }{
		{"DataDir", cfg.DataDir, filepath.Join(dir, "git", "foostoredb")},
		{"ExportDir", cfg.ExportDir, filepath.Join(dir, ".foostore-export")},
		{"KeyFile", cfg.KeyFile, filepath.Join(dir, ".foostore.key")},
		{"EncAlg", cfg.EncAlg, "AES-256-CBC"},
		{"AddToIV", cfg.AddToIV, "Hello world"},
		{"EditCmd", cfg.EditCmd, "vi"},
		{"GnomeClipboardCmd", cfg.GnomeClipboardCmd, "gpaste-client"},
		{"MacOSClipboardCmd", cfg.MacOSClipboardCmd, "pbcopy"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q; want %q", tc.name, tc.got, tc.want)
		}
	}
	if cfg.KeyLength != 32 {
		t.Errorf("KeyLength = %d; want 32", cfg.KeyLength)
	}
	if len(cfg.SyncRepos) != 2 || cfg.SyncRepos[0] != "git1" || cfg.SyncRepos[1] != "git2" {
		t.Errorf("SyncRepos = %v; want [git1 git2]", cfg.SyncRepos)
	}
}

// TestLoad_editorEnvVar verifies that when $EDITOR is set, defaultConfig uses it
// as the EditCmd, and that a JSON config value overrides $EDITOR.
func TestLoad_editorEnvVar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// $EDITOR set, no config file — EditCmd must equal $EDITOR.
	t.Setenv("EDITOR", "nano")
	cfg := Load()
	if cfg.EditCmd != "nano" {
		t.Errorf("EditCmd = %q; want nano (from $EDITOR)", cfg.EditCmd)
	}

	// JSON config overrides $EDITOR.
	writeUserConfig(t, dir, `{"edit_cmd":"vim"}`)
	cfg = Load()
	if cfg.EditCmd != "vim" {
		t.Errorf("EditCmd = %q; want vim (from config file)", cfg.EditCmd)
	}
}

// TestLoad_override calls Load() directly (via a redirected HOME) and verifies
// that JSON-supplied fields override defaults while absent fields keep defaults.
func TestLoad_override(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	writeUserConfig(t, dir, `{"edit_cmd":"nvim","key_length":64,"sync_repos":["github","gitlab"]}`)

	cfg := Load()

	// Overridden fields must change.
	if cfg.EditCmd != "nvim" {
		t.Errorf("EditCmd = %q; want nvim", cfg.EditCmd)
	}
	if cfg.KeyLength != 64 {
		t.Errorf("KeyLength = %d; want 64", cfg.KeyLength)
	}
	if len(cfg.SyncRepos) != 2 || cfg.SyncRepos[0] != "github" || cfg.SyncRepos[1] != "gitlab" {
		t.Errorf("SyncRepos = %v; want [github gitlab]", cfg.SyncRepos)
	}

	// Non-overridden fields must remain at their defaults (with the temp HOME).
	if cfg.EncAlg != "AES-256-CBC" {
		t.Errorf("EncAlg = %q; want AES-256-CBC", cfg.EncAlg)
	}
	if cfg.DataDir != filepath.Join(dir, "git", "foostoredb") {
		t.Errorf("DataDir = %q; want default", cfg.DataDir)
	}
}

// TestLoad_pathOverride calls Load() directly and verifies that a tilde path
// supplied via JSON is expanded to an absolute path after loading.
func TestLoad_pathOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	writeUserConfig(t, dir, `{"data_dir":"~/custom/vault"}`)

	cfg := Load()

	want := filepath.Join(dir, "custom", "vault")
	if cfg.DataDir != want {
		t.Errorf("DataDir = %q; want %q", cfg.DataDir, want)
	}
}

// TestLoad_invalid_json verifies that invalid JSON causes Load() to emit a
// warning to stderr and return defaults (including EditCmd = "vi" when EDITOR
// is unset).
func TestLoad_invalid_json(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("EDITOR", "") // ensure fallback to "vi"
	writeUserConfig(t, dir, `{invalid json}`)

	var cfg Config
	stderr := captureStderr(func() { cfg = Load() })

	if !strings.Contains(stderr, "Unable to read") {
		t.Errorf("expected warning on stderr, got: %q", stderr)
	}
	// Defaults must be returned with the redirected HOME.
	if cfg.EditCmd != "vi" {
		t.Errorf("EditCmd = %q; want vi (default)", cfg.EditCmd)
	}
	if cfg.KeyLength != 32 {
		t.Errorf("KeyLength = %d; want 32 (default)", cfg.KeyLength)
	}
}

// TestLoad_missing_file_no_warning verifies that a missing config file does NOT
// produce any output — absence is normal for a first-run or unconfigured install.
func TestLoad_missing_file_no_warning(t *testing.T) {
	dir := t.TempDir() // no foostore.json inside
	t.Setenv("HOME", dir)

	stderr := captureStderr(func() { _ = Load() })

	if stderr != "" {
		t.Errorf("expected no stderr output for missing file, got: %q", stderr)
	}
}

// TestLoad_unreadable_file verifies that a config file that exists but cannot
// be read emits a warning and returns defaults (the !os.IsNotExist branch).
// EDITOR is unset so EditCmd falls back to "vi".
func TestLoad_unreadable_file(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: permission checks do not apply")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("EDITOR", "") // ensure fallback to "vi"
	writeUserConfig(t, dir, `{"edit_cmd":"nvim"}`)

	// Make the file unreadable.
	cfgPath := filepath.Join(dir, ".config", "foostore.json")
	if err := os.Chmod(cfgPath, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgPath, 0o600) })

	var cfg Config
	stderr := captureStderr(func() { cfg = Load() })

	if !strings.Contains(stderr, "Unable to read") {
		t.Errorf("expected warning on stderr, got: %q", stderr)
	}
	// Must return pure defaults, not the file content.
	if cfg.EditCmd != "vi" {
		t.Errorf("EditCmd = %q; want vi (default)", cfg.EditCmd)
	}
}
