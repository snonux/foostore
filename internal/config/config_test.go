package config

import (
	"bytes"
	"io"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// homeDir is a test helper that returns the current user's home directory,
// panicking if it cannot be determined (should never happen in tests).
func homeDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	return home
}

// writeConfigFile creates a temporary directory, writes content to
// geheim.json inside it, and returns the file path.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "geheim.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// loadFromPath replicates the Load() merge logic against an arbitrary file
// path instead of the real ~/.config/geheim.json, so tests don't need to
// redirect HOME or touch the real user config.
func loadFromPath(path string) Config {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defaultConfig()
	}
	expandPathFields(&cfg)
	return cfg
}

// ---- tests ------------------------------------------------------------------

// TestExpandTilde verifies all three cases: tilde prefix, no tilde, empty string.
func TestExpandTilde(t *testing.T) {
	home := homeDir(t)

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

// TestLoad_defaults verifies that Load() returns fully-expanded default values
// when the config file does not exist.  HOME is redirected to a temp dir so
// Load() looks for a config file that is guaranteed not to exist.
func TestLoad_defaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := Load()
	home := dir // HOME was redirected, defaultConfig() uses the new value

	if cfg.DataDir != filepath.Join(home, "git", "geheimlager") {
		t.Errorf("DataDir = %q; want %q", cfg.DataDir, filepath.Join(home, "git", "geheimlager"))
	}
	if cfg.ExportDir != filepath.Join(home, ".geheimlagerexport") {
		t.Errorf("ExportDir = %q; want %q", cfg.ExportDir, filepath.Join(home, ".geheimlagerexport"))
	}
	if cfg.KeyFile != filepath.Join(home, ".geheimlager.key") {
		t.Errorf("KeyFile = %q; want %q", cfg.KeyFile, filepath.Join(home, ".geheimlager.key"))
	}
	if cfg.KeyLength != 32 {
		t.Errorf("KeyLength = %d; want 32", cfg.KeyLength)
	}
	if cfg.EncAlg != "AES-256-CBC" {
		t.Errorf("EncAlg = %q; want AES-256-CBC", cfg.EncAlg)
	}
	if cfg.AddToIV != "Hello world" {
		t.Errorf("AddToIV = %q; want 'Hello world'", cfg.AddToIV)
	}
	if cfg.EditCmd != "hx" {
		t.Errorf("EditCmd = %q; want hx", cfg.EditCmd)
	}
	if cfg.GnomeClipboardCmd != "gpaste-client" {
		t.Errorf("GnomeClipboardCmd = %q; want gpaste-client", cfg.GnomeClipboardCmd)
	}
	if cfg.MacOSClipboardCmd != "pbcopy" {
		t.Errorf("MacOSClipboardCmd = %q; want pbcopy", cfg.MacOSClipboardCmd)
	}
	if len(cfg.SyncRepos) != 2 || cfg.SyncRepos[0] != "git1" || cfg.SyncRepos[1] != "git2" {
		t.Errorf("SyncRepos = %v; want [git1 git2]", cfg.SyncRepos)
	}
}

// TestLoad_override verifies that fields present in the JSON file override
// defaults while absent fields retain their default values.
func TestLoad_override(t *testing.T) {
	jsonContent := `{"edit_cmd":"nvim","key_length":64,"sync_repos":["github","gitlab"]}`
	path := writeConfigFile(t, jsonContent)

	cfg := loadFromPath(path)

	// Overridden fields.
	if cfg.EditCmd != "nvim" {
		t.Errorf("EditCmd = %q; want nvim", cfg.EditCmd)
	}
	if cfg.KeyLength != 64 {
		t.Errorf("KeyLength = %d; want 64", cfg.KeyLength)
	}
	if len(cfg.SyncRepos) != 2 || cfg.SyncRepos[0] != "github" || cfg.SyncRepos[1] != "gitlab" {
		t.Errorf("SyncRepos = %v; want [github gitlab]", cfg.SyncRepos)
	}

	// Non-overridden fields must keep their defaults.
	home := homeDir(t)
	if cfg.EncAlg != "AES-256-CBC" {
		t.Errorf("EncAlg = %q; want AES-256-CBC", cfg.EncAlg)
	}
	if cfg.DataDir != filepath.Join(home, "git", "geheimlager") {
		t.Errorf("DataDir = %q; want default", cfg.DataDir)
	}
}

// TestLoad_pathOverride verifies that tilde paths supplied via JSON are
// expanded to absolute paths after loading.
func TestLoad_pathOverride(t *testing.T) {
	home := homeDir(t)
	jsonContent := `{"data_dir":"~/custom/vault"}`
	path := writeConfigFile(t, jsonContent)

	cfg := loadFromPath(path)

	want := filepath.Join(home, "custom", "vault")
	if cfg.DataDir != want {
		t.Errorf("DataDir = %q; want %q", cfg.DataDir, want)
	}
}

// TestLoad_invalid_json verifies that invalid JSON causes Load() to return
// defaults and print a warning to stderr.
func TestLoad_invalid_json(t *testing.T) {
	// Write invalid JSON to the expected config location inside a temp HOME.
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, ".config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	badJSON := filepath.Join(cfgDir, "geheim.json")
	if err := os.WriteFile(badJSON, []byte("{invalid json}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Capture stderr to verify the warning message is emitted.
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	t.Setenv("HOME", dir)

	cfg := Load()

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	stderrOutput := buf.String()

	if !strings.Contains(stderrOutput, "Unable to read") {
		t.Errorf("expected warning on stderr, got: %q", stderrOutput)
	}

	// Returned config must equal defaults (with the redirected HOME).
	if cfg.EditCmd != "hx" {
		t.Errorf("EditCmd = %q; want hx (default)", cfg.EditCmd)
	}
	if cfg.KeyLength != 32 {
		t.Errorf("KeyLength = %d; want 32 (default)", cfg.KeyLength)
	}
}

// TestLoad_missing_file_no_warning verifies that a missing config file does
// NOT produce a warning on stderr — absence of the file is a normal condition
// (first run or unconfigured installation).
func TestLoad_missing_file_no_warning(t *testing.T) {
	dir := t.TempDir() // no geheim.json inside

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	t.Setenv("HOME", dir)

	_ = Load()

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if buf.Len() != 0 {
		t.Errorf("expected no stderr output for missing file, got: %q", buf.String())
	}
}
