// Package config handles loading and storing foostore configuration.
// Defaults mirror the Ruby reference (geheim.rb Config::DEFAULTS).
// A JSON file at ~/.config/foostore.json overrides individual fields;
// missing fields keep their default values because Go's json.Unmarshal
// only touches fields that are present in the JSON document.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// configPath is the location of the optional user config file.
	configPath = "~/.config/foostore.json"
	// fallbackHomeDirName is used when we cannot resolve a valid home directory.
	fallbackHomeDirName = "foostore-home"
)

// Config holds all application-wide configuration values.
// JSON field names use snake_case to match the original geheim.rb Config::DEFAULTS keys.
type Config struct {
	DataDir           string   `json:"data_dir"`
	ExportDir         string   `json:"export_dir"`
	KeyFile           string   `json:"key_file"`
	KeyLength         int      `json:"key_length"`
	EncAlg            string   `json:"enc_alg"`
	AddToIV           string   `json:"add_to_iv"`
	EditCmd           string   `json:"edit_cmd"`
	GnomeClipboardCmd string   `json:"gnome_clipboard_cmd"`
	MacOSClipboardCmd string   `json:"macos_clipboard_cmd"`
	SyncRepos         []string `json:"sync_repos"`
}

// resolveHomeDir resolves the current user's home directory from OS state.
// If resolution succeeds with os.UserHomeDir, error is nil.
// If resolution falls back to HOME or a temp-based directory, an explanatory
// non-nil error is returned so callers can warn without failing hard.
func resolveHomeDir() (string, error) {
	return resolveHomeDirFrom(os.UserHomeDir, os.Getenv("HOME"), os.TempDir())
}

// resolveHomeDirFrom is a test seam for home directory resolution.
func resolveHomeDirFrom(userHomeDir func() (string, error), envHome, tempDir string) (string, error) {
	home, err := userHomeDir()
	if err == nil && home != "" {
		return home, nil
	}

	if envHome != "" && filepath.IsAbs(envHome) {
		if err != nil {
			return envHome, fmt.Errorf("os.UserHomeDir failed; using HOME=%q: %w", envHome, err)
		}
		return envHome, fmt.Errorf("os.UserHomeDir returned empty home; using HOME=%q", envHome)
	}

	fallbackHome := filepath.Join(tempDir, fallbackHomeDirName)
	if envHome != "" && !filepath.IsAbs(envHome) {
		if err != nil {
			return fallbackHome, fmt.Errorf("os.UserHomeDir failed; HOME is not absolute (%q), using %q: %w", envHome, fallbackHome, err)
		}
		return fallbackHome, fmt.Errorf("os.UserHomeDir returned empty home; HOME is not absolute (%q), using %q", envHome, fallbackHome)
	}

	if err != nil {
		return fallbackHome, fmt.Errorf("os.UserHomeDir failed and HOME is unavailable; using %q: %w", fallbackHome, err)
	}
	return fallbackHome, fmt.Errorf("os.UserHomeDir returned empty home and HOME is unavailable; using %q", fallbackHome)
}

// homeDirOrFallback resolves a usable home path and logs fallback reasons.
func homeDirOrFallback() string {
	home, err := resolveHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}
	return home
}

// defaultConfigWithHome returns built-in defaults using the supplied home path.
func defaultConfigWithHome(home string) Config {
	// Prefer $EDITOR; fall back to vi if not set.
	editCmd := os.Getenv("EDITOR")
	if editCmd == "" {
		editCmd = "vi"
	}

	return Config{
		DataDir:           filepath.Join(home, "git", "foostoredb"),
		ExportDir:         filepath.Join(home, ".foostore-export"),
		KeyFile:           filepath.Join(home, ".foostore.key"),
		KeyLength:         32,
		EncAlg:            "AES-256-CBC",
		AddToIV:           "Hello world",
		EditCmd:           editCmd,
		GnomeClipboardCmd: "gpaste-client",
		MacOSClipboardCmd: "pbcopy",
		SyncRepos:         []string{"git1", "git2"},
	}
}

// defaultConfig returns a Config populated with built-in defaults.
// EditCmd honours the $EDITOR environment variable and falls back to "vi"
// when the variable is unset or empty, so users get their preferred editor
// automatically without touching the config file.
func defaultConfig() Config {
	return defaultConfigWithHome(homeDirOrFallback())
}

// expandTildeWithHome replaces a leading "~" in path with the supplied home.
func expandTildeWithHome(path, home string) string {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	// Replace only the leading "~"; preserve any subdirectory suffix.
	return home + path[1:]
}

// expandTilde replaces a leading "~" in path with the user's home directory.
// Non-tilde paths and empty strings are returned unchanged.
func expandTilde(path string) string {
	return expandTildeWithHome(path, homeDirOrFallback())
}

// expandPathFieldsWithHome tilde-expands every path-typed field in cfg in place.
func expandPathFieldsWithHome(cfg *Config, home string) {
	cfg.DataDir = expandTildeWithHome(cfg.DataDir, home)
	cfg.ExportDir = expandTildeWithHome(cfg.ExportDir, home)
	cfg.KeyFile = expandTildeWithHome(cfg.KeyFile, home)
}

// expandPathFields tilde-expands every path-typed field in cfg in place.
func expandPathFields(cfg *Config) {
	expandPathFieldsWithHome(cfg, homeDirOrFallback())
}

// Load reads ~/.config/foostore.json and merges it over the built-in defaults.
// Any field present in the JSON file overrides the corresponding default
// (including edit_cmd, which defaults to $EDITOR or "vi" when unset);
// fields absent from the file keep their default values.
// If the file is missing or contains invalid JSON a warning is printed to
// stderr and the pure defaults are returned.
// Note: the Ruby reference uses puts (stdout) for this warning; we use stderr
// intentionally because warnings belong on the error stream.
func Load() Config {
	home := homeDirOrFallback()
	cfg := defaultConfigWithHome(home)
	path := expandTildeWithHome(configPath, home)

	data, err := os.ReadFile(path)
	if err != nil {
		// File missing or unreadable — use defaults silently only when the
		// error is "not found"; otherwise warn the caller.
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Unable to read %s, using defaults! %v\n", path, err)
		}
		return cfg
	}

	// Unmarshal into the defaults struct so that only fields present in the
	// JSON document are overwritten; all others retain their default values.
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read %s, using defaults! %v\n", path, err)
		return defaultConfigWithHome(home)
	}

	// Tilde-expand path fields that may have been supplied as "~/…" strings
	// in the JSON file (defaultConfig() already returns absolute paths, but
	// user-supplied values might use "~").
	expandPathFieldsWithHome(&cfg, home)
	return cfg
}
