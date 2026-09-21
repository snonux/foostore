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
// The Backend field selects the storage backend: "keepass" (default, a .kdbx
// database file) or "geheim" (encrypted .index/.data files in a git repo).
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

	// Backend selects the storage backend: "keepass" (default) or "geheim".
	Backend string `json:"backend"`
	// KDBXPath is the path to the KeePass .kdbx database file.
	// Defaults to ~/Documents/Keepass/master.kdbx.
	KDBXPath string `json:"kdbx_path"`
	// KDBXKeyFile is the optional path to a KeePass key file.
	// An empty value disables key file authentication.
	KDBXKeyFile string `json:"kdbx_key_file"`
	// KDBXPassFile is the optional path to a file containing the KeePass password.
	// Defaults to ~/.master.pass to match migrate-kdbx defaults.
	// When empty, the password is read interactively at startup.
	KDBXPassFile string `json:"kdbx_pass_file"`
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

		// Backend defaults to "keepass" so new users get the KeePass backend
		// out of the box.  Existing geheim users must set backend="geheim" in
		// ~/.config/foostore.json to keep their existing behaviour.
		// KDBXPath and KDBXPassFile defaults mirror the migrate-kdbx command
		// at internal/cli/migrate_kdbx.go so users who already use that command
		// have zero additional configuration to provide.
		Backend:      "keepass",
		KDBXPath:     filepath.Join(home, "Documents", "Keepass", "master.kdbx"),
		KDBXKeyFile:  "",
		KDBXPassFile: filepath.Join(home, ".master.pass"),
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
// This covers both the geheim fields (DataDir, ExportDir, KeyFile) and the
// KeePass fields (KDBXPath, KDBXKeyFile, KDBXPassFile).
func expandPathFieldsWithHome(cfg *Config, home string) {
	cfg.DataDir = expandTildeWithHome(cfg.DataDir, home)
	cfg.ExportDir = expandTildeWithHome(cfg.ExportDir, home)
	cfg.KeyFile = expandTildeWithHome(cfg.KeyFile, home)
	cfg.KDBXPath = expandTildeWithHome(cfg.KDBXPath, home)
	cfg.KDBXKeyFile = expandTildeWithHome(cfg.KDBXKeyFile, home)
	cfg.KDBXPassFile = expandTildeWithHome(cfg.KDBXPassFile, home)
}

// expandPathFields tilde-expands every path-typed field in cfg in place.
func expandPathFields(cfg *Config) {
	expandPathFieldsWithHome(cfg, homeDirOrFallback())
}

// Load reads ~/.config/foostore.json and merges it over the built-in defaults.
// Any field present in the JSON file overrides the corresponding default
// (including edit_cmd, which defaults to $EDITOR or "vi" when unset);
// fields absent from the file keep their default values.
// If the file is unreadable or contains invalid JSON a warning is printed to
// stderr and the pure defaults are returned; a missing file silently yields
// the defaults.
// Note: the Ruby reference uses puts (stdout) for this warning; we use stderr
// intentionally because warnings belong on the error stream.
func Load() Config {
	cfg, path, _, err := loadFrom(homeDirOrFallback())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read %s, using defaults! %v\n", path, err)
	}
	return cfg
}

// LoadStrict is Load for callers that must not silently substitute defaults
// for a broken configuration (the machine-facing read command: falling back
// to the default database and credential sources could read from the wrong
// store). A missing config file is still fine — defaults are the documented
// behaviour — but an unreadable file or invalid JSON is returned as an error,
// and so is an unresolvable home directory: Load's shared-temp-dir fallback
// would let anyone able to write there plant a config that redirects the read.
//
// The credential file is also never taken from a built-in default: unless the
// config file itself sets kdbx_pass_file, the returned KDBXPassFile is empty,
// so an owner-only ~/.master.pass that the operator never pointed a machine
// read at cannot be picked up silently.
func LoadStrict() (Config, error) {
	home, err := resolveHomeDir()
	if err != nil {
		return Config{}, fmt.Errorf("cannot resolve the home directory for the config file: %w", err)
	}
	cfg, path, passFileSet, err := loadFrom(home)
	if err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	if !passFileSet {
		cfg.KDBXPassFile = ""
	}
	return cfg, nil
}

// loadFrom implements Load and LoadStrict for the given home directory. It
// also reports whether the config file itself set a non-empty kdbx_pass_file,
// so callers can tell an operator's choice from a built-in default. That is
// decided by decoding the key the same way the config is decoded (so key
// spelling is matched identically, and a JSON null counts as unset), not by
// scanning raw key names. On a read or parse failure it returns the pure
// defaults together with the config path and the error, leaving the
// warn-or-fail decision to the caller.
func loadFrom(home string) (Config, string, bool, error) {
	cfg := defaultConfigWithHome(home)
	path := expandTildeWithHome(configPath, home)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, path, false, nil
		}
		return cfg, path, false, err
	}

	// Unmarshal into the defaults struct so that only fields present in the
	// JSON document are overwritten; all others retain their default values.
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defaultConfigWithHome(home), path, false, err
	}
	var probe struct {
		KDBXPassFile *string `json:"kdbx_pass_file"`
	}
	passFileSet := json.Unmarshal(data, &probe) == nil && probe.KDBXPassFile != nil && *probe.KDBXPassFile != ""

	// Tilde-expand path fields that may have been supplied as "~/…" strings
	// in the JSON file (defaultConfig() already returns absolute paths, but
	// user-supplied values might use "~").
	expandPathFieldsWithHome(&cfg, home)
	return cfg, path, passFileSet, nil
}
