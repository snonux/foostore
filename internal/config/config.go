// Package config handles loading and storing geheim configuration.
// Defaults mirror the Ruby reference (geheim.rb Config::DEFAULTS).
// A JSON file at ~/.config/geheim.json overrides individual fields;
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

// configPath is the location of the optional user config file.
const configPath = "~/.config/foostore.json"

// Config holds all application-wide configuration values.
// JSON field names use snake_case to match geheim.rb Config::DEFAULTS keys.
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

// defaultConfig returns a Config populated with the same defaults as the
// Ruby reference implementation's Config::DEFAULTS.  It calls
// os.UserHomeDir() so that path fields expand correctly at runtime.
func defaultConfig() Config {
	home, _ := os.UserHomeDir()
	return Config{
		DataDir:           filepath.Join(home, "git", "geheimlager"),
		ExportDir:         filepath.Join(home, ".geheimlagerexport"),
		KeyFile:           filepath.Join(home, ".geheimlager.key"),
		KeyLength:         32,
		EncAlg:            "AES-256-CBC",
		AddToIV:           "Hello world",
		EditCmd:           "hx",
		GnomeClipboardCmd: "gpaste-client",
		MacOSClipboardCmd: "pbcopy",
		SyncRepos:         []string{"git1", "git2"},
	}
}

// expandTilde replaces a leading "~" in path with the user's home directory.
// Non-tilde paths and empty strings are returned unchanged.
func expandTilde(path string) string {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	home, _ := os.UserHomeDir()
	// Replace only the leading "~"; preserve any subdirectory suffix.
	return home + path[1:]
}

// expandPathFields tilde-expands every path-typed field in cfg in place.
func expandPathFields(cfg *Config) {
	cfg.DataDir = expandTilde(cfg.DataDir)
	cfg.ExportDir = expandTilde(cfg.ExportDir)
	cfg.KeyFile = expandTilde(cfg.KeyFile)
}

// Load reads ~/.config/geheim.json and merges it over the built-in defaults.
// Any field present in the JSON file overrides the corresponding default;
// fields absent from the file keep their default values.
// If the file is missing or contains invalid JSON a warning is printed to
// stderr and the pure defaults are returned.
// Note: the Ruby reference uses puts (stdout) for this warning; we use stderr
// intentionally because warnings belong on the error stream.
func Load() Config {
	cfg := defaultConfig()
	path := expandTilde(configPath)

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
		return defaultConfig()
	}

	// Tilde-expand path fields that may have been supplied as "~/…" strings
	// in the JSON file (defaultConfig() already returns absolute paths, but
	// user-supplied values might use "~").
	expandPathFields(&cfg)
	return cfg
}
