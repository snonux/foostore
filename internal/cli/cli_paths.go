package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// readPasswordFile reads a password from a file, trimming trailing newlines.
// Returns an error when the file cannot be read or the result is empty.
// Used by both migrate-kdbx and the KeePass backend initialisation
// (cli_backend.go → readKeepassPassphrase).
func readPasswordFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading password file %q: %w", path, err)
	}
	pass := strings.TrimRight(string(data), "\r\n")
	if pass == "" {
		return "", fmt.Errorf("password file %q is empty", path)
	}
	return pass, nil
}

// resolveHomeDir returns the current user's home directory.
// Falls back to "." when os.UserHomeDir fails so callers always receive a
// non-empty path.
func resolveHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return home
}

// expandHome expands a leading "~" or "~/" to the current user's home directory.
// Paths that do not start with "~" are returned unchanged.
func expandHome(path string) string {
	if path == "~" {
		return resolveHomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(resolveHomeDir(), path[2:])
	}
	return path
}
