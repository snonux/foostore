// Package cli — backend factory.
//
// This file is responsible for instantiating the correct storage backend
// (geheim AES-encrypted store or KeePass) and its associated git client based
// on the effective backend name resolved from the --backend flag and config
// file.  None of the functions here touch the CLI struct or dispatch logic.
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"codeberg.org/snonux/foostore/internal/backend"
	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/crypto"
	"codeberg.org/snonux/foostore/internal/git"
	"codeberg.org/snonux/foostore/internal/keepass"
	"codeberg.org/snonux/foostore/internal/shell"
	"codeberg.org/snonux/foostore/internal/store"
)

// resolveBackend returns the effective backend name given the flag override and
// the config value.  flag takes precedence; config value is used next; the
// last-resort default is "keepass" (matching the config.defaultConfigWithHome
// default so that the two sources of truth stay in sync).
func resolveBackend(flagValue, cfgValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if cfgValue != "" {
		return cfgValue
	}
	return "keepass"
}

// buildBackend constructs the Backend and its associated Gitter based on
// effectiveBackend ("geheim" or "keepass").  Returns the Backend and git client
// so the caller can wire them into the CLI struct.
func buildBackend(ctx context.Context, cfg *config.Config, effectiveBackend string) (backend.Backend, git.Gitter, error) {
	switch effectiveBackend {
	case "keepass":
		return buildKeepassBackend(ctx, cfg)
	default:
		return buildGeheimBackend(cfg)
	}
}

// buildGeheimBackend initialises the original AES-encrypted geheim backend:
// reads the PIN, builds the cipher, creates a *store.Store, and points git at
// cfg.DataDir via buildGeheimGit.
func buildGeheimBackend(cfg *config.Config) (backend.Backend, git.Gitter, error) {
	pin, err := readPIN()
	if err != nil {
		return nil, nil, fmt.Errorf("reading PIN: %w", err)
	}

	ciph, err := crypto.NewCipher(cfg.KeyFile, cfg.KeyLength, pin, cfg.AddToIV)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising cipher: %w", err)
	}

	g := buildGeheimGit(cfg)

	st, err := store.New(cfg, ciph, g)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising store: %w", err)
	}

	return st, g, nil
}

// buildGeheimGit returns a *git.Git pointed at cfg.DataDir.  The geheim data
// directory is always a git repository (it is the store itself), so a real
// git client is always appropriate here — unlike the keepass backend which
// may live outside a repo and needs a NoOp fallback.
func buildGeheimGit(cfg *config.Config) git.Gitter {
	return git.New(cfg.DataDir)
}

// buildKeepassBackend reads the KeePass passphrase and optional key-file bytes,
// then instantiates a keepass.Backend.  The git client is pointed at the
// directory that contains the .kdbx file.
//
// If that directory is a git repository (detected via git rev-parse
// --is-inside-work-tree), a real *git.Git is returned so that sync/status/
// commit/reset operate normally against it.  If the directory is not a git
// repository, a *git.NoOp is returned instead — its methods print an
// informational message ("kdbx file is not in a git repo; skipping") and return
// nil, keeping the UX transparent without crashing.
func buildKeepassBackend(ctx context.Context, cfg *config.Config) (backend.Backend, git.Gitter, error) {
	passphrase, err := readKeepassPassphrase(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("reading keepass passphrase: %w", err)
	}

	keyFileData, err := readKeepassKeyFile(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("reading keepass key file: %w", err)
	}

	st, err := keepass.New(cfg, passphrase, keyFileData)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising keepass backend: %w", err)
	}

	g := buildKeepassGit(cfg.KDBXPath)
	return st, g, nil
}

// buildKeepassGit returns the appropriate Gitter for the directory containing
// the kdbx file.  When the directory is a git repository, a real *git.Git is
// returned.  Otherwise, a *git.NoOp is returned so that callers receive
// informational messages rather than errors when running git commands.
func buildKeepassGit(kdbxPath string) git.Gitter {
	kdbxDir := filepath.Dir(kdbxPath)
	if git.IsGitRepo(kdbxDir) {
		return git.New(kdbxDir)
	}
	return git.NewNoOp()
}

// readPIN returns the PIN string for encryption.  If the $PIN environment
// variable is set, it is used directly (matching the Ruby ENV['PIN'] check).
// Otherwise the user is prompted with masked input via the shell package.
func readPIN() (string, error) {
	if pin := os.Getenv("PIN"); pin != "" {
		return pin, nil
	}

	pin, err := shell.ReadPassword("< PIN: ")
	if err != nil {
		return "", fmt.Errorf("reading PIN from terminal: %w", err)
	}
	return pin, nil
}

// readKeepassPassphrase resolves the KeePass database passphrase using the
// following priority: $PIN env var → cfg.KDBXPassFile → interactive prompt.
// This mirrors the geheim readPIN() priority while accommodating the extra
// KDBXPassFile option specific to the keepass backend.
func readKeepassPassphrase(cfg *config.Config) (string, error) {
	// 1. $PIN environment variable — same as geheim backend for symmetry.
	if pin := os.Getenv("PIN"); pin != "" {
		return pin, nil
	}

	// 2. KDBXPassFile — a file containing the password (trimmed of newlines).
	// readPasswordFile is defined in migrate_kdbx.go and shared here.
	if cfg.KDBXPassFile != "" {
		pass, err := readPasswordFile(cfg.KDBXPassFile)
		if err != nil {
			return "", fmt.Errorf("reading KDBXPassFile: %w", err)
		}
		return pass, nil
	}

	// 3. Interactive prompt — same mechanism as geheim's PIN prompt.
	pass, err := shell.ReadPassword("< KeePass passphrase: ")
	if err != nil {
		return "", fmt.Errorf("reading passphrase from terminal: %w", err)
	}
	return pass, nil
}

// readKeepassKeyFile reads the optional KeePass key-file bytes.  Returns nil
// when cfg.KDBXKeyFile is empty (password-only authentication).
func readKeepassKeyFile(cfg *config.Config) ([]byte, error) {
	if cfg.KDBXKeyFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(cfg.KDBXKeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", cfg.KDBXKeyFile, err)
	}
	return data, nil
}
