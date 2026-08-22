package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/snonux/foostore/internal/migrate"
)

// migrateKDBXOptions holds the parsed CLI flags for the migrate-kdbx command.
// Path fields are expanded (~ resolved, absolute) before use.
type migrateKDBXOptions struct {
	DBPath       string
	PassFile     string
	BinaryOutDir string
	DryRun       bool
}

// cmdMigrateKDBX is the CLI handler for "migrate-kdbx". It validates the active
// backend, parses flags, opens the KDBX database, runs the migration, and
// reports a summary. All migration business logic is delegated to internal/migrate.
//
// migrate-kdbx only makes sense when the source is the geheim backend.
// We check c.effectiveBackend (which incorporates the --backend flag override)
// rather than c.cfg.Backend so that "foostore --backend keepass migrate-kdbx"
// is correctly rejected even when cfg.Backend is empty.
func (c *CLI) cmdMigrateKDBX(ctx context.Context, argv []string) int {
	if c.effectiveBackend == "keepass" {
		warn("migrate-kdbx is not supported when the active backend is 'keepass'; it migrates geheim→keepass only")
		return 1
	}

	opts, err := c.parseMigrateKDBXOptions(argv)
	if err != nil {
		warn(err.Error())
		return 1
	}

	if err := os.MkdirAll(opts.BinaryOutDir, 0o700); err != nil {
		warn(fmt.Sprintf("creating binary output directory %q: %v", opts.BinaryOutDir, err))
		return 1
	}

	password, err := readPasswordFile(opts.PassFile)
	if err != nil {
		warn(err.Error())
		return 1
	}

	var kdbx migrate.KDBXStore
	if !opts.DryRun {
		opener := c.openKDBX
		if opener == nil {
			opener = migrate.OpenKDBXStore
		}
		kdbx, err = opener(opts.DBPath, password)
		if err != nil {
			warn(err.Error())
			return 1
		}
	}

	migrateOpts := migrate.Options{
		DryRun: opts.DryRun,
	}

	// logMsg routes informational messages to stdout; warn routes per-entry
	// errors to stderr so they are visually distinct and script-filterable.
	stats, err := migrate.Run(ctx, c.st, kdbx, migrateOpts, logMsg, warn)
	if err != nil {
		warn(err.Error())
		return 1
	}

	if !opts.DryRun {
		if err := kdbx.Save(); err != nil {
			warn(err.Error())
			return 1
		}
	}

	logMsg(fmt.Sprintf(
		"migrate-kdbx done: total=%d text_migrated=%d binary_migrated=%d overwritten_text=%d overwritten_binary=%d errors=%d db=%s binary_out=%s dry_run=%t",
		stats.Total,
		stats.TextMigrated,
		stats.BinaryMigrated,
		stats.OverwrittenText,
		stats.OverwrittenBin,
		stats.Errors,
		opts.DBPath,
		opts.BinaryOutDir,
		opts.DryRun,
	))

	if stats.Errors > 0 {
		return 1
	}
	return 0
}

// parseMigrateKDBXOptions parses the migrate-kdbx flags from argv and returns
// a migrateKDBXOptions with all paths resolved and validated.
func (c *CLI) parseMigrateKDBXOptions(argv []string) (migrateKDBXOptions, error) {
	now := c.now
	if now == nil {
		now = func() time.Time { return time.Now() }
	}
	home := resolveHomeDir()
	exportDir := filepath.Join(home, ".foostore-export")
	if c.cfg != nil && c.cfg.ExportDir != "" {
		exportDir = c.cfg.ExportDir
	}

	opts := migrateKDBXOptions{
		DBPath:       filepath.Join(home, "Documents", "Keepass", "master"),
		PassFile:     filepath.Join(home, ".master.pass"),
		BinaryOutDir: filepath.Join(exportDir, "keepass-binary-dump", now().Format("20060102-150405")),
	}

	for i := 1; i < len(argv); i++ {
		switch argv[i] {
		case "--db":
			i++
			if i >= len(argv) {
				return opts, fmt.Errorf("--db requires a value")
			}
			opts.DBPath = argv[i]
		case "--pass-file":
			i++
			if i >= len(argv) {
				return opts, fmt.Errorf("--pass-file requires a value")
			}
			opts.PassFile = argv[i]
		case "--binary-out":
			i++
			if i >= len(argv) {
				return opts, fmt.Errorf("--binary-out requires a value")
			}
			opts.BinaryOutDir = argv[i]
		case "--dry-run":
			opts.DryRun = true
		default:
			return opts, fmt.Errorf("unknown flag for migrate-kdbx: %s", argv[i])
		}
	}

	opts.DBPath = expandHome(opts.DBPath)
	opts.PassFile = expandHome(opts.PassFile)
	opts.BinaryOutDir = expandHome(opts.BinaryOutDir)

	if _, err := os.Stat(opts.DBPath); err != nil {
		return opts, fmt.Errorf("database file %q is not readable: %w", opts.DBPath, err)
	}
	if _, err := os.Stat(opts.PassFile); err != nil {
		return opts, fmt.Errorf("password file %q is not readable: %w", opts.PassFile, err)
	}
	return opts, nil
}
