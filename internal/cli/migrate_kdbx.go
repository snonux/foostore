package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"codeberg.org/snonux/foostore/internal/store"
)

type migrateKDBXOptions struct {
	DBPath       string
	PassFile     string
	BinaryOutDir string
	DryRun       bool
}

type migrateKDBXStats struct {
	Total           int
	TextMigrated    int
	BinaryMigrated  int
	OverwrittenText int
	OverwrittenBin  int
	Errors          int
}

func (c *CLI) cmdMigrateKDBX(ctx context.Context, argv []string) int {
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

	var kdbx KDBXStore
	if !opts.DryRun {
		opener := c.openKDBX
		if opener == nil {
			opener = OpenKDBXStore
		}
		kdbx, err = opener(opts.DBPath, password)
		if err != nil {
			warn(err.Error())
			return 1
		}
	}

	var indexes store.IndexSlice
	if err := c.st.WalkIndexes(ctx, "", func(idx *store.Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		warn(fmt.Sprintf("listing store entries: %v", err))
		return 1
	}
	sort.Sort(indexes)

	stats := migrateKDBXStats{}
	for _, idx := range indexes {
		stats.Total++
		if err := c.migrateOneEntry(ctx, idx, opts, kdbx, &stats); err != nil {
			stats.Errors++
			warn(err.Error())
		}
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

func (c *CLI) migrateOneEntry(ctx context.Context, idx *store.Index, opts migrateKDBXOptions, kdbx KDBXStore, stats *migrateKDBXStats) error {
	safePath, err := sanitizeRelativePath(idx.Description)
	if err != nil {
		return fmt.Errorf("entry %q: %w", idx.Description, err)
	}

	d, err := c.st.LoadData(ctx, idx)
	if err != nil {
		return fmt.Errorf("loading data for %q: %w", idx.Description, err)
	}

	if idx.IsBinary() {
		groupPath, title, err := splitDescriptionPath(safePath)
		if err != nil {
			return fmt.Errorf("mapping binary entry %q: %w", idx.Description, err)
		}
		if opts.DryRun {
			logMsg(fmt.Sprintf("DRY-RUN binary migrate: %s -> attachment=%s", idx.Description, title))
			stats.BinaryMigrated++
			return nil
		}
		overwrote, err := kdbx.UpsertBinaryEntry(groupPath, title, title, d.Content)
		if err != nil {
			return fmt.Errorf("upserting binary entry %q: %w", idx.Description, err)
		}
		if overwrote {
			stats.OverwrittenBin++
		}
		stats.BinaryMigrated++
		return nil
	}

	groupPath, title, err := splitDescriptionPath(safePath)
	if err != nil {
		return fmt.Errorf("mapping text entry %q: %w", idx.Description, err)
	}
	if opts.DryRun {
		logMsg(fmt.Sprintf("DRY-RUN text migrate: %s -> group=%q title=%q", idx.Description, strings.Join(groupPath, "/"), title))
		stats.TextMigrated++
		return nil
	}

	entryPassword, entryNotes := extractPasswordFromContent(string(d.Content))
	overwrote, err := kdbx.UpsertTextEntry(groupPath, title, entryPassword, entryNotes)
	if err != nil {
		return fmt.Errorf("upserting text entry %q: %w", idx.Description, err)
	}
	if overwrote {
		stats.OverwrittenText++
	}
	stats.TextMigrated++
	return nil
}

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

func resolveHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return home
}

func expandHome(path string) string {
	if path == "~" {
		return resolveHomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(resolveHomeDir(), path[2:])
	}
	return path
}

var passwordLinePattern = regexp.MustCompile(`(?i)^\s*(pass|password)\s*:\s*(.*)\s*$`)

func extractPasswordFromContent(content string) (password, notes string) {
	lines := strings.Split(content, "\n")
	notesLines := make([]string, 0, len(lines))

	for _, line := range lines {
		m := passwordLinePattern.FindStringSubmatch(line)
		if len(m) == 3 {
			if password == "" {
				password = strings.TrimSpace(m[2])
			}
			continue
		}
		notesLines = append(notesLines, line)
	}

	notes = strings.TrimRight(strings.Join(notesLines, "\n"), "\n")
	return password, notes
}
