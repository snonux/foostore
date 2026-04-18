package migrate

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"codeberg.org/snonux/foostore/internal/keepass"
	"codeberg.org/snonux/foostore/internal/store"
)

// Options holds the resolved parameters for a geheim→KeePass migration run.
type Options struct {
	DryRun bool
}

// Stats accumulates counters for a migration run so callers can report progress.
type Stats struct {
	Total           int
	TextMigrated    int
	BinaryMigrated  int
	OverwrittenText int
	OverwrittenBin  int
	Errors          int
}

// StoreWalker is the subset of backend.Backend needed by the migrator. Using a
// narrow interface here avoids importing the full backend package and makes
// testing straightforward.
type StoreWalker interface {
	WalkIndexes(ctx context.Context, prefix string, fn func(*store.Index) error) error
	LoadData(ctx context.Context, idx *store.Index) (*store.Data, error)
}

// Run walks all index entries in src, migrating each one into kdbx.
// It returns aggregated Stats. When opts.DryRun is true, no writes are made
// to kdbx (kdbx may be nil in that case). logFn receives informational
// messages; warnFn receives per-entry error messages (should write to stderr).
// Neither may be nil.
func Run(ctx context.Context, src StoreWalker, kdbx KDBXStore, opts Options, logFn, warnFn func(string)) (Stats, error) {
	var indexes store.IndexSlice
	if err := src.WalkIndexes(ctx, "", func(idx *store.Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return Stats{}, fmt.Errorf("listing store entries: %w", err)
	}
	sort.Sort(indexes)

	var stats Stats
	for _, idx := range indexes {
		stats.Total++
		if err := migrateOneEntry(ctx, src, idx, opts, kdbx, &stats, logFn); err != nil {
			stats.Errors++
			// Per-entry errors go through warnFn so the caller can route them
			// to stderr, keeping informational log and error output separate.
			warnFn(err.Error())
		}
	}
	return stats, nil
}

// migrateOneEntry migrates a single index entry from src into kdbx (or logs
// the action when dry-run is active). Errors are returned so the caller can
// increment the error counter and continue.
func migrateOneEntry(
	ctx context.Context,
	src StoreWalker,
	idx *store.Index,
	opts Options,
	kdbx KDBXStore,
	stats *Stats,
	logFn func(string),
) error {
	safePath, err := keepass.SanitizeRelativePath(idx.Description)
	if err != nil {
		return fmt.Errorf("entry %q: %w", idx.Description, err)
	}

	d, err := src.LoadData(ctx, idx)
	if err != nil {
		return fmt.Errorf("loading data for %q: %w", idx.Description, err)
	}

	if idx.IsBinary() {
		return migrateBinaryEntry(idx, safePath, d.Content, opts, kdbx, stats, logFn)
	}
	return migrateTextEntry(idx, safePath, d.Content, opts, kdbx, stats, logFn)
}

// migrateBinaryEntry handles a binary (non-text) store entry.
func migrateBinaryEntry(
	idx *store.Index,
	safePath string,
	content []byte,
	opts Options,
	kdbx KDBXStore,
	stats *Stats,
	logFn func(string),
) error {
	groupPath, title, err := keepass.SplitDescriptionPath(safePath)
	if err != nil {
		return fmt.Errorf("mapping binary entry %q: %w", idx.Description, err)
	}
	if opts.DryRun {
		logFn(fmt.Sprintf("DRY-RUN binary migrate: %s -> attachment=%s", idx.Description, title))
		stats.BinaryMigrated++
		return nil
	}
	overwrote, err := kdbx.UpsertBinaryEntry(groupPath, title, title, content)
	if err != nil {
		return fmt.Errorf("upserting binary entry %q: %w", idx.Description, err)
	}
	if overwrote {
		stats.OverwrittenBin++
	}
	stats.BinaryMigrated++
	return nil
}

// migrateTextEntry handles a text (non-binary) store entry.
func migrateTextEntry(
	idx *store.Index,
	safePath string,
	content []byte,
	opts Options,
	kdbx KDBXStore,
	stats *Stats,
	logFn func(string),
) error {
	groupPath, title, err := keepass.SplitDescriptionPath(safePath)
	if err != nil {
		return fmt.Errorf("mapping text entry %q: %w", idx.Description, err)
	}
	if opts.DryRun {
		logFn(fmt.Sprintf("DRY-RUN text migrate: %s -> group=%q title=%q",
			idx.Description, strings.Join(groupPath, "/"), title))
		stats.TextMigrated++
		return nil
	}
	entryPassword, entryNotes := ExtractPasswordFromContent(string(content))
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

// passwordLinePattern matches lines like "password: s3cr3t" or "pass: s3cr3t"
// (case-insensitive) so that the password field can be extracted from entry content.
var passwordLinePattern = regexp.MustCompile(`(?i)^\s*(pass|password)\s*:\s*(.*)\s*$`)

// ExtractPasswordFromContent splits entry text content into a password (from
// the first "pass:" or "password:" line) and the remaining notes. The password
// line itself is removed from the notes output. This is exported so the CLI
// package can call it directly in tests without duplicating the logic.
func ExtractPasswordFromContent(content string) (password, notes string) {
	lines := strings.Split(content, "\n")
	notesLines := make([]string, 0, len(lines))

	for _, line := range lines {
		m := passwordLinePattern.FindStringSubmatch(line)
		if len(m) == 3 {
			// Take only the first password line encountered.
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
