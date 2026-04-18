// Package store manages the foostore secret store on disk.
// It mirrors the Geheim class from the Ruby reference (geheim.rb lines 341-549),
// providing add/import/remove/search/export operations over the encrypted file pairs
// (.index + .data) stored in cfg.DataDir.
//
// The package is split into focused files:
//   - store.go        — Store type, constructor, walk/search (core business logic)
//   - store_crud.go   — add/import/remove/buildPair (mutation operations)
//   - store_picker.go — fzf/picker types, Fzf/FzfInteractive, key parsing
//   - store_shred.go  — ShredFile, ShredAllExported (secure deletion)
//   - data.go         — Data struct: encrypt/decrypt/export/reimport
//   - index.go        — Index struct: load, commit, remove, sort
//   - dependencies.go — Encryptor and Committer interfaces
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"codeberg.org/snonux/foostore/internal/config"
)

// Action describes what to do with each matching secret during a Search call.
type Action int

const (
	ActionNone       Action = iota // just list descriptions
	ActionCat                      // print decrypted content to stdout
	ActionPaste                    // copy to clipboard (caller handles via ActionFn)
	ActionExport                   // export to exportDir using basename of description
	ActionPathExport               // export to exportDir preserving full description path
	ActionOpen                     // export then open with OS viewer
	ActionEdit                     // export, edit in external editor, reimport
)

// Store provides all secret-store operations.
// regexCache avoids recompiling the same search-term regexp on every WalkIndexes call.
type Store struct {
	cfg        *config.Config
	cipher     Encryptor
	git        Committer
	regexCache map[string]*regexp.Regexp
}

// New creates a Store, ensuring cfg.DataDir exists on disk.
func New(cfg *config.Config, cipher Encryptor, g Committer) (*Store, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data directory %q: %w", cfg.DataDir, err)
	}

	return &Store{
		cfg:        cfg,
		cipher:     cipher,
		git:        g,
		regexCache: make(map[string]*regexp.Regexp),
	}, nil
}

// HashPath computes the SHA-256 hex digest of each "/"-separated path component
// and rejoins them with "/". Double slashes are normalised before splitting.
// This mirrors Ruby's Geheim#hash_path method exactly.
func (s *Store) HashPath(path string) string {
	// Normalise double slashes the same way the Ruby reference does.
	normalised := strings.ReplaceAll(path, "//", "/")
	parts := strings.Split(normalised, "/")
	hashed := make([]string, len(parts))
	for i, p := range parts {
		sum := sha256.Sum256([]byte(p))
		hashed[i] = hex.EncodeToString(sum[:])
	}
	return strings.Join(hashed, "/")
}

// WalkIndexes iterates over every .index file in cfg.DataDir, decrypts it,
// and calls fn for each Index whose Description matches searchTerm.
// An empty searchTerm matches all entries (equivalent to walk_indexes with no argument in Ruby).
// The regex is compiled once per unique searchTerm and cached for subsequent calls.
func (s *Store) WalkIndexes(ctx context.Context, searchTerm string, fn func(*Index) error) error {
	regex, err := s.compileRegex(searchTerm)
	if err != nil {
		return err
	}

	return filepath.WalkDir(s.cfg.DataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip the .git directory entirely — the data directory is a git repo
		// but no secrets live inside .git, so descending into it is wasteful
		// and may surface spurious errors if any path happens to end in ".index".
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".index") {
			return nil
		}
		return s.processIndexFile(ctx, path, searchTerm, regex, fn)
	})
}

// compileRegex returns a cached compiled regexp for the given search term.
// An empty term compiles to a regexp that matches everything.
func (s *Store) compileRegex(searchTerm string) (*regexp.Regexp, error) {
	if r, ok := s.regexCache[searchTerm]; ok {
		return r, nil
	}
	r, err := regexp.Compile(searchTerm)
	if err != nil {
		return nil, fmt.Errorf("invalid search term %q: %w", searchTerm, err)
	}
	s.regexCache[searchTerm] = r
	return r, nil
}

// processIndexFile loads and optionally matches a single .index file,
// calling fn when the description matches the regex.
func (s *Store) processIndexFile(ctx context.Context, path, searchTerm string, regex *regexp.Regexp, fn func(*Index) error) error {
	idx, err := loadIndex(ctx, path, s.cfg.DataDir, s.cipher)
	if err != nil {
		return fmt.Errorf("loading index %q: %w", path, err)
	}

	if searchTerm == "" || regex.MatchString(idx.Description) {
		return fn(idx)
	}
	return nil
}

// LoadData decrypts and returns the .data payload for the given index entry.
// The returned Data.WriteBack is populated with the geheim re-encrypt path so
// that ReimportAfterExport encrypts and git-stages the file via Commit, exactly
// as before the WriteBack hook was introduced.
func (s *Store) LoadData(ctx context.Context, idx *Index) (*Data, error) {
	if idx == nil {
		return nil, fmt.Errorf("loading data: nil index")
	}

	d, err := loadData(ctx, filepath.Join(s.cfg.DataDir, idx.DataFile), s.cipher, s.git)
	if err != nil {
		return nil, err
	}

	// Populate WriteBack so that ReimportAfterExport uses the standard
	// encrypt-and-git-stage path rather than relying on ReimportAfterExport's
	// built-in Commit fallback. This makes the hook explicit and keeps
	// backend-specific reimport logic out of the Data struct itself
	// (Open/Closed principle). d.Content is already set by ReimportAfterExport
	// before calling WriteBack, so no assignment is needed here.
	d.WriteBack = func(newContent []byte) error {
		// newContent is intentionally ignored here: ReimportAfterExport already
		// assigned it to d.Content before calling WriteBack, and Commit reads
		// d.Content directly.
		return d.Commit(ctx, true)
	}

	return d, nil
}

// Search collects all indexes matching searchTerm, sorts them by Description,
// and applies the given action to each. For ActionCat the decrypted content is
// printed; for ActionExport/ActionPathExport the content is written to ExportDir.
// Actions requiring external tools (paste, open, edit) are delegated to the
// optional actionFn callback — pass nil if those actions are not needed.
// The optional onMatch callback lets callers handle presentation concerns
// (for example, printing idx.String()) outside the store layer.
// Returns the sorted list of matching indexes for the caller's use.
func (s *Store) Search(
	ctx context.Context,
	searchTerm string,
	action Action,
	actionFn func(context.Context, *Index, *Data) error,
	onMatch func(*Index),
) ([]*Index, error) {
	var indexes IndexSlice
	if err := s.WalkIndexes(ctx, searchTerm, func(idx *Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return nil, err
	}

	sort.Sort(indexes)

	for _, idx := range indexes {
		if onMatch != nil {
			onMatch(idx)
		}
		if err := s.applyAction(ctx, idx, action, actionFn); err != nil {
			return indexes, err
		}
	}

	return indexes, nil
}

// applyAction executes the requested action for a single matching Index.
// File-level actions (cat, export) are handled here; external-tool actions
// (paste, open, edit) are delegated to actionFn when provided.
func (s *Store) applyAction(ctx context.Context, idx *Index, action Action, actionFn func(context.Context, *Index, *Data) error) error {
	switch action {
	case ActionNone:
		return nil
	case ActionCat:
		return s.actionCat(ctx, idx)
	case ActionExport:
		return s.actionExport(ctx, idx, false)
	case ActionPathExport:
		return s.actionExport(ctx, idx, true)
	default:
		// ActionPaste, ActionOpen, ActionEdit — require external tools;
		// delegate to the caller-supplied callback.
		// Use s.LoadData (exported) rather than the bare loadData so that
		// WriteBack is populated, enabling ReimportAfterExport (ActionEdit)
		// to encrypt and git-stage changes via the standard hook path.
		if actionFn != nil {
			d, err := s.LoadData(ctx, idx)
			if err != nil {
				return err
			}
			return actionFn(ctx, idx, d)
		}
	}
	return nil
}

// actionCat prints the decrypted content of an index entry to stdout.
// Binary entries are skipped with a warning, mirroring Ruby's behaviour.
func (s *Store) actionCat(ctx context.Context, idx *Index) error {
	if idx.IsBinary() {
		fmt.Println("Not displaying/pasting binary data!")
		return nil
	}
	d, err := loadData(ctx, filepath.Join(s.cfg.DataDir, idx.DataFile), s.cipher, s.git)
	if err != nil {
		return err
	}
	fmt.Print(d.String())
	return nil
}

// actionExport writes the decrypted content to cfg.ExportDir.
// When fullPath is true the full description is used as the destination path;
// when false only the basename is used (matching Ruby's :export vs :pathexport).
func (s *Store) actionExport(ctx context.Context, idx *Index, fullPath bool) error {
	d, err := loadData(ctx, filepath.Join(s.cfg.DataDir, idx.DataFile), s.cipher, s.git)
	if err != nil {
		return err
	}
	destFile := idx.Description
	if !fullPath {
		destFile = filepath.Base(idx.Description)
	}
	return d.Export(ctx, s.cfg.ExportDir, destFile)
}
