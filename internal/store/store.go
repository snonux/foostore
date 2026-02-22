// Package store manages the foostore secret store on disk.
// It mirrors the Geheim class from the Ruby reference (geheim.rb lines 341-549),
// providing add/import/remove/search/export operations over the encrypted file pairs
// (.index + .data) stored in cfg.DataDir.
package store

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/crypto"
	"codeberg.org/snonux/foostore/internal/git"
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
	cipher     *crypto.Cipher
	git        *git.Git
	regexCache map[string]*regexp.Regexp
}

// New creates a Store, ensuring cfg.DataDir exists on disk.
func New(cfg *config.Config, cipher *crypto.Cipher, g *git.Git) (*Store, error) {
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

// Search collects all indexes matching searchTerm, sorts them by Description,
// and applies the given action to each. For ActionCat the decrypted content is
// printed; for ActionExport/ActionPathExport the content is written to ExportDir.
// Actions requiring external tools (paste, open, edit) are delegated to the
// optional actionFn callback — pass nil if those actions are not needed.
// Returns the sorted list of matching indexes for the caller's use.
func (s *Store) Search(ctx context.Context, searchTerm string, action Action, actionFn func(context.Context, *Index, *Data) error) ([]*Index, error) {
	var indexes IndexSlice
	if err := s.WalkIndexes(ctx, searchTerm, func(idx *Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return nil, err
	}

	sort.Sort(indexes)

	for _, idx := range indexes {
		fmt.Print(idx.String())
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
		if actionFn != nil {
			d, err := loadData(ctx, filepath.Join(s.cfg.DataDir, idx.DataFile), s.cipher)
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
	d, err := loadData(ctx, filepath.Join(s.cfg.DataDir, idx.DataFile), s.cipher)
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
	d, err := loadData(ctx, filepath.Join(s.cfg.DataDir, idx.DataFile), s.cipher)
	if err != nil {
		return err
	}
	destFile := idx.Description
	if !fullPath {
		destFile = filepath.Base(idx.Description)
	}
	return d.Export(ctx, s.cfg.ExportDir, destFile)
}

// Fzf launches fzf with all index entries piped to its stdin and returns the
// description of the entry the user selected. All entries are collected first
// so that cipher initialisation happens before the pipe is opened (matching
// the Ruby note: "Need to read an index first before opening the pipe to
// initialize the encryption PIN").
// Returns ("", nil) when fzf is not installed or the user presses Escape.
func (s *Store) Fzf(ctx context.Context) (string, error) {
	// Collect all entries before opening the fzf pipe so the cipher is ready.
	var entries []string
	if err := s.WalkIndexes(ctx, "", func(idx *Index) error {
		entries = append(entries, idx.String())
		return nil
	}); err != nil {
		return "", err
	}

	if len(entries) == 0 {
		return "", nil
	}

	return runFzf(ctx, entries)
}

// runFzf pipes entries to fzf and returns the description of the selected line.
// Returns ("", nil) if fzf exits with a non-zero status (user cancelled).
func runFzf(ctx context.Context, entries []string) (string, error) {
	cmd := exec.CommandContext(ctx, "fzf")
	cmd.Stdin = strings.NewReader(strings.Join(entries, ""))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Any non-zero exit from fzf (e.g., 130 for Escape, 1 for no match)
		// is treated as no selection — the caller receives ("", nil).
		return "", nil
	}

	line := strings.TrimRight(out.String(), "\n")
	if line == "" {
		return "", nil
	}
	// The format is "<description>; (BINARY) ...<hashSuffix>\n" — take the part before ";".
	return strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), nil
}

// Add stores a new secret with the given description and plaintext data.
// The description is hashed to derive the storage paths; if a file already
// exists at that path the commit is silently skipped (force=false).
func (s *Store) Add(ctx context.Context, description, data string) error {
	hash := s.HashPath(description)
	idx, dataObj := s.buildPair(description, hash)
	dataObj.Content = []byte(data)

	if err := dataObj.Commit(ctx, s.cipher, s.git, false); err != nil {
		return fmt.Errorf("committing data for %q: %w", description, err)
	}
	if err := idx.CommitIndex(ctx, s.cipher, s.git, false); err != nil {
		return fmt.Errorf("committing index for %q: %w", description, err)
	}
	return nil
}

// Import reads a file from srcPath and stores it under destPath in the store.
// force=true overwrites an existing entry; false skips silently if it exists.
func (s *Store) Import(ctx context.Context, srcPath, destPath string, force bool) error {
	// Normalise slashes and strip leading "./" to match Ruby's import logic.
	srcPath = strings.ReplaceAll(srcPath, "//", "/")
	srcPath = strings.TrimPrefix(srcPath, "./")

	content, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading source file %q: %w", srcPath, err)
	}

	hash := s.HashPath(destPath)
	idx, dataObj := s.buildPair(destPath, hash)
	dataObj.Content = content

	if err := dataObj.Commit(ctx, s.cipher, s.git, force); err != nil {
		return fmt.Errorf("committing data for %q: %w", destPath, err)
	}
	if err := idx.CommitIndex(ctx, s.cipher, s.git, force); err != nil {
		return fmt.Errorf("committing index for %q: %w", destPath, err)
	}
	return nil
}

// ImportRecursive walks directory and imports every regular file under destDir.
// The description for each file is its path relative to the source directory.
// Note: the Ruby import_recursive flattens subdirectories to basename in the
// hash/storage path while preserving the full relative path only in the
// description. Go preserves the full subpath in both description and hash path.
// The compatibility verification task (355) will surface any impact on live data.
func (s *Store) ImportRecursive(ctx context.Context, directory, destDir string) error {
	return filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Derive the destination path from the file's position inside directory.
		relFile := strings.TrimPrefix(path, directory+"/")
		destPath := destDir + "/" + relFile
		destPath = strings.ReplaceAll(destPath, "//", "/")

		return s.Import(ctx, path, destPath, false)
	})
}

// Remove finds all indexes matching searchTerm, prints each one, and prompts
// the user interactively before deleting the index+data pair. Mirrors Ruby's rm.
// Pass os.Stdin as the reader for interactive use; a strings.Reader in tests.
func (s *Store) Remove(ctx context.Context, searchTerm string, input io.Reader) error {
	var indexes IndexSlice
	if err := s.WalkIndexes(ctx, searchTerm, func(idx *Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return err
	}

	sort.Sort(indexes)

	scanner := bufio.NewScanner(input)
	for _, idx := range indexes {
		if err := s.confirmAndRemove(ctx, idx, scanner); err != nil {
			return err
		}
	}
	return nil
}

// confirmAndRemove prompts the user to confirm deletion of a single entry,
// then removes both the .data and .index files via git rm on confirmation.
func (s *Store) confirmAndRemove(ctx context.Context, idx *Index, scanner *bufio.Scanner) error {
	for {
		fmt.Print(idx.String())
		fmt.Print("You really want to delete this? (y/n): ")

		if !scanner.Scan() {
			return nil
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "y":
			dataPath := filepath.Join(s.cfg.DataDir, idx.DataFile)
			d := &Data{DataPath: dataPath}
			if err := d.Remove(ctx, s.git); err != nil {
				return fmt.Errorf("removing data file: %w", err)
			}
			if err := idx.Remove(ctx, s.git); err != nil {
				return fmt.Errorf("removing index file: %w", err)
			}
			return nil
		case "n":
			return nil
		}
		// Any other input: loop and ask again.
	}
}

// ShredAllExported removes (shreds) every regular file in cfg.ExportDir.
// Uses GNU shred when available; falls back to "rm -Pfv" otherwise.
// Mirrors Ruby's shred_all_exported: iterates all files and returns the last
// non-nil error so that as many files as possible are shredded even on failure.
func (s *Store) ShredAllExported(ctx context.Context) error {
	entries, err := filepath.Glob(filepath.Join(s.cfg.ExportDir, "*"))
	if err != nil {
		return fmt.Errorf("listing export dir: %w", err)
	}

	var lastErr error
	for _, entry := range entries {
		info, err := os.Stat(entry)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := shredFile(ctx, entry); err != nil {
			// Record the error but keep shredding — security demands best-effort
			// destruction of all exported secrets even if one fails.
			lastErr = err
		}
	}
	return lastErr
}

// shredFile destroys a single file using shred(1) if available, or rm -Pfv.
// This mirrors Ruby's Geheim#shred_file method.
func shredFile(ctx context.Context, filePath string) error {
	if _, err := exec.LookPath("shred"); err == nil {
		cmd := exec.CommandContext(ctx, "shred", "-vu", filePath)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return cmd.Run()
	}
	cmd := exec.CommandContext(ctx, "rm", "-Pfv", filePath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// buildPair constructs an Index and Data struct pair for the given description
// and pre-computed hash path. Both structs share the same derived paths.
func (s *Store) buildPair(description, hash string) (*Index, *Data) {
	indexPath := filepath.Join(s.cfg.DataDir, hash+".index")
	dataPath := filepath.Join(s.cfg.DataDir, hash+".data")
	// filepath.Base of the hash gives the final path component (the filename stem).
	hashBase := filepath.Base(hash)

	idx := &Index{
		Description: description,
		DataFile:    hash + ".data",
		IndexPath:   indexPath,
		Hash:        hashBase,
	}
	dataObj := &Data{
		DataPath: dataPath,
	}
	return idx, dataObj
}
