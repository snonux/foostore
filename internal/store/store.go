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
	"strconv"
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

// PickerAction describes the action requested from the interactive fzf picker.
type PickerAction string

const (
	PickerSelect PickerAction = "select"
	PickerCat    PickerAction = "cat"
	PickerPaste  PickerAction = "paste"
	PickerOpen   PickerAction = "open"
	PickerEdit   PickerAction = "edit"
)

// PickerResult is the selected description plus the desired action from fzf.
// Description is empty when the picker was cancelled.
type PickerResult struct {
	Description string
	Action      PickerAction
}

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

type pickerEntry struct {
	rowID       int
	description string
	kind        string
	hashSuffix  string
}

// Fzf launches fzf and returns only the selected description for compatibility
// with callers that do not care about picker action keys.
func (s *Store) Fzf(ctx context.Context) (string, error) {
	result, err := s.FzfInteractive(ctx)
	if err != nil {
		return "", err
	}
	return result.Description, nil
}

// FzfInteractive launches fzf with helper bars, preview metadata, and action
// key bindings, then returns both the selected description and action.
func (s *Store) FzfInteractive(ctx context.Context) (PickerResult, error) {
	var indexes IndexSlice
	if err := s.WalkIndexes(ctx, "", func(idx *Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return PickerResult{}, err
	}
	if len(indexes) == 0 {
		return PickerResult{}, nil
	}

	sort.Sort(indexes)
	entries := make([]pickerEntry, 0, len(indexes))
	for i, idx := range indexes {
		kind := "TEXT"
		if idx.IsBinary() {
			kind = "BINARY"
		}
		hashSuffix := ""
		if len(idx.Hash) >= 63 {
			hashSuffix = idx.Hash[53:63]
		}
		entries = append(entries, pickerEntry{
			rowID:       i + 1,
			description: idx.Description,
			kind:        kind,
			hashSuffix:  hashSuffix,
		})
	}

	return runFzfInteractive(ctx, entries)
}

func runFzfInteractive(ctx context.Context, entries []pickerEntry) (PickerResult, error) {
	if len(entries) == 0 {
		return PickerResult{}, nil
	}
	if _, err := exec.LookPath("fzf"); err != nil {
		return PickerResult{}, fmt.Errorf("fzf not found in PATH")
	}

	input, idToDescription := buildFzfInput(entries)

	cmd := exec.CommandContext(ctx, "fzf", buildFzfArgs(len(entries))...)
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Any non-zero exit from fzf (e.g., Escape/no match) is treated as cancel.
		return PickerResult{}, nil
	}

	return parsePickerResult(out.String(), idToDescription), nil
}

func buildFzfInput(entries []pickerEntry) (string, map[string]string) {
	var b strings.Builder
	idToDescription := make(map[string]string, len(entries))
	for _, e := range entries {
		id := strconv.Itoa(e.rowID)
		idToDescription[id] = e.description
		fmt.Fprintf(
			&b,
			"%s\t%s\t%s\t%s\n",
			id,
			sanitizePickerField(e.description),
			sanitizePickerField(e.kind),
			sanitizePickerField(e.hashSuffix),
		)
	}
	return b.String(), idToDescription
}

func buildFzfArgs(entryCount int) []string {
	header := "enter select | ctrl-t/alt-t cat | ctrl-y/alt-y paste | ctrl-o/alt-o open | ctrl-e/alt-e edit | esc cancel"
	status := fmt.Sprintf("foostore interactive picker | %d entries | metadata preview only", entryCount)
	args := []string{
		"--height=80%",
		"--layout=reverse",
		"--border",
		"--ansi",
		"--delimiter=\t",
		"--with-nth=2,3,4",
		"--prompt=secret> ",
		"--expect=enter,ctrl-t,ctrl-y,ctrl-o,ctrl-e,alt-t,alt-y,alt-o,alt-e",
		"--bind=ctrl-t:ignore,ctrl-y:ignore,ctrl-o:ignore,ctrl-e:ignore,alt-t:ignore,alt-y:ignore,alt-o:ignore,alt-e:ignore",
		"--header=" + header + "\n" + status,
		"--preview-window=down,6,wrap,border-top",
		"--preview=printf 'entry: %s\\nkind: %s\\nhash suffix: %s\\n' {2} {3} {4}",
		"--color=" + pickerColorTheme(os.Getenv("FOOSTORE_TUI_THEME")),
	}
	if extra := strings.TrimSpace(os.Getenv("FOOSTORE_FZF_OPTS")); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}
	return args
}

func pickerColorTheme(theme string) string {
	switch strings.ToLower(strings.TrimSpace(theme)) {
	case "", "bold":
		return "fg:#f8fafc,bg:#0b1220,hl:#f59e0b,fg+:#ffffff,bg+:#1d4ed8,hl+:#fde047,info:#22d3ee,prompt:#f43f5e,pointer:#10b981,marker:#a78bfa,spinner:#fb7185,header:#38bdf8,border:#334155,separator:#0ea5e9,query:#e2e8f0,label:#f472b6"
	case "clean":
		return "fg:#e5e7eb,bg:#111827,hl:#93c5fd,fg+:#f9fafb,bg+:#1f2937,hl+:#93c5fd,info:#a7f3d0,prompt:#fbbf24,pointer:#34d399,marker:#34d399,spinner:#fbbf24,header:#a7f3d0,border:#374151"
	case "neon":
		return "fg:#d1fae5,bg:#020617,hl:#f0abfc,fg+:#ffffff,bg+:#0f172a,hl+:#f9a8d4,info:#67e8f9,prompt:#22d3ee,pointer:#22c55e,marker:#f472b6,spinner:#a78bfa,header:#38bdf8,border:#1d4ed8,separator:#22d3ee,query:#bbf7d0,label:#f0abfc"
	case "mono":
		return "fg:#e5e5e5,bg:#111111,hl:#ffffff,fg+:#ffffff,bg+:#222222,hl+:#ffffff,info:#d4d4d4,prompt:#ffffff,pointer:#ffffff,marker:#ffffff,spinner:#ffffff,header:#d4d4d4,border:#444444"
	default:
		return pickerColorTheme("bold")
	}
}

func sanitizePickerField(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func parsePickerResult(output string, idToDescription map[string]string) PickerResult {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) < 2 {
		return PickerResult{}
	}

	action, ok := parsePickerAction(lines[0])
	if !ok {
		return PickerResult{}
	}

	row := strings.TrimSpace(lines[1])
	if row == "" {
		return PickerResult{}
	}

	id := row
	if parts := strings.SplitN(row, "\t", 2); len(parts) > 0 {
		id = strings.TrimSpace(parts[0])
	}

	description, ok := idToDescription[id]
	if !ok || description == "" {
		return PickerResult{}
	}

	return PickerResult{
		Description: description,
		Action:      action,
	}
}

func parsePickerAction(keyLine string) (PickerAction, bool) {
	switch strings.TrimSpace(keyLine) {
	case "", "enter":
		return PickerSelect, true
	case "ctrl-t", "alt-t":
		return PickerCat, true
	case "ctrl-y", "alt-y":
		return PickerPaste, true
	case "ctrl-o", "alt-o":
		return PickerOpen, true
	case "ctrl-e", "alt-e":
		return PickerEdit, true
	default:
		return "", false
	}
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
