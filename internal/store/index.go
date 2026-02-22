// Package store manages the geheim secret store on disk.
// index.go represents a decrypted .index file and its associated .data path.
// Each index entry maps a human-readable description to an encrypted .data file,
// using SHA-256-hashed paths for filenames (mirroring the Ruby Index class).
package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codeberg.org/snonux/foostore/internal/crypto"
	"codeberg.org/snonux/foostore/internal/git"
)

// Index represents a decrypted .index file and its associated .data path.
// The Description field is the human-readable entry name; all path fields
// are derived from it via SHA-256 hashing (see HashPath in store.go).
type Index struct {
	Description string // decrypted human-readable entry name
	DataFile    string // relative path within data_dir (e.g. "abc/def.data")
	IndexPath   string // absolute path to .index file
	Hash        string // hex filename without extension (64-char SHA256 hex)
}

// loadIndex decrypts an .index file and builds an Index struct.
// absoluteIndexPath is the full path to the .index file on disk;
// dataDir is the root of the secret store (used to compute the relative DataFile).
func loadIndex(ctx context.Context, absoluteIndexPath, dataDir string, c *crypto.Cipher) (*Index, error) {
	ciphertext, err := os.ReadFile(absoluteIndexPath)
	if err != nil {
		return nil, fmt.Errorf("reading index file %q: %w", absoluteIndexPath, err)
	}

	plain, err := c.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting index file %q: %w", absoluteIndexPath, err)
	}

	// Build the relative DataFile by stripping the dataDir prefix and swapping the extension.
	relPath := strings.TrimPrefix(absoluteIndexPath, dataDir+"/")
	dataFile := strings.TrimSuffix(relPath, ".index") + ".data"

	// Hash is the bare filename (no extension) — a 64-char SHA-256 hex string.
	hash := strings.TrimSuffix(filepath.Base(absoluteIndexPath), ".index")

	return &Index{
		Description: string(plain),
		DataFile:    dataFile,
		IndexPath:   absoluteIndexPath,
		Hash:        hash,
	}, nil
}

// IsBinary returns true when the Description implies a binary file format.
// Text-like extensions (.txt, .README, .conf, .csv, .md) return false.
// Any other description containing a "." returns true (binary heuristic).
// Descriptions without any "." return false (no extension → assume text).
// This mirrors the Ruby Index#binary? method exactly.
func (idx *Index) IsBinary() bool {
	d := idx.Description
	if strings.Contains(d, ".txt") {
		return false
	}
	if strings.Contains(d, ".README") {
		return false
	}
	if strings.Contains(d, ".conf") {
		return false
	}
	if strings.Contains(d, ".csv") {
		return false
	}
	if strings.Contains(d, ".md") {
		return false
	}
	return strings.Contains(d, ".")
}

// String formats the index entry for display.
// Format: "<description>; (BINARY) ...<hash[53:63]>\n"
// The "(BINARY) " prefix is omitted for text entries.
// The hash suffix is 10 characters taken from positions 53–62 of the 64-char hex hash,
// matching Ruby's @hash[-11...-1] (exclusive range on a 64-char string).
func (idx *Index) String() string {
	binary := ""
	if idx.IsBinary() {
		binary = "(BINARY) "
	}
	// Hash[53:63] matches Ruby's @hash[-11...-1] on a 64-char SHA-256 hex string.
	hashSuffix := idx.Hash[53:63]
	return fmt.Sprintf("%s; %s...%s\n", idx.Description, binary, hashSuffix)
}

// CommitIndex encrypts the Description and writes it to IndexPath, then stages
// the file with git. When force is false and IndexPath already exists the write
// is silently skipped, matching the Ruby CommitFile#commit_content behaviour and
// keeping the .index in sync with a skipped .data Commit.
func (idx *Index) CommitIndex(ctx context.Context, c *crypto.Cipher, g *git.Git, force bool) error {
	if !force {
		if _, err := os.Stat(idx.IndexPath); err == nil {
			// File already exists; skip without error to keep the index/data pair consistent
			// when Data.Commit also skipped (force=false with an existing file).
			fmt.Printf("Warning: %s already exists, skipping (use force to overwrite)\n", idx.IndexPath)
			return nil
		}
	}

	ciphertext, err := c.Encrypt([]byte(idx.Description))
	if err != nil {
		return fmt.Errorf("encrypting index %q: %w", idx.IndexPath, err)
	}

	if err := os.WriteFile(idx.IndexPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing index file %q: %w", idx.IndexPath, err)
	}

	if err := g.Add(ctx, idx.IndexPath); err != nil {
		return fmt.Errorf("git add index %q: %w", idx.IndexPath, err)
	}

	return nil
}

// Remove stages the .index file for deletion via git rm.
func (idx *Index) Remove(ctx context.Context, g *git.Git) error {
	return g.Remove(ctx, idx.IndexPath)
}

// ---- sort.Interface for []*Index --------------------------------------------

// IndexSlice is a sortable slice of Index pointers, ordered by Description.
type IndexSlice []*Index

// Len returns the number of elements — required by sort.Interface.
func (s IndexSlice) Len() int { return len(s) }

// Less reports whether element i should sort before element j.
// Comparison is alphabetical on Description, mirroring Ruby's <=> operator.
func (s IndexSlice) Less(i, j int) bool { return s[i].Description < s[j].Description }

// Swap exchanges elements i and j — required by sort.Interface.
func (s IndexSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
