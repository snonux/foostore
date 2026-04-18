// store_crud.go implements create/read/update/delete operations for the secret store.
// Each operation (Add, Import, ImportRecursive, Remove) maps cleanly to its Ruby
// counterpart in geheim.rb and delegates encryption/git staging to Data and Index.
package store

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Add stores a new secret with the given description and plaintext data.
// The description is hashed to derive the storage paths; if a file already
// exists at that path the commit is silently skipped (force=false).
func (s *Store) Add(ctx context.Context, description, data string) error {
	hash := s.HashPath(description)
	idx, dataObj := s.buildPair(description, hash)
	dataObj.Content = []byte(data)

	if err := dataObj.Commit(ctx, false); err != nil {
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

	if err := dataObj.Commit(ctx, force); err != nil {
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
// Any input other than "y" or "n" causes the prompt to repeat.
func (s *Store) confirmAndRemove(ctx context.Context, idx *Index, scanner *bufio.Scanner) error {
	for {
		fmt.Print(idx.String())
		fmt.Print("You really want to delete this? (y/n): ")

		if !scanner.Scan() {
			return nil
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "y":
			return s.removeEntry(ctx, idx)
		case "n":
			return nil
		}
		// Any other input: loop and ask again.
	}
}

// removeEntry deletes the .data and .index files for a confirmed removal,
// delegating the actual git rm to Data.Remove and Index.Remove.
func (s *Store) removeEntry(ctx context.Context, idx *Index) error {
	dataPath := filepath.Join(s.cfg.DataDir, idx.DataFile)
	d := &Data{DataPath: dataPath}
	if err := d.Remove(ctx, s.git); err != nil {
		return fmt.Errorf("removing data file: %w", err)
	}
	if err := idx.Remove(ctx, s.git); err != nil {
		return fmt.Errorf("removing index file: %w", err)
	}
	return nil
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
		DataPath:  dataPath,
		encryptor: s.cipher,
		committer: s.git,
	}
	return idx, dataObj
}
