// data.go handles reading, writing, encrypting, and exporting individual
// secret data blobs. It mirrors the Ruby GeheimData class (geheim.rb lines 237-284).
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

// Data holds a decrypted secret blob and the paths used to persist it.
// DataPath is the absolute path to the on-disk .data file.
// ExportedPath is populated by Export() and consumed by ReimportAfterExport().
type Data struct {
	Content      []byte
	DataPath     string // absolute path to .data file
	ExportedPath string // set by Export(), used by ReimportAfterExport()
}

// loadData decrypts a .data file and returns a Data struct with Content populated.
// absoluteDataPath must be the full filesystem path to the encrypted .data file.
func loadData(ctx context.Context, absoluteDataPath string, c *crypto.Cipher) (*Data, error) {
	ciphertext, err := os.ReadFile(absoluteDataPath)
	if err != nil {
		return nil, fmt.Errorf("reading data file %q: %w", absoluteDataPath, err)
	}

	plain, err := c.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting data file %q: %w", absoluteDataPath, err)
	}

	return &Data{
		Content:  plain,
		DataPath: absoluteDataPath,
	}, nil
}

// String returns the content formatted for display with tab-indented lines.
// Mirrors Ruby: "\t#{@data.gsub("\n", "\n\t")}\n"
func (d *Data) String() string {
	indented := strings.ReplaceAll(string(d.Content), "\n", "\n\t")
	return "\t" + indented + "\n"
}

// Export writes the decrypted Content to exportDir/destinationFile, creating
// any intermediate directories as needed. ExportedPath is set to the resulting
// absolute path so that ReimportAfterExport() can locate the file later.
func (d *Data) Export(ctx context.Context, exportDir, destinationFile string) error {
	destination := filepath.Join(exportDir, destinationFile)

	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("creating export directory for %q: %w", destination, err)
	}

	if err := os.WriteFile(destination, d.Content, 0o600); err != nil {
		return fmt.Errorf("exporting to %q: %w", destination, err)
	}

	d.ExportedPath = destination
	return nil
}

// ReimportAfterExport reads the (possibly edited) file from ExportedPath back
// into Content and then commits it. This is used by the edit workflow: export →
// user edits in external editor → reimport.
func (d *Data) ReimportAfterExport(ctx context.Context, c *crypto.Cipher, g *git.Git) error {
	content, err := os.ReadFile(d.ExportedPath)
	if err != nil {
		return fmt.Errorf("reading exported file %q: %w", d.ExportedPath, err)
	}

	d.Content = content
	return d.Commit(ctx, c, g, true)
}

// Commit encrypts Content and writes it to DataPath, then stages the file with git.
// If force is false and the file already exists, the commit is silently skipped
// (matching the Ruby CommitFile#commit_content behaviour that avoids overwrites
// without explicit force).
func (d *Data) Commit(ctx context.Context, c *crypto.Cipher, g *git.Git, force bool) error {
	if !force {
		if _, err := os.Stat(d.DataPath); err == nil {
			// File already exists; skip without error to preserve existing data.
			fmt.Printf("Warning: %s already exists, skipping (use force to overwrite)\n", d.DataPath)
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(d.DataPath), 0o700); err != nil {
		return fmt.Errorf("creating data directory for %q: %w", d.DataPath, err)
	}

	ciphertext, err := c.Encrypt(d.Content)
	if err != nil {
		return fmt.Errorf("encrypting data for %q: %w", d.DataPath, err)
	}

	if err := os.WriteFile(d.DataPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing data file %q: %w", d.DataPath, err)
	}

	if err := g.Add(ctx, d.DataPath); err != nil {
		return fmt.Errorf("git add data %q: %w", d.DataPath, err)
	}

	return nil
}

// Remove stages the .data file for deletion via git rm.
func (d *Data) Remove(ctx context.Context, g *git.Git) error {
	return g.Remove(ctx, d.DataPath)
}
