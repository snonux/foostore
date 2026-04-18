// store_shred.go provides secure file deletion for the secret store.
// ShredFile uses GNU shred(1) when available and falls back to "rm -Pfv".
// ShredAllExported iterates cfg.ExportDir and shreds every regular file,
// mirroring Ruby's Geheim#shred_all_exported best-effort deletion strategy.
package store

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

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
		if err := ShredFile(ctx, entry); err != nil {
			// Record the error but keep shredding — security demands best-effort
			// destruction of all exported secrets even if one fails.
			lastErr = err
		}
	}
	return lastErr
}

// ShredFile destroys a single file using shred(1) if available, or rm -Pfv.
// This mirrors Ruby's Geheim#shred_file method.
func ShredFile(ctx context.Context, filePath string) error {
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
