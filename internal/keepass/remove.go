package keepass

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"codeberg.org/snonux/foostore/internal/store"
)

// Remove finds all indexes matching searchTerm and prompts before deleting.
func (b *Backend) Remove(ctx context.Context, searchTerm string, input io.Reader) error {
	var indexes store.IndexSlice
	if err := b.WalkIndexes(ctx, searchTerm, func(idx *store.Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return err
	}
	sort.Sort(indexes)

	scanner := bufio.NewScanner(input)
	for _, idx := range indexes {
		if err := b.confirmAndRemove(idx, scanner); err != nil {
			return err
		}
	}
	return nil
}

// confirmAndRemove prompts the user for deletion confirmation and removes the
// entry (or attachment) on "y".
func (b *Backend) confirmAndRemove(idx *store.Index, scanner *bufio.Scanner) error {
	for {
		fmt.Print(idx.String())
		fmt.Print("You really want to delete this? (y/n): ")
		if !scanner.Scan() {
			return nil
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "y":
			return b.removeEntry(idx.Description)
		case "n":
			return nil
		}
	}
}

// removeEntry deletes the KeePass entry (or attachment) matching description
// and saves the DB.
//
// If description is a virtual attachment path ("Group/Title/file.bin"), the
// attachment is removed from the parent entry rather than removing the entry
// itself. For regular entries the full entry is deleted from its group.
func (b *Backend) removeEntry(description string) error {
	// Detect virtual attachment paths: if the parent exists as a text entry but
	// description itself does not, route to attachment removal.
	if parentDesc, attachName, ok := b.isAttachmentPath(description); ok {
		return b.removeAttachment(parentDesc, attachName)
	}
	return b.removeTextEntry(description)
}

// removeTextEntry deletes a regular (non-attachment) entry from its group.
func (b *Backend) removeTextEntry(description string) error {
	groupPath, title, err := SplitDescriptionPath(description)
	if err != nil {
		return fmt.Errorf("keepass remove: %w", err)
	}
	g := EnsureGroup(b.root(), groupPath)
	for i, e := range g.Entries {
		if e.GetTitle() == title {
			g.Entries = append(g.Entries[:i], g.Entries[i+1:]...)
			return b.save()
		}
	}
	return fmt.Errorf("keepass remove: entry %q not found", description)
}

// ShredAllExported securely deletes every regular file in cfg.ExportDir.
// Delegates to store.ShredFile for the actual destruction.
func (b *Backend) ShredAllExported(ctx context.Context) error {
	entries, err := os.ReadDir(b.cfg.ExportDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("listing export dir: %w", err)
	}
	var lastErr error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		filePath := filepath.Join(b.cfg.ExportDir, e.Name())
		if err := store.ShredFile(ctx, filePath); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
