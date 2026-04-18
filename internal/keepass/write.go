package keepass

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Add creates or updates a KeePass entry from plaintext data.
//
// Attachment detection: if the last path component does not match any existing
// standalone entry but its parent does, the call is routed to addAttachment so
// that "Group/Title/file.bin" attaches raw bytes to "Group/Title". The parent
// entry must already exist; return an error if it does not.
// Otherwise, the description is treated as a normal text entry and its fields
// are parsed from data via parseContent.
func (b *Backend) Add(ctx context.Context, description, data string) error {
	if parentDesc, attachName, ok := b.isAttachmentPath(description); ok {
		return b.addAttachment(parentDesc, attachName, []byte(data))
	}
	return b.addTextEntry(description, data)
}

// addTextEntry creates or updates the KeePass entry at description using the
// fields parsed from data. This is the normal (non-attachment) Add path.
func (b *Backend) addTextEntry(description, data string) error {
	groupPath, title, err := SplitDescriptionPath(description)
	if err != nil {
		return fmt.Errorf("keepass add: %w", err)
	}
	// data is already a string; pass directly to avoid a redundant []byte
	// allocation that parseContent would immediately convert back (mistake #40).
	password, user, url, notes := parseContent(data)
	g := EnsureGroup(b.root(), groupPath)
	entry, _ := UpsertEntryByTitle(g, title)
	SetEntryField(entry, "Title", title)
	SetEntryField(entry, "Password", password)
	SetEntryField(entry, "UserName", user)
	SetEntryField(entry, "URL", url)
	SetEntryField(entry, "Notes", notes)
	return b.save()
}

// Import reads a file from srcPath and stores it under destPath.
// When force is false and an entry already exists at destPath, the import is
// skipped silently (a warning is printed to stderr) and nil is returned —
// matching the interface contract and the behaviour of store.Store.Import.
func (b *Backend) Import(ctx context.Context, srcPath, destPath string, force bool) error {
	if !force && b.entryExists(destPath) {
		// Skip without error; warn on stderr so the operator knows something
		// was skipped, consistent with store.Store.Import(force=false).
		fmt.Fprintf(os.Stderr, "Warning: keepass entry %q already exists, skipping (use force to overwrite)\n", destPath)
		return nil
	}
	content, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("keepass import: reading %q: %w", srcPath, err)
	}
	// importBytes keeps the file data as []byte throughout, avoiding a
	// []byte→string→[]byte round-trip that would occur when routing through
	// the public Add(string) API for attachment entries (mistake #40).
	return b.importBytes(destPath, content)
}

// importBytes stores raw file bytes under destPath. It routes to either
// addAttachment (for virtual attachment paths) or addTextEntry, preserving
// the []byte so that attachment data never undergoes a redundant conversion.
//
// ctx is intentionally not threaded through to addAttachment or addTextEntry:
// both are synchronous, purely in-memory operations (no I/O, no goroutines)
// that complete without any blocking calls that could respect cancellation.
func (b *Backend) importBytes(destPath string, content []byte) error {
	if parentDesc, attachName, ok := b.isAttachmentPath(destPath); ok {
		return b.addAttachment(parentDesc, attachName, content)
	}
	// Text entries parse the content as a string; a single conversion here
	// is unavoidable because parseContent operates on strings for efficiency.
	return b.addTextEntry(destPath, string(content))
}

// entryExists reports whether an entry with the given description already
// exists in the KeePass database. Used by Import to detect duplicates.
func (b *Backend) entryExists(description string) bool {
	for _, ve := range walkEntries(b.root()) {
		if ve.description == description {
			return true
		}
	}
	return false
}

// ImportRecursive walks directory recursively and imports every regular file
// under destDir, preserving the relative sub-directory structure in the
// description path. Uses filepath.WalkDir to descend into sub-directories.
func (b *Backend) ImportRecursive(ctx context.Context, directory, destDir string) error {
	baseDir := strings.TrimRight(destDir, "/")
	return walkDirFilesRecursive(directory, func(relFile string) error {
		destPath := filepath.Join(baseDir, relFile)
		srcPath := filepath.Join(directory, relFile)
		return b.Import(ctx, srcPath, destPath, false)
	})
}

// walkDirFilesRecursive walks a directory tree calling fn(relativeFilePath)
// for each regular file found at any depth. Uses filepath.WalkDir so that
// sub-directories are descended into.
func walkDirFilesRecursive(dir string, fn func(string) error) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("keepass: walking %q: %w", path, err)
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return fmt.Errorf("keepass: computing relative path for %q: %w", path, relErr)
		}
		// Use forward slashes in the description regardless of OS separator.
		return fn(filepath.ToSlash(rel))
	})
}
