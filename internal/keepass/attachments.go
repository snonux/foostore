package keepass

import (
	"fmt"
	"strings"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
)

// isAttachmentPath reports whether description refers to a virtual attachment
// entry. It returns true when the parent path (description minus the last
// component) matches an existing text entry and the description itself does
// not match any existing entry.
//
// This implements the "Add to .../filename creates attachment on parent entry"
// contract: if Group/Title exists and Group/Title/file.bin does not, the last
// component is treated as an attachment filename.
func (b *Backend) isAttachmentPath(description string) (parentDesc, attachName string, ok bool) {
	// An attachment path must have at least two components (parent + filename).
	lastSlash := strings.LastIndex(description, "/")
	if lastSlash < 0 {
		return "", "", false
	}

	parentDesc = description[:lastSlash]
	attachName = description[lastSlash+1:]
	if attachName == "" || parentDesc == "" {
		return "", "", false
	}

	// The path itself must not already be a standalone text entry —
	// if it is, treat it as a normal entry update.
	if b.isTextEntry(description) {
		return "", "", false
	}

	// The parent must exist as a text (non-attachment) entry.
	if !b.isTextEntry(parentDesc) {
		return "", "", false
	}

	return parentDesc, attachName, true
}

// isTextEntry reports whether description refers to an existing non-attachment
// virtual entry in the database.
func (b *Backend) isTextEntry(description string) bool {
	for _, ve := range walkEntries(b.root()) {
		if ve.description == description && !ve.isBinary {
			return true
		}
	}
	return false
}

// addAttachment creates or replaces a binary attachment named attachName on the
// entry identified by parentDesc. The parent entry must already exist; use
// Add for the parent before adding an attachment to it.
func (b *Backend) addAttachment(parentDesc, attachName string, content []byte) error {
	groupPath, title, err := SplitDescriptionPath(parentDesc)
	if err != nil {
		return fmt.Errorf("keepass add attachment: %w", err)
	}

	g := EnsureGroup(b.root(), groupPath)
	entry, found := findEntryByTitle(g, title)
	if !found {
		return fmt.Errorf("keepass add attachment: parent entry %q not found", parentDesc)
	}

	upsertAttachment(b.db, entry, attachName, content)
	return b.save()
}

// findEntryByTitle locates an entry by title inside g without creating a new
// one. Returns the entry pointer and true when found.
func findEntryByTitle(g *gokeepasslib.Group, title string) (*gokeepasslib.Entry, bool) {
	for i := range g.Entries {
		if g.Entries[i].GetTitle() == title {
			return &g.Entries[i], true
		}
	}
	return nil, false
}

// upsertAttachment replaces an existing attachment named name on entry, or
// appends a new one if no attachment with that name exists.
func upsertAttachment(db *gokeepasslib.Database, entry *gokeepasslib.Entry, name string, content []byte) {
	// Remove the existing attachment reference for this name, if any.
	// The old binary in the db-level pool is orphaned (gokeepasslib handles
	// pool cleanup on encode), so we only need to remove the reference.
	newRefs := entry.Binaries[:0]
	for _, ref := range entry.Binaries {
		if ref.Name != name {
			newRefs = append(newRefs, ref)
		}
	}
	entry.Binaries = newRefs

	// Add the new binary to the pool and reference it from the entry.
	bin := db.AddBinary(content)
	entry.Binaries = append(entry.Binaries, bin.CreateReference(name))
}

// removeAttachment removes a binary attachment named attachName from the entry
// identified by parentDesc. Returns an error if the parent entry or attachment
// is not found.
func (b *Backend) removeAttachment(parentDesc, attachName string) error {
	groupPath, title, err := SplitDescriptionPath(parentDesc)
	if err != nil {
		return fmt.Errorf("keepass remove attachment: %w", err)
	}

	g := EnsureGroup(b.root(), groupPath)
	entry, found := findEntryByTitle(g, title)
	if !found {
		return fmt.Errorf("keepass remove attachment: parent entry %q not found", parentDesc)
	}

	before := len(entry.Binaries)
	newRefs := entry.Binaries[:0]
	for _, ref := range entry.Binaries {
		if ref.Name != attachName {
			newRefs = append(newRefs, ref)
		}
	}
	entry.Binaries = newRefs

	if len(entry.Binaries) == before {
		return fmt.Errorf("keepass remove attachment: attachment %q not found on %q", attachName, parentDesc)
	}

	return b.save()
}
