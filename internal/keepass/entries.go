package keepass

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"

	"codeberg.org/snonux/foostore/internal/store"
)

// virtualEntry is an in-memory row produced by flattening the KeePass group
// tree. Each row corresponds to either a text entry or a binary attachment.
type virtualEntry struct {
	// description is the foostore-style "Group/Title" or "Group/Title/filename"
	// that uniquely identifies this entry across the flattened view.
	description string
	// isBinary is true for attachment rows; their content is raw bytes
	// rather than formatted text.
	isBinary bool
	// entry is the underlying KeePass entry. For binary rows this is the
	// parent entry; for text rows it is the entry itself.
	entry *gokeepasslib.Entry
	// attachmentName is non-empty only for binary attachment rows.
	attachmentName string
}

// toIndex converts a virtualEntry into a *store.Index using a SHA-256 of the
// description as the Hash field. This gives fzf key stability across restarts
// without requiring any on-disk index file.
func (v *virtualEntry) toIndex() *store.Index {
	sum := sha256.Sum256([]byte(v.description))
	hash := hex.EncodeToString(sum[:])
	return &store.Index{
		Description: v.description,
		Hash:        hash,
	}
}

// walkEntries flattens the entire KeePass group tree starting from root into
// a slice of virtualEntry rows. Groups are traversed depth-first; within each
// group, entries come before sub-groups. Binary attachments surface as extra
// virtual entries "Group/Title/filename" after their parent text entry.
func walkEntries(root *gokeepasslib.Group) []virtualEntry {
	var rows []virtualEntry
	collectGroup(&rows, root, nil)
	return rows
}

// collectGroup recursively collects entries from g and its sub-groups.
// groupPath holds the ancestor group names (not including g itself).
func collectGroup(rows *[]virtualEntry, g *gokeepasslib.Group, groupPath []string) {
	// Include the current group's name in the path passed to children,
	// but skip the synthetic "Root" group at the top level so descriptions
	// don't start with "Root/".
	var myPath []string
	if g.Name != "" && g.Name != "Root" {
		myPath = append(groupPath, g.Name)
	} else {
		myPath = groupPath
	}

	for i := range g.Entries {
		collectEntry(rows, &g.Entries[i], myPath)
	}
	for i := range g.Groups {
		collectGroup(rows, &g.Groups[i], myPath)
	}
}

// collectEntry adds one text virtualEntry for e plus one virtualEntry per
// binary attachment found on e.
func collectEntry(rows *[]virtualEntry, e *gokeepasslib.Entry, groupPath []string) {
	title := e.GetTitle()
	if title == "" {
		title = "(untitled)"
	}
	desc := descriptionOf(groupPath, title, "")
	*rows = append(*rows, virtualEntry{
		description: desc,
		isBinary:    false,
		entry:       e,
	})

	for _, binRef := range e.Binaries {
		attName := binRef.Name
		if attName == "" {
			attName = "attachment"
		}
		*rows = append(*rows, virtualEntry{
			description:    descriptionOf(groupPath, title, attName),
			isBinary:       true,
			entry:          e,
			attachmentName: attName,
		})
	}
}

// descriptionOf builds the foostore Description string from the group path
// components, an entry title, and an optional attachment filename.
// If attachmentName is empty, the result is "Group/Title";
// otherwise "Group/Title/attachmentName".
func descriptionOf(groupPath []string, title, attachmentName string) string {
	parts := make([]string, 0, len(groupPath)+2)
	parts = append(parts, groupPath...)
	parts = append(parts, title)
	if attachmentName != "" {
		parts = append(parts, attachmentName)
	}
	return strings.Join(parts, "/")
}

// getEntryField returns the value of the named field from an entry, or "".
func getEntryField(e *gokeepasslib.Entry, key string) string {
	for _, v := range e.Values {
		if v.Key == key {
			return v.Value.Content
		}
	}
	return ""
}

// SetEntryField sets key=value on entry, updating in place if the key already
// exists or appending a new ValueData otherwise. Protected fields use the plain
// V struct; callers that need protection must set Value.Protected separately.
// Exported so that internal/cli/kdbx_store.go can reuse it without duplication.
func SetEntryField(entry *gokeepasslib.Entry, key, value string) {
	for i := range entry.Values {
		if entry.Values[i].Key == key {
			entry.Values[i].Value.Content = value
			return
		}
	}
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value},
	})
}

// EnsureGroup traverses the group tree from root following groupPath, creating
// sub-groups that do not yet exist. It returns a pointer to the leaf group.
// Exported so that internal/cli/kdbx_store.go can reuse it without duplication.
func EnsureGroup(root *gokeepasslib.Group, groupPath []string) *gokeepasslib.Group {
	g := root
	for _, segment := range groupPath {
		if segment == "" {
			continue
		}
		found := -1
		for i := range g.Groups {
			if g.Groups[i].Name == segment {
				found = i
				break
			}
		}
		if found == -1 {
			ng := gokeepasslib.NewGroup()
			ng.Name = segment
			g.Groups = append(g.Groups, ng)
			found = len(g.Groups) - 1
		}
		g = &g.Groups[found]
	}
	return g
}

// UpsertEntryByTitle finds an existing entry with the given title inside g, or
// appends a new blank entry. Returns a pointer to the entry and true if it was
// an update (title already existed).
// Exported so that internal/cli/kdbx_store.go can reuse it without duplication.
func UpsertEntryByTitle(g *gokeepasslib.Group, title string) (*gokeepasslib.Entry, bool) {
	for i := range g.Entries {
		if g.Entries[i].GetTitle() == title {
			return &g.Entries[i], true
		}
	}
	e := gokeepasslib.NewEntry()
	g.Entries = append(g.Entries, e)
	return &g.Entries[len(g.Entries)-1], false
}

// SplitDescriptionPath splits a foostore description ("Group/Title") into a
// group-path slice and a title, normalising and validating the path first.
// Exported so that internal/cli/kdbx_store.go can reuse it without duplication.
func SplitDescriptionPath(description string) ([]string, string, error) {
	safePath, err := SanitizeRelativePath(description)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(safePath, "/")
	if len(parts) == 1 {
		return nil, parts[0], nil
	}
	return parts[:len(parts)-1], parts[len(parts)-1], nil
}

// SanitizeRelativePath normalises slashes, trims whitespace, and rejects paths
// that would escape the store root (empty, ".", "..", or starting with "../").
// Exported so that internal/cli/kdbx_store.go can reuse it without duplication.
func SanitizeRelativePath(path string) (string, error) {
	normalised := strings.ReplaceAll(path, "\\", "/")
	normalised = strings.TrimSpace(normalised)
	if normalised == "" {
		return "", fmt.Errorf("empty entry description")
	}
	clean := filepath.Clean(normalised)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." || clean == "" || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe entry description path %q", path)
	}
	return clean, nil
}
