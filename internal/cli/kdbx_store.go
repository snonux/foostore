package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
)

// KDBXStore is the minimal interface needed by migrate-kdbx.
type KDBXStore interface {
	UpsertTextEntry(groupPath []string, title, password, notes string) (overwrote bool, err error)
	UpsertBinaryEntry(groupPath []string, title, filename string, content []byte) (overwrote bool, err error)
	Save() error
}

type kdbxStore struct {
	path string
	db   *gokeepasslib.Database
}

// OpenKDBXStore opens an existing KDBX database using password credentials.
func OpenKDBXStore(dbPath, password string) (KDBXStore, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening kdbx %q: %w", dbPath, err)
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return nil, fmt.Errorf("decoding kdbx %q: %w", dbPath, err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("unlocking kdbx %q: %w", dbPath, err)
	}

	if db.Content == nil {
		db.Content = gokeepasslib.NewContent()
	}
	if db.Content.Root == nil {
		db.Content.Root = gokeepasslib.NewRootData()
	}
	if len(db.Content.Root.Groups) == 0 {
		root := gokeepasslib.NewGroup()
		root.Name = "Root"
		db.Content.Root.Groups = append(db.Content.Root.Groups, root)
	}

	return &kdbxStore{
		path: dbPath,
		db:   db,
	}, nil
}

func (s *kdbxStore) UpsertTextEntry(groupPath []string, title, password, notes string) (bool, error) {
	g := s.ensureGroup(groupPath)
	entry, overwrote := upsertEntryByTitle(g, title)
	setEntryField(entry, "Title", title)
	setEntryField(entry, "Password", password)
	setEntryField(entry, "Notes", notes)
	return overwrote, nil
}

func (s *kdbxStore) UpsertBinaryEntry(groupPath []string, title, filename string, content []byte) (bool, error) {
	g := s.ensureGroup(groupPath)
	entry, overwrote := upsertEntryByTitle(g, title)
	setEntryField(entry, "Title", title)
	setEntryField(entry, "Password", "")

	b := s.db.AddBinary(content)
	entry.Binaries = []gokeepasslib.BinaryReference{b.CreateReference(filename)}
	// Keep notes concise for binary-only entries.
	setEntryField(entry, "Notes", fmt.Sprintf("Migrated binary attachment: %s", filename))
	return overwrote, nil
}

func (s *kdbxStore) ensureGroup(groupPath []string) *gokeepasslib.Group {
	g := &s.db.Content.Root.Groups[0]
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

func upsertEntryByTitle(g *gokeepasslib.Group, title string) (*gokeepasslib.Entry, bool) {
	for i := range g.Entries {
		if g.Entries[i].GetTitle() == title {
			return &g.Entries[i], true
		}
	}
	e := gokeepasslib.NewEntry()
	g.Entries = append(g.Entries, e)
	return &g.Entries[len(g.Entries)-1], false
}

func (s *kdbxStore) Save() error {
	if err := s.db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("locking kdbx entries: %w", err)
	}

	tmpPath := s.path + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("creating temporary kdbx %q: %w", tmpPath, err)
	}
	defer out.Close()

	if err := gokeepasslib.NewEncoder(out).Encode(s.db); err != nil {
		return fmt.Errorf("encoding kdbx to %q: %w", tmpPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing temporary kdbx %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replacing kdbx %q: %w", s.path, err)
	}
	return nil
}

func setEntryField(entry *gokeepasslib.Entry, key, value string) {
	for i := range entry.Values {
		if entry.Values[i].Key == key {
			entry.Values[i].Value.Content = value
			return
		}
	}

	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key: key,
		Value: gokeepasslib.V{
			Content: value,
		},
	})
}

func splitDescriptionPath(description string) ([]string, string, error) {
	safePath, err := sanitizeRelativePath(description)
	if err != nil {
		return nil, "", err
	}

	parts := strings.Split(safePath, "/")
	if len(parts) == 1 {
		return nil, parts[0], nil
	}
	return parts[:len(parts)-1], parts[len(parts)-1], nil
}

func sanitizeRelativePath(path string) (string, error) {
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
