package cli

import (
	"fmt"
	"os"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"

	"codeberg.org/snonux/foostore/internal/keepass"
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

// UpsertTextEntry creates or updates a text entry in groupPath with the given
// title, password, and notes. Delegates field manipulation to keepass.SetEntryField
// and group navigation to keepass.EnsureGroup to avoid duplication.
func (s *kdbxStore) UpsertTextEntry(groupPath []string, title, password, notes string) (bool, error) {
	g := keepass.EnsureGroup(&s.db.Content.Root.Groups[0], groupPath)
	entry, overwrote := keepass.UpsertEntryByTitle(g, title)
	keepass.SetEntryField(entry, "Title", title)
	keepass.SetEntryField(entry, "Password", password)
	keepass.SetEntryField(entry, "Notes", notes)
	return overwrote, nil
}

// UpsertBinaryEntry creates or updates a binary attachment entry in groupPath.
// Delegates field manipulation to keepass.SetEntryField and group navigation
// to keepass.EnsureGroup to avoid duplication.
func (s *kdbxStore) UpsertBinaryEntry(groupPath []string, title, filename string, content []byte) (bool, error) {
	g := keepass.EnsureGroup(&s.db.Content.Root.Groups[0], groupPath)
	entry, overwrote := keepass.UpsertEntryByTitle(g, title)
	keepass.SetEntryField(entry, "Title", title)
	keepass.SetEntryField(entry, "Password", "")

	b := s.db.AddBinary(content)
	entry.Binaries = []gokeepasslib.BinaryReference{b.CreateReference(filename)}
	// Keep notes concise for binary-only entries.
	keepass.SetEntryField(entry, "Notes", fmt.Sprintf("Migrated binary attachment: %s", filename))
	return overwrote, nil
}

// Save locks protected entries and atomically writes the database to disk.
// Delegates the tmp→encode→rename sequence to keepass.AtomicSave to avoid
// duplicating that logic here (keepass.Backend.save() uses the same helper).
func (s *kdbxStore) Save() error {
	if err := s.db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("locking kdbx entries: %w", err)
	}
	return keepass.AtomicSave(s.db, s.path)
}
