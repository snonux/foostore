package keepass

import (
	"context"
	"fmt"
	"os"
	"regexp"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"

	"codeberg.org/snonux/foostore/internal/backend"
	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/store"
)

// Backend implements backend.Backend for a KeePass (.kdbx) database.
// It is intentionally read-oriented; write methods (Add, Import, etc.) are
// currently stubs that return "not supported" errors — they will be wired in a
// later task once the read path is validated. The database is loaded once at
// construction time and held in memory.
type Backend struct {
	cfg        *config.Config
	db         *gokeepasslib.Database
	dbPath     string
	regexCache map[string]*regexp.Regexp
}

// Compile-time assertion: *Backend must satisfy backend.Backend.
var _ backend.Backend = (*Backend)(nil)

// New opens the KeePass database at cfg.KDBXPath using the supplied password
// and optional key-file bytes. The database is fully decrypted and held in
// memory; the file is closed immediately after loading.
//
// Pass a non-nil keyFileData only when cfg.KDBXKeyFile is non-empty; otherwise
// pass nil to use password-only credentials.
func New(cfg *config.Config, password string, keyFileData []byte) (*Backend, error) {
	creds, err := buildCredentials(password, keyFileData)
	if err != nil {
		return nil, fmt.Errorf("building keepass credentials: %w", err)
	}

	db, err := openDatabase(cfg.KDBXPath, creds)
	if err != nil {
		return nil, err
	}

	return &Backend{
		cfg:        cfg,
		db:         db,
		dbPath:     cfg.KDBXPath,
		regexCache: make(map[string]*regexp.Regexp),
	}, nil
}

// buildCredentials returns the appropriate gokeepasslib credentials pointer.
// When keyFileData is non-empty a combined password+keyfile credential is used;
// otherwise a password-only credential is returned.
func buildCredentials(password string, keyFileData []byte) (*gokeepasslib.DBCredentials, error) {
	if len(keyFileData) > 0 {
		return gokeepasslib.NewPasswordAndKeyDataCredentials(password, keyFileData)
	}
	return gokeepasslib.NewPasswordCredentials(password), nil
}

// openDatabase opens, decodes, and unlocks a KeePass database from the given
// path using the supplied credentials.
func openDatabase(path string, creds *gokeepasslib.DBCredentials) (*gokeepasslib.Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening kdbx %q: %w", path, err)
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = creds
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return nil, fmt.Errorf("decoding kdbx %q: %w", path, err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("unlocking kdbx %q: %w", path, err)
	}
	ensureRootGroup(db)
	return db, nil
}

// ensureRootGroup guarantees that the database has a Content, Root, and at
// least one top-level group so that all navigation helpers can assume a valid
// tree structure.
func ensureRootGroup(db *gokeepasslib.Database) {
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
}

// root returns the single top-level KeePass group that acts as the tree root.
func (b *Backend) root() *gokeepasslib.Group {
	return &b.db.Content.Root.Groups[0]
}

// WalkIndexes iterates over every virtual entry in the database whose
// description matches searchTerm (empty matches all) and calls fn for each.
func (b *Backend) WalkIndexes(ctx context.Context, searchTerm string, fn func(*store.Index) error) error {
	regex, err := b.compileRegex(searchTerm)
	if err != nil {
		return err
	}

	for _, ve := range walkEntries(b.root()) {
		if searchTerm != "" && !regex.MatchString(ve.description) {
			continue
		}
		if err := fn(ve.toIndex()); err != nil {
			return err
		}
	}
	return nil
}

// compileRegex returns a cached compiled regexp for the given search term.
func (b *Backend) compileRegex(searchTerm string) (*regexp.Regexp, error) {
	if r, ok := b.regexCache[searchTerm]; ok {
		return r, nil
	}
	r, err := regexp.Compile(searchTerm)
	if err != nil {
		return nil, fmt.Errorf("invalid search term %q: %w", searchTerm, err)
	}
	b.regexCache[searchTerm] = r
	return r, nil
}

// LoadData builds a *store.Data for the given index entry. For text entries
// the Content is the formatted Password/User/URL/Notes block; for binary
// attachment entries the Content is the raw attachment bytes.
//
// WriteBack is populated so that edits via ReimportAfterExport parse the
// updated text back into KeePass fields and persist the database.
func (b *Backend) LoadData(ctx context.Context, idx *store.Index) (*store.Data, error) {
	for _, ve := range walkEntries(b.root()) {
		if ve.description != idx.Description {
			continue
		}
		return b.virtualEntryToData(ctx, &ve)
	}
	return nil, fmt.Errorf("keepass: entry %q not found", idx.Description)
}

// virtualEntryToData converts a resolved virtualEntry into a *store.Data.
func (b *Backend) virtualEntryToData(ctx context.Context, ve *virtualEntry) (*store.Data, error) {
	if ve.isBinary {
		return b.binaryData(ve)
	}
	return b.textData(ve)
}

// textData builds a *store.Data for a text (non-attachment) virtual entry.
func (b *Backend) textData(ve *virtualEntry) (*store.Data, error) {
	password := getEntryField(ve.entry, "Password")
	user := getEntryField(ve.entry, "UserName")
	url := getEntryField(ve.entry, "URL")
	notes := getEntryField(ve.entry, "Notes")
	content := formatContent(password, user, url, notes)

	d := &store.Data{Content: content}
	d.WriteBack = b.makeWriteBack(ve.description)
	return d, nil
}

// binaryData builds a *store.Data for a binary attachment virtual entry.
// It resolves the BinaryReference against the database-level binaries store
// and returns the decompressed content bytes.
func (b *Backend) binaryData(ve *virtualEntry) (*store.Data, error) {
	for _, binRef := range ve.entry.Binaries {
		if binRef.Name != ve.attachmentName {
			continue
		}
		bin := binRef.Find(b.db)
		if bin == nil {
			return nil, fmt.Errorf("keepass: binary ID %d not found in db", binRef.Value.ID)
		}
		content, err := bin.GetContentBytes()
		if err != nil {
			return nil, fmt.Errorf("keepass: reading attachment %q: %w", ve.attachmentName, err)
		}
		return &store.Data{Content: content}, nil
	}
	return nil, fmt.Errorf("keepass: attachment %q not found on entry %q", ve.attachmentName, ve.description)
}

// makeWriteBack returns a WriteBack function that parses updated text content
// back into KeePass fields and saves the database. The d *store.Data parameter
// is intentionally absent — the closure only needs the description and db ref.
func (b *Backend) makeWriteBack(description string) func([]byte) error {
	return func(newContent []byte) error {
		password, user, url, notes := parseContent(newContent)
		groupPath, title, err := SplitDescriptionPath(description)
		if err != nil {
			return fmt.Errorf("keepass writeback: %w", err)
		}
		g := EnsureGroup(b.root(), groupPath)
		entry, _ := UpsertEntryByTitle(g, title)
		SetEntryField(entry, "Title", title)
		SetEntryField(entry, "Password", password)
		SetEntryField(entry, "UserName", user)
		SetEntryField(entry, "URL", url)
		SetEntryField(entry, "Notes", notes)
		return b.save()
	}
}

// save locks protected entries and atomically replaces the database file.
func (b *Backend) save() error {
	if err := b.db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("keepass: locking entries: %w", err)
	}
	defer func() {
		// Re-unlock so in-memory state stays usable after a save.
		_ = b.db.UnlockProtectedEntries()
	}()
	return AtomicSave(b.db, b.dbPath)
}

// AtomicSave encodes db to a temporary file then renames it over dbPath,
// ensuring the database file is never left in a partial state.
// The file is closed exactly once via the explicit close below; no defer is
// used to avoid double-close on the already-closed file handle.
// Exported so that cli.kdbxStore.Save() can reuse the same pattern without
// duplicating the tmp→rename logic.
func AtomicSave(db *gokeepasslib.Database, dbPath string) error {
	tmpPath := dbPath + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("keepass: creating tmp file %q: %w", tmpPath, err)
	}

	if err := gokeepasslib.NewEncoder(out).Encode(db); err != nil {
		_ = out.Close()
		return fmt.Errorf("keepass: encoding to %q: %w", tmpPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("keepass: closing tmp file %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, dbPath); err != nil {
		return fmt.Errorf("keepass: replacing db %q: %w", dbPath, err)
	}
	return nil
}
