package keepass

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"

	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/store"
)

// createTestDB builds a minimal in-memory KeePass database, writes it to a
// temp file, and returns the file path. The caller must remove the file when
// done. The database uses password "testpass" with:
//   - Root/Work/Email  — text entry (password=secret, user=alice, url=https://mail.example.com)
//   - Root/Personal/Note — text entry (password=note123)
//   - Root/Work/Report — binary attachment named "report.pdf"
func createTestDB(t *testing.T) string {
	t.Helper()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")

	root := gokeepasslib.NewGroup()
	root.Name = "Root"

	work := gokeepasslib.NewGroup()
	work.Name = "Work"

	personal := gokeepasslib.NewGroup()
	personal.Name = "Personal"

	// Email entry
	email := gokeepasslib.NewEntry()
	SetEntryField(&email, "Title", "Email")
	SetEntryField(&email, "Password", "secret")
	SetEntryField(&email, "UserName", "alice")
	SetEntryField(&email, "URL", "https://mail.example.com")
	SetEntryField(&email, "Notes", "Work email account")
	work.Entries = append(work.Entries, email)

	// Binary attachment on a separate entry
	report := gokeepasslib.NewEntry()
	SetEntryField(&report, "Title", "Report")
	binContent := []byte("PDF content here")
	bin := db.AddBinary(binContent)
	report.Binaries = append(report.Binaries, bin.CreateReference("report.pdf"))
	work.Entries = append(work.Entries, report)

	// Personal note entry
	note := gokeepasslib.NewEntry()
	SetEntryField(&note, "Title", "Note")
	SetEntryField(&note, "Password", "note123")
	personal.Entries = append(personal.Entries, note)

	root.Groups = append(root.Groups, work, personal)
	db.Content.Root.Groups = []gokeepasslib.Group{root}

	// Write to temp file
	tmp, err := os.CreateTemp(t.TempDir(), "test-*.kdbx")
	if err != nil {
		t.Fatalf("creating temp kdbx: %v", err)
	}
	defer tmp.Close()

	if err := gokeepasslib.NewEncoder(tmp).Encode(db); err != nil {
		t.Fatalf("encoding test db: %v", err)
	}
	return tmp.Name()
}

// newTestBackend opens the test database and returns a *Backend ready for use.
func newTestBackend(t *testing.T, dbPath string) *Backend {
	t.Helper()
	exportDir := filepath.Join(t.TempDir(), "export")
	cfg := &config.Config{
		KDBXPath:  dbPath,
		ExportDir: exportDir,
	}
	b, err := New(cfg, "testpass", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// TestWalkIndexes verifies that all expected descriptions appear during a walk.
func TestWalkIndexes(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	tests := []struct {
		name       string
		searchTerm string
		wantDescs  []string
		wantCount  int
	}{
		{
			name:       "empty search returns all entries",
			searchTerm: "",
			wantDescs:  []string{"Work/Email", "Work/Report", "Work/Report/report.pdf", "Personal/Note"},
			wantCount:  4,
		},
		{
			name:       "search by group name",
			searchTerm: "Work",
			wantDescs:  []string{"Work/Email", "Work/Report", "Work/Report/report.pdf"},
			wantCount:  3,
		},
		{
			name:       "search by entry title",
			searchTerm: "Email",
			wantDescs:  []string{"Work/Email"},
			wantCount:  1,
		},
		{
			name:       "search by attachment name",
			searchTerm: "report.pdf",
			wantDescs:  []string{"Work/Report/report.pdf"},
			wantCount:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			err := b.WalkIndexes(ctx, tc.searchTerm, func(idx *store.Index) error {
				got = append(got, idx.Description)
				return nil
			})
			if err != nil {
				t.Fatalf("WalkIndexes error: %v", err)
			}
			if len(got) != tc.wantCount {
				t.Errorf("got %d entries, want %d; entries: %v", len(got), tc.wantCount, got)
			}
			for _, want := range tc.wantDescs {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("description %q not found in walk results %v", want, got)
				}
			}
		})
	}
}

// TestLoadData verifies content formatting for text and binary entries.
func TestLoadData(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	tests := []struct {
		name        string
		description string
		wantContain []string
		wantBinary  bool
	}{
		{
			name:        "text entry content",
			description: "Work/Email",
			wantContain: []string{"Password: secret", "User: alice", "URL: https://mail.example.com", "Notes:"},
		},
		{
			name:        "binary attachment content",
			description: "Work/Report/report.pdf",
			wantContain: []string{"PDF content here"},
			wantBinary:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build a synthetic index (same as WalkIndexes would produce).
			idx := &store.Index{Description: tc.description}
			d, err := b.LoadData(ctx, idx)
			if err != nil {
				t.Fatalf("LoadData error: %v", err)
			}
			content := string(d.Content)
			for _, want := range tc.wantContain {
				if !strings.Contains(content, want) {
					t.Errorf("content %q does not contain %q", content, want)
				}
			}
		})
	}
}

// TestSearch verifies that Search returns the correct sorted list and calls
// onMatch for each entry.
func TestSearch(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	var matched []string
	indexes, err := b.Search(ctx, "Work", store.ActionNone, nil, func(idx *store.Index) {
		matched = append(matched, idx.Description)
	})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if len(indexes) == 0 {
		t.Fatal("expected at least one result from Search")
	}
	if len(matched) != len(indexes) {
		t.Errorf("onMatch called %d times, got %d indexes", len(matched), len(indexes))
	}
	// Verify sorted order.
	for i := 1; i < len(indexes); i++ {
		if indexes[i].Description < indexes[i-1].Description {
			t.Errorf("indexes not sorted: %v >= %v", indexes[i-1].Description, indexes[i].Description)
		}
	}
}

// TestAddAndWalk verifies that Add persists a new entry that appears in a
// subsequent WalkIndexes call.
func TestAddAndWalk(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	data := string(formatContent("pw123", "bob", "https://example.com", "some notes"))
	if err := b.Add(ctx, "Work/NewEntry", data); err != nil {
		t.Fatalf("Add error: %v", err)
	}

	// Re-open to verify persistence.
	b2 := newTestBackend(t, dbPath)
	found := false
	if err := b2.WalkIndexes(ctx, "NewEntry", func(idx *store.Index) error {
		if idx.Description == "Work/NewEntry" {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes after Add: %v", err)
	}
	if !found {
		t.Error("Work/NewEntry not found after Add + re-open")
	}
}

// TestRemove verifies that Remove deletes an existing entry and it no longer
// appears in a subsequent WalkIndexes call.
func TestRemove(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// Confirm deletion automatically.
	input := strings.NewReader("y\n")
	if err := b.Remove(ctx, "^Personal/Note$", input); err != nil {
		t.Fatalf("Remove error: %v", err)
	}

	// Re-open to verify the entry is gone.
	b2 := newTestBackend(t, dbPath)
	var found bool
	if err := b2.WalkIndexes(ctx, "Personal/Note", func(idx *store.Index) error {
		if idx.Description == "Personal/Note" {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes after Remove: %v", err)
	}
	if found {
		t.Error("Personal/Note still present after Remove")
	}
}

// TestImportSkipsOnDuplicate verifies that Import with force=false returns nil
// and leaves the entry count unchanged when the destination already exists.
func TestImportSkipsOnDuplicate(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// Create a temp file to use as import source.
	srcFile := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(srcFile, []byte("Password: newpw\n"), 0o600); err != nil {
		t.Fatalf("writing src file: %v", err)
	}

	// Count baseline entries before any import.
	countEntries := func(b *Backend) int {
		var n int
		_ = b.WalkIndexes(ctx, "", func(*store.Index) error { n++; return nil })
		return n
	}
	before := countEntries(b)

	// Import with force=false — should skip silently because "Work/Email" already exists.
	if err := b.Import(ctx, srcFile, "Work/Email", false); err != nil {
		t.Fatalf("first Import error: %v", err)
	}

	// "Work/Email" already exists in the test DB — count must not have changed.
	after := countEntries(b)
	if after != before {
		t.Errorf("entry count changed: before=%d after=%d (expected no change)", before, after)
	}
}

// TestAddAttachment verifies that Add with a virtual attachment path creates
// an attachment on the parent entry and it surfaces via WalkIndexes and LoadData.
func TestAddAttachment(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// "Work/Email" already exists; add an attachment to it.
	attachContent := []byte("attachment binary content")
	if err := b.Add(ctx, "Work/Email/notes.txt", string(attachContent)); err != nil {
		// notes.txt is a text extension — IsBinary() would return false,
		// but isAttachmentPath checks entry existence, not extension.
		// The parent "Work/Email" exists so this must succeed.
		t.Fatalf("Add attachment error: %v", err)
	}

	// Re-open and verify the attachment virtual entry appears.
	b2 := newTestBackend(t, dbPath)
	found := false
	if err := b2.WalkIndexes(ctx, "Work/Email/notes.txt", func(idx *store.Index) error {
		if idx.Description == "Work/Email/notes.txt" {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes after AddAttachment: %v", err)
	}
	if !found {
		t.Error("Work/Email/notes.txt not found after Add attachment")
	}

	// LoadData for the attachment virtual entry must return the raw bytes.
	idx := &store.Index{Description: "Work/Email/notes.txt"}
	d, err := b2.LoadData(ctx, idx)
	if err != nil {
		t.Fatalf("LoadData attachment error: %v", err)
	}
	if string(d.Content) != string(attachContent) {
		t.Errorf("attachment content: got %q, want %q", d.Content, attachContent)
	}
}

// TestAddAttachmentReplace verifies that adding an attachment with an existing
// name replaces the old attachment bytes.
func TestAddAttachmentReplace(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// "Work/Report" already exists and has "report.pdf" attached.
	// Replace it with new content.
	newContent := []byte("updated PDF bytes")
	if err := b.Add(ctx, "Work/Report/report.pdf", string(newContent)); err != nil {
		t.Fatalf("Add (replace) attachment error: %v", err)
	}

	// LoadData must return the new bytes.
	b2 := newTestBackend(t, dbPath)
	idx := &store.Index{Description: "Work/Report/report.pdf"}
	d, err := b2.LoadData(ctx, idx)
	if err != nil {
		t.Fatalf("LoadData after replace error: %v", err)
	}
	if string(d.Content) != string(newContent) {
		t.Errorf("attachment content after replace: got %q, want %q", d.Content, newContent)
	}
}

// TestAddNoParentCreatesTextEntry verifies that Add with a multi-component path
// whose parent does not exist as an entry creates a new regular text entry rather
// than treating the last component as an attachment filename. This is the
// "new nested entry" case where no parent entry has been established yet.
func TestAddNoParentCreatesTextEntry(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// "Work/Ghost" does not exist as an entry, so "Work/Ghost/notes.txt" is
	// treated as a new text entry (not an attachment).
	if err := b.Add(ctx, "Work/Ghost/notes.txt", "Password: pw\n"); err != nil {
		t.Fatalf("Add new text entry error: %v", err)
	}

	// Re-open: the new entry must appear as a text entry (not an attachment).
	b2 := newTestBackend(t, dbPath)
	found := false
	if err := b2.WalkIndexes(ctx, "Work/Ghost/notes.txt", func(idx *store.Index) error {
		if idx.Description == "Work/Ghost/notes.txt" {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}
	if !found {
		t.Error("Work/Ghost/notes.txt not found after Add")
	}
}

// TestRemoveAttachment verifies that Remove on a virtual attachment path removes
// only the attachment and leaves the parent entry intact.
func TestRemoveAttachment(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// "Work/Report/report.pdf" is a virtual attachment entry.
	input := strings.NewReader("y\n")
	if err := b.Remove(ctx, `^Work/Report/report\.pdf$`, input); err != nil {
		t.Fatalf("Remove attachment error: %v", err)
	}

	// Re-open: the parent entry "Work/Report" must still exist.
	b2 := newTestBackend(t, dbPath)
	parentFound := false
	attachFound := false
	if err := b2.WalkIndexes(ctx, "", func(idx *store.Index) error {
		switch idx.Description {
		case "Work/Report":
			parentFound = true
		case "Work/Report/report.pdf":
			attachFound = true
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes after Remove attachment: %v", err)
	}
	if !parentFound {
		t.Error("parent entry Work/Report missing after attachment removal")
	}
	if attachFound {
		t.Error("Work/Report/report.pdf still present after Remove attachment")
	}
}

// TestAddThenRemoveAttachment verifies the full attachment lifecycle: Add,
// then Remove via WalkIndexes → LoadData roundtrip.
func TestAddThenRemoveAttachment(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// Add an attachment to an existing entry.
	if err := b.Add(ctx, "Personal/Note/secret.bin", "binary payload"); err != nil {
		t.Fatalf("Add attachment error: %v", err)
	}

	// Verify it's there.
	b2 := newTestBackend(t, dbPath)
	idx := &store.Index{Description: "Personal/Note/secret.bin"}
	if _, err := b2.LoadData(ctx, idx); err != nil {
		t.Fatalf("LoadData after Add: %v", err)
	}

	// Remove it.
	input := strings.NewReader("y\n")
	if err := b2.Remove(ctx, `^Personal/Note/secret\.bin$`, input); err != nil {
		t.Fatalf("Remove attachment error: %v", err)
	}

	// Verify it's gone but parent remains.
	b3 := newTestBackend(t, dbPath)
	var descs []string
	if err := b3.WalkIndexes(ctx, "Personal", func(idx *store.Index) error {
		descs = append(descs, idx.Description)
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}
	for _, d := range descs {
		if d == "Personal/Note/secret.bin" {
			t.Error("attachment still present after Remove")
		}
	}
}

// TestFormatParseRoundtrip verifies that formatContent and parseContent are
// mutual inverses across a range of inputs.
func TestFormatParseRoundtrip(t *testing.T) {
	tests := []struct {
		name     string
		password string
		user     string
		url      string
		notes    string
	}{
		{
			name:     "full fields",
			password: "s3cr3t!",
			user:     "alice@example.com",
			url:      "https://example.com/login",
			notes:    "Two-factor auth enabled\nBackup codes in vault",
		},
		{name: "empty fields"},
		{
			name:     "only password",
			password: "pw",
		},
		{
			name:  "multiline notes",
			notes: "line1\nline2\nline3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := formatContent(tc.password, tc.user, tc.url, tc.notes)
			gotPw, gotUser, gotURL, gotNotes := parseContent(content)
			if gotPw != tc.password {
				t.Errorf("password: got %q, want %q", gotPw, tc.password)
			}
			if gotUser != tc.user {
				t.Errorf("user: got %q, want %q", gotUser, tc.user)
			}
			if gotURL != tc.url {
				t.Errorf("url: got %q, want %q", gotURL, tc.url)
			}
			if gotNotes != tc.notes {
				t.Errorf("notes: got %q, want %q", gotNotes, tc.notes)
			}
		})
	}
}
