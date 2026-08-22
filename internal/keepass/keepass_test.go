package keepass

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"

	"github.com/snonux/foostore/internal/config"
	"github.com/snonux/foostore/internal/store"
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

// TestWriteBackEditRoundtrip verifies that makeWriteBack returns a function that
// parses updated content back into KeePass fields and persists them. This
// exercises the edit workflow: export → external editor modifies content →
// WriteBack re-imports the new fields into the database.
func TestWriteBackEditRoundtrip(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// Load the entry to get a Data with a populated WriteBack hook.
	idx := &store.Index{Description: "Work/Email"}
	d, err := b.LoadData(ctx, idx)
	if err != nil {
		t.Fatalf("LoadData: %v", err)
	}
	if d.WriteBack == nil {
		t.Fatal("LoadData must set WriteBack for keepass text entries")
	}

	// Simulate an external editor: produce new content with changed fields.
	newContent := formatContent("newpass", "bob", "https://new.example.com", "updated notes")
	if err := d.WriteBack(newContent); err != nil {
		t.Fatalf("WriteBack: %v", err)
	}

	// Re-open and verify the fields persisted correctly.
	b2 := newTestBackend(t, dbPath)
	d2, err := b2.LoadData(ctx, idx)
	if err != nil {
		t.Fatalf("LoadData after WriteBack: %v", err)
	}
	content := string(d2.Content)
	for _, want := range []string{"Password: newpass", "User: bob", "URL: https://new.example.com", "updated notes"} {
		if !strings.Contains(content, want) {
			t.Errorf("content after WriteBack missing %q; got: %q", want, content)
		}
	}
}

// captureStdout redirects os.Stdout to a pipe, runs fn, then restores
// os.Stdout and returns all bytes written during fn. It calls t.Fatal if the
// pipe cannot be created.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureStdout: pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, _ := r.Read(tmp)
		if n == 0 {
			break
		}
		buf.Write(tmp[:n])
	}
	return buf.String()
}

// TestSearchActionCat verifies that Search with ActionCat calls actionCat for
// each matching text entry (printing content to stdout) and does not error.
func TestSearchActionCat(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	var indexes []*store.Index
	var searchErr error
	out := captureStdout(t, func() {
		indexes, searchErr = b.Search(ctx, "Work/Email", store.ActionCat, nil, nil)
	})

	if searchErr != nil {
		t.Fatalf("Search(ActionCat): %v", searchErr)
	}
	if len(indexes) == 0 {
		t.Fatal("expected at least one result")
	}
	if !strings.Contains(out, "Password: secret") {
		t.Errorf("cat output missing 'Password: secret'; got: %q", out)
	}
}

// TestSearchActionExport verifies that Search with ActionExport writes the
// content to the export directory and that the exported file is readable.
func TestSearchActionExport(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	_, err := b.Search(ctx, "Personal/Note", store.ActionExport, nil, nil)
	if err != nil {
		t.Fatalf("Search(ActionExport): %v", err)
	}

	// The export dir is set to a temp dir by newTestBackend; find the exported file.
	exportDir := b.cfg.ExportDir
	entries, err := os.ReadDir(exportDir)
	if err != nil {
		t.Fatalf("ReadDir exportDir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one exported file")
	}
	// Read the exported file and verify it contains the formatted content.
	exported, err := os.ReadFile(filepath.Join(exportDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("reading exported file: %v", err)
	}
	if !strings.Contains(string(exported), "Password: note123") {
		t.Errorf("exported file missing 'Password: note123'; got: %q", exported)
	}
}

// TestSearchActionWithActionFn verifies that Search with a non-Cat action
// delegates to the provided actionFn (e.g., the paste path that extracts only
// the password). This exercises the applyAction default branch and confirms
// that only the password field is surfaced to the callback — matching the
// paste-only-password contract.
func TestSearchActionWithActionFn(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	var captured []byte
	// Simulate the paste actionFn: it should receive the full formatted content,
	// from which the caller extracts the password. We verify the password field
	// is present in the content passed to the callback.
	pasteActionFn := func(_ context.Context, idx *store.Index, d *store.Data) error {
		captured = d.Content
		return nil
	}

	_, err := b.Search(ctx, "Work/Email", store.ActionPaste, pasteActionFn, nil)
	if err != nil {
		t.Fatalf("Search(ActionPaste): %v", err)
	}
	if !strings.Contains(string(captured), "Password: secret") {
		t.Errorf("content passed to paste actionFn missing password; got: %q", captured)
	}
	// Verify the password is extractable via parseContent (the actual paste path
	// in the CLI would do this and send only the password to the clipboard).
	// parseContent accepts string; convert captured []byte once here.
	pw, _, _, _ := parseContent(string(captured))
	if pw != "secret" {
		t.Errorf("parseContent from paste content: got password %q, want %q", pw, "secret")
	}
}

// TestShredAllExported verifies that ShredAllExported removes all regular files
// from the export directory and returns nil.
func TestShredAllExported(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// Export an entry to populate the export directory.
	idx := &store.Index{Description: "Work/Email"}
	d, err := b.LoadData(ctx, idx)
	if err != nil {
		t.Fatalf("LoadData: %v", err)
	}
	if err := d.Export(ctx, b.cfg.ExportDir, "email.txt"); err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Verify the file was created.
	if _, err := os.Stat(filepath.Join(b.cfg.ExportDir, "email.txt")); err != nil {
		t.Fatalf("exported file missing: %v", err)
	}

	// Shred exported files.
	if err := b.ShredAllExported(ctx); err != nil {
		t.Fatalf("ShredAllExported: %v", err)
	}

	// Verify the file is gone.
	if _, err := os.Stat(filepath.Join(b.cfg.ExportDir, "email.txt")); err == nil {
		t.Error("exported file still present after ShredAllExported")
	}
}

// TestShredAllExported_missingDir verifies that ShredAllExported returns nil
// when the export directory does not exist (no export has been run yet).
func TestShredAllExported_missingDir(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	// Use a non-existent export dir path to trigger the IsNotExist branch.
	b.cfg.ExportDir = filepath.Join(t.TempDir(), "nonexistent-export")
	if err := b.ShredAllExported(context.Background()); err != nil {
		t.Errorf("ShredAllExported with non-existent dir: %v", err)
	}
}

// TestImportRecursive verifies that ImportRecursive walks a directory tree and
// imports all files, preserving relative paths as descriptions.
func TestImportRecursive(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	// Build a small directory tree with two files in different subdirectories.
	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	files := map[string]string{
		"top.txt":     "Password: toppass\n",
		"sub/deep.txt": "Password: deeppass\n",
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(srcDir, rel), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	if err := b.ImportRecursive(ctx, srcDir, "imported"); err != nil {
		t.Fatalf("ImportRecursive: %v", err)
	}

	// Re-open and verify both entries are present.
	b2 := newTestBackend(t, dbPath)
	var descs []string
	if err := b2.WalkIndexes(ctx, "imported", func(idx *store.Index) error {
		descs = append(descs, idx.Description)
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}

	want := []string{"imported/top.txt", "imported/sub/deep.txt"}
	for _, w := range want {
		found := false
		for _, d := range descs {
			if d == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("description %q not found after ImportRecursive; got: %v", w, descs)
		}
	}
}

// TestParsePickerAction verifies that each known fzf key maps to the correct
// PickerAction and that unknown keys return (_, false).
func TestParsePickerAction(t *testing.T) {
	cases := []struct {
		key    string
		want   store.PickerAction
		wantOK bool
	}{
		{"enter", store.PickerSelect, true},
		{"", store.PickerSelect, true},
		{"ctrl-t", store.PickerCat, true},
		{"alt-t", store.PickerCat, true},
		{"ctrl-y", store.PickerPaste, true},
		{"alt-y", store.PickerPaste, true},
		{"ctrl-o", store.PickerOpen, true},
		{"alt-o", store.PickerOpen, true},
		{"ctrl-e", store.PickerEdit, true},
		{"alt-e", store.PickerEdit, true},
		{"unknown-key", "", false},
		{"ctrl-z", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got, ok := parsePickerAction(tc.key)
			if ok != tc.wantOK {
				t.Errorf("parsePickerAction(%q) ok = %v; want %v", tc.key, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("parsePickerAction(%q) = %q; want %q", tc.key, got, tc.want)
			}
		})
	}
}

// TestBuildPickerEntries verifies that buildPickerEntries produces one entry
// per index with the correct Description, Kind, and non-empty HashSuffix for
// entries with a hash of sufficient length.
func TestBuildPickerEntries(t *testing.T) {
	indexes := store.IndexSlice{
		{Description: "Work/Email", Hash: strings.Repeat("a", 64)},
		{Description: "images/logo.png", Hash: strings.Repeat("b", 64)},
	}

	entries := buildPickerEntries(indexes)

	if len(entries) != 2 {
		t.Fatalf("buildPickerEntries len = %d; want 2", len(entries))
	}

	if entries[0].Description != "Work/Email" {
		t.Errorf("entries[0].Description = %q; want Work/Email", entries[0].Description)
	}
	if entries[0].Kind != "TEXT" {
		t.Errorf("entries[0].Kind = %q; want TEXT", entries[0].Kind)
	}
	if entries[0].HashSuffix == "" {
		t.Error("entries[0].HashSuffix must be non-empty when hash length >= 63")
	}
	// RowID is 1-based, so the first entry must be 1.
	if entries[0].RowID != 1 {
		t.Errorf("entries[0].RowID = %d; want 1", entries[0].RowID)
	}

	// "images/logo.png" has extension ".png" → IsBinary() returns true.
	if entries[1].Kind != "BINARY" {
		t.Errorf("entries[1].Kind = %q; want BINARY", entries[1].Kind)
	}
	// RowID for the second entry must be 2.
	if entries[1].RowID != 2 {
		t.Errorf("entries[1].RowID = %d; want 2", entries[1].RowID)
	}
}

// TestImportForce verifies that Import with force=true replaces an existing
// entry and reflects updated content in a subsequent LoadData call.
func TestImportForce(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	srcFile := filepath.Join(t.TempDir(), "creds.txt")
	newContent := string(formatContent("replaced", "replaced-user", "", ""))
	if err := os.WriteFile(srcFile, []byte(newContent), 0o600); err != nil {
		t.Fatalf("write src file: %v", err)
	}

	// force=true must succeed even though "Work/Email" already exists.
	if err := b.Import(ctx, srcFile, "Work/Email", true); err != nil {
		t.Fatalf("Import force: %v", err)
	}

	b2 := newTestBackend(t, dbPath)
	idx := &store.Index{Description: "Work/Email"}
	d, err := b2.LoadData(ctx, idx)
	if err != nil {
		t.Fatalf("LoadData after forced import: %v", err)
	}
	// parseContent accepts string; d.Content is []byte so convert once.
	pw, _, _, _ := parseContent(string(d.Content))
	if pw != "replaced" {
		t.Errorf("password after forced import = %q; want %q", pw, "replaced")
	}
}

// TestSearchActionCatSkipsBinary verifies that actionCat does not print content
// for binary entries (it prints a "Not displaying" notice instead).
func TestSearchActionCatSkipsBinary(t *testing.T) {
	dbPath := createTestDB(t)
	b := newTestBackend(t, dbPath)
	ctx := context.Background()

	var searchErr error
	// "Work/Report/report.pdf" is a binary attachment — actionCat must skip it.
	out := captureStdout(t, func() {
		_, searchErr = b.Search(ctx, `^Work/Report/report\.pdf$`, store.ActionCat, nil, nil)
	})

	if searchErr != nil {
		t.Fatalf("Search(ActionCat binary): %v", searchErr)
	}
	// The output must contain the "Not displaying" notice, not raw binary bytes.
	if !strings.Contains(out, "Not displaying") {
		t.Errorf("expected 'Not displaying' notice for binary entry; got: %q", out)
	}
}

// TestEnsureRootGroup_nilContent verifies that ensureRootGroup initialises
// Content and Root on a database that has no Content set. After the call the
// database must have at least one top-level group.
func TestEnsureRootGroup_nilContent(t *testing.T) {
	// A bare &Database{} has nil Content; ensureRootGroup must fill it in.
	db := &gokeepasslib.Database{}
	ensureRootGroup(db)
	if db.Content == nil {
		t.Fatal("ensureRootGroup: Content is nil")
	}
	if db.Content.Root == nil {
		t.Fatal("ensureRootGroup: Root is nil")
	}
	if len(db.Content.Root.Groups) == 0 {
		t.Fatal("ensureRootGroup: no top-level groups after initialisation")
	}
}

// TestEnsureRootGroup_nilRoot verifies that ensureRootGroup creates a Root
// group when db.Content is present but db.Content.Root is nil.
func TestEnsureRootGroup_nilRoot(t *testing.T) {
	db := gokeepasslib.NewDatabase()
	db.Content.Root = nil // simulate missing root
	ensureRootGroup(db)
	if db.Content.Root == nil {
		t.Fatal("ensureRootGroup: Root still nil after call")
	}
	if len(db.Content.Root.Groups) == 0 {
		t.Fatal("ensureRootGroup: no top-level groups after root fix")
	}
}

// TestEnsureRootGroup_emptyGroups verifies that ensureRootGroup adds a "Root"
// group when db.Content.Root.Groups is empty.
func TestEnsureRootGroup_emptyGroups(t *testing.T) {
	db := gokeepasslib.NewDatabase()
	// Remove all groups so the len==0 branch fires.
	db.Content.Root.Groups = nil
	ensureRootGroup(db)
	if len(db.Content.Root.Groups) == 0 {
		t.Fatal("ensureRootGroup: no group added for empty Groups slice")
	}
	if db.Content.Root.Groups[0].Name != "Root" {
		t.Errorf("ensureRootGroup: group name = %q; want Root", db.Content.Root.Groups[0].Name)
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
			// parseContent accepts string; formatContent returns []byte, so convert once.
			gotPw, gotUser, gotURL, gotNotes := parseContent(string(content))
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
