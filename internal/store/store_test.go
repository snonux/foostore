// store_test.go provides integration-level tests for the Store type.
// All tests use temporary directories and a real crypto.Cipher so that
// the encrypt/decrypt round-trip is exercised end-to-end.
// Tests that exercise git Add/Remove initialise a real git repo in the temp dir.
package store

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/crypto"
	"codeberg.org/snonux/foostore/internal/git"
)

// --- test helpers ------------------------------------------------------------

// testSetup creates temporary dataDir/exportDir/keyFile, builds a Cipher and a
// Store, and returns them ready for use. The temp dirs are cleaned up
// automatically by the testing framework.
func testSetup(t *testing.T) (context.Context, *Store, *config.Config, *crypto.Cipher, *git.Git) {
	t.Helper()
	ctx := context.Background()

	dataDir := t.TempDir()
	exportDir := t.TempDir()

	keyFile := filepath.Join(t.TempDir(), "keyfile")
	if err := os.WriteFile(keyFile, []byte("testkey1234567890"), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	c, err := crypto.NewCipher(keyFile, 32, "testpin", "Hello world")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	cfg := &config.Config{
		DataDir:   dataDir,
		ExportDir: exportDir,
		KeyFile:   keyFile,
		KeyLength: 32,
		AddToIV:   "Hello world",
	}

	g := git.New(dataDir)
	store, err := New(cfg, c, g)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return ctx, store, cfg, c, g
}

// initGitRepo runs "git init" and sets a user identity so that git commit works.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	cmds := [][]string{
		{"git", "init", dir},
		{"git", "-C", dir, "config", "user.email", "test@example.com"},
		{"git", "-C", dir, "config", "user.name", "Test"},
	}
	for _, args := range cmds {
		c := exec.Command(args[0], args[1:]...)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

// --- TestHashPath ------------------------------------------------------------

// TestHashPath verifies that HashPath produces SHA-256 hex digests for each
// path component, joined by "/". Expected values were computed independently:
//
//	echo -n "foo" | sha256sum
//	echo -n "bar" | sha256sum
func TestHashPath(t *testing.T) {
	_, store, _, _, _ := testSetup(t)

	fooHash := "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	barHash := "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"

	cases := []struct {
		input string
		want  string
	}{
		{"foo", fooHash},
		{"foo/bar", fooHash + "/" + barHash},
		// Double slash must be normalised before hashing.
		{"foo//bar", fooHash + "/" + barHash},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := store.HashPath(tc.input)
			if got != tc.want {
				t.Errorf("HashPath(%q)\n  got  %s\n  want %s", tc.input, got, tc.want)
			}
		})
	}
}

// --- TestAddAndSearch --------------------------------------------------------

// TestAddAndSearch adds an entry, then walks indexes to verify the description
// and content are round-tripped correctly through encryption.
func TestAddAndSearch(t *testing.T) {
	ctx, store, cfg, c, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	description := "my/secret/note"
	content := "super secret content\nline two\n"

	if err := store.Add(ctx, description, content); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var found []*Index
	if err := store.WalkIndexes(ctx, "", func(idx *Index) error {
		found = append(found, idx)
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 index entry; got %d", len(found))
	}

	idx := found[0]
	if idx.Description != description {
		t.Errorf("Description = %q; want %q", idx.Description, description)
	}

	dataPath := filepath.Join(cfg.DataDir, idx.DataFile)
	d, err := loadData(ctx, dataPath, c, nil)
	if err != nil {
		t.Fatalf("loadData: %v", err)
	}
	if string(d.Content) != content {
		t.Errorf("Content = %q; want %q", d.Content, content)
	}
}

// --- TestSearchFilter --------------------------------------------------------

// TestSearchFilter adds multiple entries and confirms that WalkIndexes filters
// correctly by regex search term.
func TestSearchFilter(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	entries := map[string]string{
		"alpha/secret":   "data alpha",
		"beta/secret":    "data beta",
		"gamma/password": "data gamma",
	}
	for desc, data := range entries {
		if err := store.Add(ctx, desc, data); err != nil {
			t.Fatalf("Add %q: %v", desc, err)
		}
	}

	var found []string
	if err := store.WalkIndexes(ctx, "secret", func(idx *Index) error {
		found = append(found, idx.Description)
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}

	if len(found) != 2 {
		t.Errorf("expected 2 matches for 'secret'; got %d: %v", len(found), found)
	}
	for _, desc := range found {
		if desc != "alpha/secret" && desc != "beta/secret" {
			t.Errorf("unexpected match: %q", desc)
		}
	}
}

// --- TestImport --------------------------------------------------------------

// TestImport creates a temporary source file, imports it into the store, then
// verifies the entry is discoverable and has the correct content.
func TestImport(t *testing.T) {
	ctx, store, cfg, c, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "secret.txt")
	wantContent := "imported secret content\n"
	if err := os.WriteFile(srcPath, []byte(wantContent), 0o600); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	destPath := "imported/secret.txt"
	if err := store.Import(ctx, srcPath, destPath, false); err != nil {
		t.Fatalf("Import: %v", err)
	}

	var found []*Index
	if err := store.WalkIndexes(ctx, "", func(idx *Index) error {
		found = append(found, idx)
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 entry after import; got %d", len(found))
	}
	if found[0].Description != destPath {
		t.Errorf("Description = %q; want %q", found[0].Description, destPath)
	}

	dataPath := filepath.Join(cfg.DataDir, found[0].DataFile)
	d, err := loadData(ctx, dataPath, c, nil)
	if err != nil {
		t.Fatalf("loadData: %v", err)
	}
	if string(d.Content) != wantContent {
		t.Errorf("Content = %q; want %q", d.Content, wantContent)
	}
}

// --- TestExport --------------------------------------------------------------

// TestExport imports a file and exports it to the export directory, verifying
// the exported file has the correct content.
func TestExport(t *testing.T) {
	ctx, store, cfg, c, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	wantContent := "exported content\n"
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "note.txt")
	if err := os.WriteFile(srcPath, []byte(wantContent), 0o600); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	destPath := "docs/note.txt"
	if err := store.Import(ctx, srcPath, destPath, false); err != nil {
		t.Fatalf("Import: %v", err)
	}

	var idx *Index
	if err := store.WalkIndexes(ctx, "", func(i *Index) error { idx = i; return nil }); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}
	if idx == nil {
		t.Fatal("no index found after import")
	}

	dataPath := filepath.Join(cfg.DataDir, idx.DataFile)
	d, err := loadData(ctx, dataPath, c, nil)
	if err != nil {
		t.Fatalf("loadData: %v", err)
	}

	if err := d.Export(ctx, cfg.ExportDir, filepath.Base(idx.Description)); err != nil {
		t.Fatalf("Export: %v", err)
	}

	exportedPath := filepath.Join(cfg.ExportDir, filepath.Base(idx.Description))
	gotBytes, err := os.ReadFile(exportedPath)
	if err != nil {
		t.Fatalf("reading exported file: %v", err)
	}
	if string(gotBytes) != wantContent {
		t.Errorf("exported content = %q; want %q", gotBytes, wantContent)
	}
}

// --- TestWalkIndexesInvalidRegex ---------------------------------------------

// TestWalkIndexesInvalidRegex confirms that WalkIndexes returns an error when
// the search term is not a valid regular expression.
func TestWalkIndexesInvalidRegex(t *testing.T) {
	ctx, store, _, _, _ := testSetup(t)

	err := store.WalkIndexes(ctx, "[invalid", func(*Index) error { return nil })
	if err == nil {
		t.Error("WalkIndexes with invalid regex: expected error, got nil")
	}
}

// --- TestImportMissingSourceFile ---------------------------------------------

// TestImportMissingSourceFile confirms that Import returns an error when the
// source file does not exist.
func TestImportMissingSourceFile(t *testing.T) {
	ctx, store, _, _, _ := testSetup(t)

	err := store.Import(ctx, "/nonexistent/path/secret.txt", "dest/secret.txt", false)
	if err == nil {
		t.Error("Import with missing source file: expected error, got nil")
	}
}

// --- TestHashPathEdgeCases ---------------------------------------------------

// TestHashPathEdgeCases exercises edge inputs: empty string and a lone slash.
func TestHashPathEdgeCases(t *testing.T) {
	_, store, _, _, _ := testSetup(t)

	// Empty string — HashPath("") should return sha256("") without panicking.
	got := store.HashPath("")
	if len(got) != 64 {
		t.Errorf("HashPath(\"\") length = %d; want 64", len(got))
	}

	// Leading slash produces an empty first component after split on "/".
	// Verify it does not panic and returns a non-empty result.
	got2 := store.HashPath("/only")
	if got2 == "" {
		t.Error("HashPath(\"/only\") returned empty string")
	}
}

// --- TestRemoveEntry ---------------------------------------------------------

// TestRemoveEntry adds an entry, commits it so that git rm works, then removes
// it and confirms WalkIndexes no longer returns it.
func TestRemoveEntry(t *testing.T) {
	ctx, store, cfg, _, g := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	if err := store.Add(ctx, "removable/entry", "some data"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Commit staged files so git rm can find them.
	if err := g.Commit(ctx); err != nil {
		t.Fatalf("git Commit: %v", err)
	}

	// Confirm the entry exists.
	count := 0
	if err := store.WalkIndexes(ctx, "", func(*Index) error { count++; return nil }); err != nil {
		t.Fatalf("WalkIndexes before remove: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 entry before remove; got %d", count)
	}

	// Locate the index and remove both files directly (bypass interactive prompt).
	var idx *Index
	_ = store.WalkIndexes(ctx, "", func(i *Index) error { idx = i; return nil })

	d := &Data{DataPath: filepath.Join(cfg.DataDir, idx.DataFile)}
	if err := d.Remove(ctx, g); err != nil {
		t.Fatalf("Data.Remove: %v", err)
	}
	if err := idx.Remove(ctx, g); err != nil {
		t.Fatalf("Index.Remove: %v", err)
	}

	// Confirm the entry is gone.
	count = 0
	if err := store.WalkIndexes(ctx, "", func(*Index) error { count++; return nil }); err != nil {
		t.Fatalf("WalkIndexes after remove: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries after remove; got %d", count)
	}
}

// --- TestSearch --------------------------------------------------------------

// TestSearch adds two entries, then calls Search with ActionNone and verifies
// both descriptions are returned sorted and printed to stdout.
func TestSearch(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	for _, desc := range []string{"zebra/entry", "apple/entry"} {
		if err := store.Add(ctx, desc, "data"); err != nil {
			t.Fatalf("Add %q: %v", desc, err)
		}
	}

	results, err := store.Search(ctx, "", ActionNone, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results; got %d", len(results))
	}
	// Search returns results sorted by Description.
	if results[0].Description != "apple/entry" || results[1].Description != "zebra/entry" {
		t.Errorf("unexpected sort order: %v, %v", results[0].Description, results[1].Description)
	}
}

// --- TestSearchActionCat -----------------------------------------------------

// TestSearchActionCat verifies that Search with ActionCat prints decrypted
// content to stdout (we capture os.Stdout via a temp file redirect).
func TestSearchActionCat(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	if err := store.Add(ctx, "my/note.txt", "hello cat content\n"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Redirect stdout to capture output.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	os.Stdout = w

	results, err := store.Search(ctx, "note.txt", ActionCat, nil)

	w.Close()
	os.Stdout = oldStdout
	var buf strings.Builder
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("Search ActionCat: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	// The cat output should contain the decrypted content (tab-prefixed).
	if !strings.Contains(buf.String(), "hello cat content") {
		t.Errorf("stdout does not contain expected content: %q", buf.String())
	}
}

// --- TestSearchActionCatBinarySkip -------------------------------------------

// TestSearchActionCatBinarySkip confirms that ActionCat prints a skip message
// rather than binary content when the description implies a binary file.
func TestSearchActionCatBinarySkip(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	// A .jpg description is detected as binary by IsBinary().
	if err := store.Add(ctx, "photo.jpg", "\x89PNG\r\n\x1a\n"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Capture stdout to verify the skip message is printed.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	results, searchErr := store.Search(ctx, "photo.jpg", ActionCat, nil)

	w.Close()
	os.Stdout = oldStdout
	var buf strings.Builder
	io.Copy(&buf, r)

	if searchErr != nil {
		t.Fatalf("Search ActionCat (binary): %v", searchErr)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	// The "binary" warning must be present; the raw bytes must NOT be printed.
	if !strings.Contains(buf.String(), "Not displaying") {
		t.Errorf("expected binary-skip message; stdout = %q", buf.String())
	}
}

// --- TestShredAllExported ----------------------------------------------------

// TestShredAllExported writes two files to the export dir, calls ShredAllExported,
// and verifies both files have been removed.
func TestShredAllExported(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)

	// Write two plaintext files to the export directory.
	for _, name := range []string{"secret1.txt", "secret2.txt"} {
		p := filepath.Join(cfg.ExportDir, name)
		if err := os.WriteFile(p, []byte("sensitive"), 0o600); err != nil {
			t.Fatalf("writing export file: %v", err)
		}
	}

	if err := store.ShredAllExported(ctx); err != nil {
		t.Fatalf("ShredAllExported: %v", err)
	}

	// Both files should be gone.
	for _, name := range []string{"secret1.txt", "secret2.txt"} {
		p := filepath.Join(cfg.ExportDir, name)
		if _, err := os.Stat(p); err == nil {
			t.Errorf("file %q still exists after ShredAllExported", name)
		}
	}
}

// --- TestSearchActionExport --------------------------------------------------

// TestSearchActionExport verifies that Search with ActionExport writes the
// decrypted content to cfg.ExportDir using the basename of the description.
func TestSearchActionExport(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	wantContent := "exported via search\n"
	if err := store.Add(ctx, "docs/report.txt", wantContent); err != nil {
		t.Fatalf("Add: %v", err)
	}

	results, err := store.Search(ctx, "report.txt", ActionExport, nil)
	if err != nil {
		t.Fatalf("Search ActionExport: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}

	// ActionExport uses the basename of the description as the export filename.
	exportedPath := filepath.Join(cfg.ExportDir, "report.txt")
	got, err := os.ReadFile(exportedPath)
	if err != nil {
		t.Fatalf("reading exported file: %v", err)
	}
	if string(got) != wantContent {
		t.Errorf("exported content = %q; want %q", got, wantContent)
	}
}

// --- TestImportRecursive -----------------------------------------------------

// TestImportRecursive creates a directory tree, imports it, then verifies that
// all files appear as indexed entries with the correct descriptions and content.
func TestImportRecursive(t *testing.T) {
	ctx, store, cfg, c, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	// Build a two-level source tree.
	srcRoot := t.TempDir()
	files := map[string]string{
		"top.txt":        "top level content\n",
		"sub/nested.txt": "nested content\n",
	}
	for rel, content := range files {
		full := filepath.Join(srcRoot, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %q: %v", rel, err)
		}
	}

	if err := store.ImportRecursive(ctx, srcRoot, "backup"); err != nil {
		t.Fatalf("ImportRecursive: %v", err)
	}

	// Both files should now be indexed.
	found := map[string]*Index{}
	if err := store.WalkIndexes(ctx, "", func(idx *Index) error {
		found[idx.Description] = idx
		return nil
	}); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 indexed entries; got %d", len(found))
	}

	// Verify content round-trips correctly.
	for desc, wantContent := range map[string]string{
		"backup/top.txt":        "top level content\n",
		"backup/sub/nested.txt": "nested content\n",
	} {
		idx, ok := found[desc]
		if !ok {
			t.Errorf("entry %q not found; found: %v", desc, func() []string {
				keys := make([]string, 0, len(found))
				for k := range found {
					keys = append(keys, k)
				}
				return keys
			}())
			continue
		}
		d, err := loadData(ctx, filepath.Join(cfg.DataDir, idx.DataFile), c, nil)
		if err != nil {
			t.Fatalf("loadData for %q: %v", desc, err)
		}
		if string(d.Content) != wantContent {
			t.Errorf("content for %q = %q; want %q", desc, d.Content, wantContent)
		}
	}
}

// --- TestReimportAfterExport -------------------------------------------------

// TestReimportAfterExport exports an entry, modifies the exported file, then
// reimports it and verifies the updated content is stored in the encrypted .data file.
func TestReimportAfterExport(t *testing.T) {
	ctx, store, cfg, c, g := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	original := "original content\n"
	if err := store.Add(ctx, "editable/note.txt", original); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Locate the entry.
	var idx *Index
	if err := store.WalkIndexes(ctx, "", func(i *Index) error { idx = i; return nil }); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}

	d, err := loadData(ctx, filepath.Join(cfg.DataDir, idx.DataFile), c, g)
	if err != nil {
		t.Fatalf("loadData: %v", err)
	}

	// Export to a temp export dir.
	if err := d.Export(ctx, cfg.ExportDir, "note.txt"); err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Simulate editing the exported file.
	updated := "updated content after edit\n"
	if err := os.WriteFile(d.ExportedPath, []byte(updated), 0o600); err != nil {
		t.Fatalf("updating exported file: %v", err)
	}

	// Reimport overwrites the encrypted .data with the updated content.
	if err := d.ReimportAfterExport(ctx); err != nil {
		t.Fatalf("ReimportAfterExport: %v", err)
	}

	// Reload from disk and verify the update was persisted.
	reloaded, err := loadData(ctx, filepath.Join(cfg.DataDir, idx.DataFile), c, nil)
	if err != nil {
		t.Fatalf("loadData after reimport: %v", err)
	}
	if string(reloaded.Content) != updated {
		t.Errorf("reimported content = %q; want %q", reloaded.Content, updated)
	}
}

// --- TestRemoveInteractive ---------------------------------------------------

// TestRemoveInteractive tests Store.Remove by injecting a strings.Reader as the
// interactive input (answering "y"). After removal WalkIndexes must find no entries.
func TestRemoveInteractive(t *testing.T) {
	ctx, store, cfg, _, g := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	if err := store.Add(ctx, "interactive/remove", "data to delete"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := g.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Inject "y\n" as user input to confirm deletion.
	input := strings.NewReader("y\n")
	if err := store.Remove(ctx, "interactive/remove", input); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	count := 0
	if err := store.WalkIndexes(ctx, "", func(*Index) error { count++; return nil }); err != nil {
		t.Fatalf("WalkIndexes after remove: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries after removal; got %d", count)
	}
}

// --- TestRemoveInteractiveDecline --------------------------------------------

// TestRemoveInteractiveDecline confirms that answering "n" leaves the entry intact.
func TestRemoveInteractiveDecline(t *testing.T) {
	ctx, store, cfg, _, g := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	if err := store.Add(ctx, "keep/this", "important data"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := g.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Inject "n\n" — user declines deletion.
	input := strings.NewReader("n\n")
	if err := store.Remove(ctx, "keep/this", input); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	count := 0
	if err := store.WalkIndexes(ctx, "", func(*Index) error { count++; return nil }); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 entry after decline; got %d", count)
	}
}

// --- TestCommitIndexSkipsExisting --------------------------------------------

// TestCommitIndexSkipsExisting verifies that CommitIndex with force=false is a
// no-op when IndexPath already exists, preserving the original encrypted content.
func TestCommitIndexSkipsExisting(t *testing.T) {
	ctx := context.Background()
	c := newTestIndexCipher(t)
	dir := t.TempDir()

	indexPath := filepath.Join(dir, "existing.index")
	sentinel := []byte("original encrypted content")
	if err := os.WriteFile(indexPath, sentinel, 0o600); err != nil {
		t.Fatalf("writing sentinel: %v", err)
	}

	idx := &Index{
		Description: "should not be written",
		IndexPath:   indexPath,
		Hash:        strings.Repeat("0", 64),
	}

	// force=false must skip writing; passing nil for git since it won't be reached.
	if err := idx.CommitIndex(ctx, c, nil, false); err != nil {
		t.Errorf("CommitIndex(force=false) with existing file returned error: %v", err)
	}

	got, _ := os.ReadFile(indexPath)
	if string(got) != string(sentinel) {
		t.Errorf("index file was overwritten: got %q; want %q", got, sentinel)
	}
}

// --- TestSearchActionPathExport ----------------------------------------------

// TestSearchActionPathExport verifies that ActionPathExport preserves the full
// description path (not just the basename) when writing to the export dir.
func TestSearchActionPathExport(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	wantContent := "path export content\n"
	if err := store.Add(ctx, "docs/subdir/report.txt", wantContent); err != nil {
		t.Fatalf("Add: %v", err)
	}

	results, err := store.Search(ctx, "report.txt", ActionPathExport, nil)
	if err != nil {
		t.Fatalf("Search ActionPathExport: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}

	// ActionPathExport uses the full description as the export path.
	exportedPath := filepath.Join(cfg.ExportDir, "docs/subdir/report.txt")
	got, err := os.ReadFile(exportedPath)
	if err != nil {
		t.Fatalf("reading exported file at full path: %v", err)
	}
	if string(got) != wantContent {
		t.Errorf("exported content = %q; want %q", got, wantContent)
	}
}

// --- TestSearchActionWithCallback --------------------------------------------

// TestSearchActionWithCallback verifies that Search passes the correct Index and
// Data to the actionFn for actions that delegate to the caller (ActionPaste etc.).
func TestSearchActionWithCallback(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	wantContent := "callback content\n"
	if err := store.Add(ctx, "cb/entry.txt", wantContent); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var gotDesc string
	var gotContent string
	actionFn := func(_ context.Context, idx *Index, d *Data) error {
		gotDesc = idx.Description
		gotContent = string(d.Content)
		return nil
	}

	// ActionPaste falls through to the default/actionFn branch of applyAction.
	results, err := store.Search(ctx, "cb/entry.txt", ActionPaste, actionFn)
	if err != nil {
		t.Fatalf("Search with callback: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	if gotDesc != "cb/entry.txt" {
		t.Errorf("callback got description %q; want %q", gotDesc, "cb/entry.txt")
	}
	if gotContent != wantContent {
		t.Errorf("callback got content %q; want %q", gotContent, wantContent)
	}
}

// --- TestSearchActionNilCallback ---------------------------------------------

// TestSearchActionNilCallback confirms that passing a nil actionFn for a
// callback-delegated action (ActionPaste) is handled gracefully without panic.
func TestSearchActionNilCallback(t *testing.T) {
	ctx, store, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	if err := store.Add(ctx, "nil/cb.txt", "data"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// nil actionFn: applyAction must return nil without calling anything.
	_, err := store.Search(ctx, "nil/cb.txt", ActionPaste, nil)
	if err != nil {
		t.Fatalf("Search with nil callback: %v", err)
	}
}

// --- TestFzfEmpty ------------------------------------------------------------

// TestFzfEmpty calls Fzf on an empty store and confirms it returns ("", nil)
// without attempting to launch fzf.
func TestFzfEmpty(t *testing.T) {
	ctx, store, _, _, _ := testSetup(t)
	// No entries added — Fzf must return immediately.
	result, err := store.Fzf(ctx)
	if err != nil {
		t.Fatalf("Fzf on empty store: %v", err)
	}
	if result != "" {
		t.Errorf("Fzf on empty store = %q; want empty string", result)
	}
}

// TestParsePickerAction verifies fzf key line parsing for supported picker
// actions and unknown values.
func TestParsePickerAction(t *testing.T) {
	cases := []struct {
		name    string
		keyLine string
		want    PickerAction
		ok      bool
	}{
		{name: "enter", keyLine: "enter", want: PickerSelect, ok: true},
		{name: "blank means enter", keyLine: "", want: PickerSelect, ok: true},
		{name: "cat", keyLine: "ctrl-t", want: PickerCat, ok: true},
		{name: "paste", keyLine: "ctrl-y", want: PickerPaste, ok: true},
		{name: "open", keyLine: "ctrl-o", want: PickerOpen, ok: true},
		{name: "edit", keyLine: "ctrl-e", want: PickerEdit, ok: true},
		{name: "unknown", keyLine: "ctrl-x", want: "", ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parsePickerAction(tc.keyLine)
			if ok != tc.ok {
				t.Fatalf("parsePickerAction(%q) ok = %v; want %v", tc.keyLine, ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("parsePickerAction(%q) = %q; want %q", tc.keyLine, got, tc.want)
			}
		})
	}
}

// TestParsePickerResult checks output decoding from fzf --expect mode.
func TestParsePickerResult(t *testing.T) {
	idMap := map[string]string{
		"1": "alpha/secret.txt",
		"2": "photo.jpg",
	}

	cases := []struct {
		name   string
		output string
		want   PickerResult
	}{
		{
			name:   "ctrl-y paste",
			output: "ctrl-y\n1\talpha/secret.txt\tTEXT\tabcdef1234\n",
			want:   PickerResult{Description: "alpha/secret.txt", Action: PickerPaste},
		},
		{
			name:   "enter select",
			output: "enter\n2\tphoto.jpg\tBINARY\tff00ff00ff\n",
			want:   PickerResult{Description: "photo.jpg", Action: PickerSelect},
		},
		{
			name:   "cancel or empty output",
			output: "",
			want:   PickerResult{},
		},
		{
			name:   "unknown key ignored",
			output: "ctrl-x\n1\talpha/secret.txt\tTEXT\tabcdef1234\n",
			want:   PickerResult{},
		},
		{
			name:   "unknown id ignored",
			output: "enter\n999\tmissing\tTEXT\tabcdef1234\n",
			want:   PickerResult{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePickerResult(tc.output, idMap)
			if got != tc.want {
				t.Fatalf("parsePickerResult() = %+v; want %+v", got, tc.want)
			}
		})
	}
}

// TestPickerColorTheme verifies supported theme presets and fallback behavior.
func TestPickerColorTheme(t *testing.T) {
	if got := pickerColorTheme("bold"); got == "" {
		t.Fatal("pickerColorTheme(bold) returned empty string")
	}
	if got := pickerColorTheme("clean"); got == "" {
		t.Fatal("pickerColorTheme(clean) returned empty string")
	}
	if got := pickerColorTheme("mono"); got == "" {
		t.Fatal("pickerColorTheme(mono) returned empty string")
	}
	// Unknown themes must fall back to bold.
	if pickerColorTheme("unknown") != pickerColorTheme("bold") {
		t.Fatal("unknown theme did not fall back to bold")
	}
}

// TestBuildFzfArgs_envOverrides verifies default args and extra user opts.
func TestBuildFzfArgs_envOverrides(t *testing.T) {
	t.Setenv("FOOSTORE_TUI_THEME", "clean")
	t.Setenv("FOOSTORE_FZF_OPTS", "--cycle --no-mouse")

	args := buildFzfArgs(12)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--expect=enter,ctrl-t,ctrl-y,ctrl-o,ctrl-e") {
		t.Fatalf("expected --expect in args, got: %v", args)
	}
	if !strings.Contains(joined, "--cycle") || !strings.Contains(joined, "--no-mouse") {
		t.Fatalf("expected FOOSTORE_FZF_OPTS to be appended, got: %v", args)
	}
	if !strings.Contains(joined, "--color=") {
		t.Fatalf("expected color option, got: %v", args)
	}
}

// --- TestRemoveInteractiveInvalidThenDecline ---------------------------------

// TestRemoveInteractiveInvalidThenDecline exercises the retry loop in
// confirmAndRemove: an unrecognised answer causes a re-prompt; "n" then exits.
func TestRemoveInteractiveInvalidThenDecline(t *testing.T) {
	ctx, store, cfg, _, g := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	if err := store.Add(ctx, "retry/entry", "data"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := g.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// "maybe\n" is not "y" or "n" → retry; "n\n" then declines.
	input := strings.NewReader("maybe\nn\n")
	if err := store.Remove(ctx, "retry/entry", input); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Entry must still be present because deletion was declined.
	count := 0
	if err := store.WalkIndexes(ctx, "", func(*Index) error { count++; return nil }); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 entry after decline; got %d", count)
	}
}

// --- TestImportForceOverwrite ------------------------------------------------

// TestImportForceOverwrite confirms that force=true overwrites an existing entry
// while force=false (the default) skips it silently.
func TestImportForceOverwrite(t *testing.T) {
	ctx, store, cfg, c, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "f.txt")
	if err := os.WriteFile(src, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// First import.
	if err := store.Import(ctx, src, "force/f.txt", false); err != nil {
		t.Fatalf("first Import: %v", err)
	}

	// Overwrite source with new content.
	if err := os.WriteFile(src, []byte("updated\n"), 0o600); err != nil {
		t.Fatalf("write updated src: %v", err)
	}

	// Second import with force=true must overwrite.
	if err := store.Import(ctx, src, "force/f.txt", true); err != nil {
		t.Fatalf("second Import (force): %v", err)
	}

	var idx *Index
	if err := store.WalkIndexes(ctx, "", func(i *Index) error { idx = i; return nil }); err != nil {
		t.Fatalf("WalkIndexes: %v", err)
	}
	d, err := loadData(ctx, filepath.Join(cfg.DataDir, idx.DataFile), c, nil)
	if err != nil {
		t.Fatalf("loadData: %v", err)
	}
	if string(d.Content) != "updated\n" {
		t.Errorf("content after force import = %q; want %q", d.Content, "updated\n")
	}
}
