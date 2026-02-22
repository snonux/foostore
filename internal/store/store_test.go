// store_test.go provides integration-level tests for the Store type.
// All tests use temporary directories and a real crypto.Cipher so that
// the encrypt/decrypt round-trip is exercised end-to-end.
// Tests that exercise git Add/Remove initialise a real git repo in the temp dir.
package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"codeberg.org/snonux/geheim/internal/config"
	"codeberg.org/snonux/geheim/internal/crypto"
	"codeberg.org/snonux/geheim/internal/git"
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
	d, err := loadData(ctx, dataPath, c)
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
	d, err := loadData(ctx, dataPath, c)
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
	d, err := loadData(ctx, dataPath, c)
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
