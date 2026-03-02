// data_test.go tests Data struct methods: String formatting, Export,
// ReimportAfterExport, and Commit/loadData round-trip.
package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/snonux/foostore/internal/crypto"
)

// --- helpers -----------------------------------------------------------------

// newTestCipher builds a Cipher from a freshly written temp key file.
func newTestCipher(t *testing.T) *crypto.Cipher {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("testkey1234567890"), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	c, err := crypto.NewCipher(keyFile, 32, "testpin", "Hello world")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

// --- TestDataString ----------------------------------------------------------

// TestDataString verifies that String() tab-indents content and appends a newline,
// matching Ruby's "\t#{@data.gsub("\n", "\n\t")}\n".
func TestDataString(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "single line",
			content: "hello",
			want:    "\thello\n",
		},
		{
			name:    "multi-line",
			content: "line1\nline2\nline3",
			want:    "\tline1\n\tline2\n\tline3\n",
		},
		{
			name:    "empty",
			content: "",
			want:    "\t\n",
		},
		{
			name:    "trailing newline",
			content: "hello\n",
			want:    "\thello\n\t\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Data{Content: []byte(tc.content)}
			got := d.String()
			if got != tc.want {
				t.Errorf("String() = %q; want %q", got, tc.want)
			}
		})
	}
}

// --- TestDataCommitAndLoad ---------------------------------------------------

// TestDataCommitAndLoad encrypts content directly and reads it back via
// loadData, verifying the full encrypt/decrypt round-trip.
// (Commit is tested in the integration tests that wire up a real git repo;
// here we test the encrypt+write+decrypt path without git scaffolding.)
func TestDataCommitAndLoad(t *testing.T) {
	ctx := context.Background()
	c := newTestCipher(t)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "test.data")
	wantContent := "my secret data\nwith newlines\n"

	ciphertext, err := c.Encrypt([]byte(wantContent))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.WriteFile(dataPath, ciphertext, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := loadData(ctx, dataPath, c, nil)
	if err != nil {
		t.Fatalf("loadData: %v", err)
	}
	if string(loaded.Content) != wantContent {
		t.Errorf("loadData content = %q; want %q", loaded.Content, wantContent)
	}
}

// --- TestDataExport ----------------------------------------------------------

// TestDataExport verifies that Export writes Content to exportDir/destinationFile
// and sets ExportedPath correctly.
func TestDataExport(t *testing.T) {
	ctx := context.Background()
	exportDir := t.TempDir()
	wantContent := "export me\n"

	d := &Data{Content: []byte(wantContent)}
	if err := d.Export(ctx, exportDir, "subdir/note.txt"); err != nil {
		t.Fatalf("Export: %v", err)
	}

	expectedPath := filepath.Join(exportDir, "subdir", "note.txt")
	if d.ExportedPath != expectedPath {
		t.Errorf("ExportedPath = %q; want %q", d.ExportedPath, expectedPath)
	}

	got, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("reading exported file: %v", err)
	}
	if string(got) != wantContent {
		t.Errorf("exported content = %q; want %q", got, wantContent)
	}
}

// --- TestDataExportCreatesSubdir ---------------------------------------------

// TestDataExportCreatesSubdir confirms that Export creates intermediate directories.
func TestDataExportCreatesSubdir(t *testing.T) {
	ctx := context.Background()
	exportDir := t.TempDir()

	d := &Data{Content: []byte("data")}
	deepPath := "a/b/c/d/file.txt"
	if err := d.Export(ctx, exportDir, deepPath); err != nil {
		t.Fatalf("Export with deep path: %v", err)
	}

	fullPath := filepath.Join(exportDir, deepPath)
	if _, err := os.Stat(fullPath); err != nil {
		t.Errorf("exported file not found at %q: %v", fullPath, err)
	}
}

// --- TestLoadDataMissingFile -------------------------------------------------

// TestLoadDataMissingFile verifies that loadData returns an error when the data
// file does not exist on disk.
func TestLoadDataMissingFile(t *testing.T) {
	ctx := context.Background()
	c := newTestCipher(t)

	_, err := loadData(ctx, "/nonexistent/path/to.data", c, nil)
	if err == nil {
		t.Error("loadData with missing file: expected error, got nil")
	}
}

// --- TestLoadDataCorrupted ---------------------------------------------------

// TestLoadDataCorrupted verifies that loadData returns an error when the file
// contains data that cannot be decrypted (not valid ciphertext).
func TestLoadDataCorrupted(t *testing.T) {
	ctx := context.Background()
	c := newTestCipher(t)

	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.data")
	// Write garbage that is not valid AES-CBC ciphertext.
	if err := os.WriteFile(badPath, []byte("not valid ciphertext"), 0o600); err != nil {
		t.Fatalf("writing bad file: %v", err)
	}

	_, err := loadData(ctx, badPath, c, nil)
	if err == nil {
		t.Error("loadData with corrupted file: expected error, got nil")
	}
}

// --- TestDataExportUnwritable ------------------------------------------------

// TestDataExportUnwritable verifies that Export returns an error when the
// destination directory cannot be created (non-writable parent).
func TestDataExportUnwritable(t *testing.T) {
	// Skip when running as root since root can write anywhere.
	if os.Getuid() == 0 {
		t.Skip("running as root; permission check not applicable")
	}

	ctx := context.Background()
	d := &Data{Content: []byte("test")}

	// /nonexistent is a path whose parent "/" is read-only for non-root users.
	err := d.Export(ctx, "/nonexistent/dir", "file.txt")
	if err == nil {
		t.Error("Export to unwritable dir: expected error, got nil")
	}
}

// --- TestDataCommitSkipsExisting ---------------------------------------------

// TestDataCommitSkipsExisting checks that Commit with force=false is a no-op
// when the file already exists, printing a warning rather than erroring.
func TestDataCommitSkipsExisting(t *testing.T) {
	ctx := context.Background()
	c := newTestCipher(t)
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "existing.data")

	// Write a sentinel file.
	sentinel := []byte("original")
	if err := os.WriteFile(dataPath, sentinel, 0o600); err != nil {
		t.Fatalf("writing sentinel: %v", err)
	}

	d := &Data{
		Content:   []byte("new content that should NOT overwrite"),
		DataPath:  dataPath,
		encryptor: c,
	}

	// Commit with force=false must not overwrite and should return before
	// encrypting or touching git dependencies.
	err := d.Commit(ctx, false)
	if err != nil {
		t.Errorf("Commit(force=false) with existing file returned error: %v", err)
	}

	// Original content must be unchanged.
	got, _ := os.ReadFile(dataPath)
	if string(got) != string(sentinel) {
		t.Errorf("file was overwritten: got %q; want %q", got, sentinel)
	}
}

func TestDataCommitMissingEncryptor(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d := &Data{
		Content:  []byte("content"),
		DataPath: filepath.Join(dir, "entry.data"),
	}

	err := d.Commit(ctx, true)
	if err == nil {
		t.Fatal("Commit with nil encryptor: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing encryptor") {
		t.Fatalf("Commit error = %q; want missing encryptor", err.Error())
	}
}

func TestDataCommitMissingCommitter(t *testing.T) {
	ctx := context.Background()
	c := newTestCipher(t)
	dir := t.TempDir()
	d := &Data{
		Content:   []byte("content"),
		DataPath:  filepath.Join(dir, "entry.data"),
		encryptor: c,
	}

	err := d.Commit(ctx, true)
	if err == nil {
		t.Fatal("Commit with nil committer: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing committer") {
		t.Fatalf("Commit error = %q; want missing committer", err.Error())
	}
}
