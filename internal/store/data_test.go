// data_test.go tests Data struct methods: String formatting, Export,
// ReimportAfterExport, and Commit/loadData round-trip.
package store

import (
	"context"
	"errors"
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

// --- TestReimportAfterExportWriteBack ----------------------------------------

// writeBackMode selects which sub-case of TestReimportAfterExportWriteBack runs.
type writeBackMode int

const (
	modeNoWriteBack    writeBackMode = iota // nil WriteBack → falls back to Commit
	modeWriteBack                           // non-nil WriteBack → hook is called
	modeWriteBackError                      // non-nil WriteBack that returns an error
)

// TestReimportAfterExportWriteBack exercises three paths through ReimportAfterExport:
//   - nil WriteBack: falls back to Commit (verified via "missing committer" error)
//   - non-nil WriteBack: hook is called with the new content
//   - non-nil WriteBack that errors: error is propagated to the caller
//
// Table-driven so new cases can be added without duplicating setup logic.
func TestReimportAfterExportWriteBack(t *testing.T) {
	cases := []struct {
		name          string
		editedContent string
		mode          writeBackMode
	}{
		{
			name:          "nil WriteBack uses Commit path",
			editedContent: "updated via commit path\n",
			mode:          modeNoWriteBack,
		},
		{
			name:          "non-nil WriteBack is called with new content",
			editedContent: "updated via WriteBack hook\n",
			mode:          modeWriteBack,
		},
		{
			name:          "WriteBack error is propagated",
			editedContent: "updated content that triggers hook error\n",
			mode:          modeWriteBackError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()

			// Write the "edited" file that ReimportAfterExport will read.
			exportedPath := filepath.Join(dir, "secret.txt")
			if err := os.WriteFile(exportedPath, []byte(tc.editedContent), 0o600); err != nil {
				t.Fatalf("writing exported file: %v", err)
			}

			switch tc.mode {
			case modeWriteBack:
				testReimportWithWriteBack(t, ctx, exportedPath, tc.editedContent)
			case modeWriteBackError:
				testReimportWithWriteBackError(t, ctx, exportedPath)
			case modeNoWriteBack:
				testReimportWithoutWriteBack(t, ctx, dir, exportedPath, tc.editedContent)
			}
		})
	}
}

// testReimportWithWriteBack verifies that ReimportAfterExport calls WriteBack
// with the file's content when WriteBack is non-nil.
func testReimportWithWriteBack(t *testing.T, ctx context.Context, exportedPath, wantContent string) {
	t.Helper()

	var capturedContent []byte
	d := &Data{
		ExportedPath: exportedPath,
		WriteBack: func(newContent []byte) error {
			capturedContent = newContent
			return nil
		},
	}

	if err := d.ReimportAfterExport(ctx); err != nil {
		t.Fatalf("ReimportAfterExport with WriteBack: %v", err)
	}
	if string(capturedContent) != wantContent {
		t.Errorf("WriteBack received %q; want %q", capturedContent, wantContent)
	}
	// Content field should also be updated.
	if string(d.Content) != wantContent {
		t.Errorf("d.Content = %q; want %q", d.Content, wantContent)
	}
}

// testReimportWithWriteBackError verifies that when WriteBack returns a non-nil
// error, ReimportAfterExport propagates that error to the caller unchanged.
func testReimportWithWriteBackError(t *testing.T, ctx context.Context, exportedPath string) {
	t.Helper()

	sentinelErr := errors.New("backend write failed")
	d := &Data{
		ExportedPath: exportedPath,
		WriteBack: func(newContent []byte) error {
			return sentinelErr
		},
	}

	err := d.ReimportAfterExport(ctx)
	if err == nil {
		t.Fatal("ReimportAfterExport with failing WriteBack: expected error, got nil")
	}
	if !errors.Is(err, sentinelErr) {
		t.Errorf("error = %v; want sentinel error %v", err, sentinelErr)
	}
}

// testReimportWithoutWriteBack verifies that ReimportAfterExport falls back to
// Commit (encrypt+git-stage) when WriteBack is nil. We stub out git by leaving
// committer nil and expect the "missing committer" error, which confirms the
// Commit path was reached (not a hook).
func testReimportWithoutWriteBack(t *testing.T, ctx context.Context, dir, exportedPath, editedContent string) {
	t.Helper()

	c := newTestCipher(t)
	dataPath := filepath.Join(dir, "entry.data")

	d := &Data{
		ExportedPath: exportedPath,
		DataPath:     dataPath,
		encryptor:    c,
		// WriteBack intentionally left nil — must use Commit path.
		// committer left nil so Commit returns "missing committer" error,
		// confirming we reached Commit rather than any WriteBack hook.
	}

	err := d.ReimportAfterExport(ctx)
	if err == nil {
		t.Fatal("expected missing committer error from nil-WriteBack path, got nil")
	}
	if !strings.Contains(err.Error(), "missing committer") {
		t.Errorf("error = %q; want missing committer (confirms Commit path was taken)", err.Error())
	}
}
