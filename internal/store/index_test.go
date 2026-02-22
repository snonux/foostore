// index_test.go tests the Index struct methods: IsBinary and String formatting.
package store

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"codeberg.org/snonux/foostore/internal/crypto"
)

// newTestIndexCipher is a local helper to avoid import cycle via store_test.go.
func newTestIndexCipher(t *testing.T) *crypto.Cipher {
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

// --- TestIsBinary ------------------------------------------------------------

// TestIsBinary verifies that IsBinary returns the correct value for every case
// in the Ruby binary? method, including the known text extensions and the
// presence/absence of any "." in the description.
func TestIsBinary(t *testing.T) {
	cases := []struct {
		description string
		want        bool
	}{
		// Known text extensions must return false regardless of other content.
		{"readme.txt", false},
		{"path/to/file.txt", false},
		{"notes.README", false},
		{"app.conf", false},
		{"data.csv", false},
		{"README.md", false},
		// A description with a dot but none of the whitelisted extensions → binary.
		{"archive.tar.gz", true},
		{"document.pdf", true},
		{"photo.jpg", true},
		// No dot at all → not binary.
		{"secretpassword", false},
		{"my/long/path/without/extension", false},
		// Edge case: description that contains both a whitelisted and a binary extension.
		// Ruby checks in order; .txt match returns false before reaching the dot check.
		{"backup.txt.gz", false},
		// .md takes priority over the presence of a non-whitelisted dot.
		{"notes.md.bak", false},
	}

	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			idx := &Index{Description: tc.description}
			got := idx.IsBinary()
			if got != tc.want {
				t.Errorf("IsBinary(%q) = %v; want %v", tc.description, got, tc.want)
			}
		})
	}
}

// --- TestIndexString ---------------------------------------------------------

// TestIndexString verifies the String() format for both text and binary entries.
// The hash suffix is 10 chars from positions [53:63] of the 64-char hex hash.
func TestIndexString(t *testing.T) {
	// Construct a synthetic 64-char hash for predictable output.
	hash := strings.Repeat("a", 53) + "0123456789" + "b" // 64 chars total
	// hash[53:63] == "0123456789"

	t.Run("text entry", func(t *testing.T) {
		idx := &Index{
			Description: "my/secret.txt",
			Hash:        hash,
		}
		got := idx.String()
		want := "my/secret.txt; ...0123456789\n"
		if got != want {
			t.Errorf("String() = %q; want %q", got, want)
		}
	})

	t.Run("binary entry", func(t *testing.T) {
		idx := &Index{
			Description: "archive.tar.gz",
			Hash:        hash,
		}
		got := idx.String()
		want := "archive.tar.gz; (BINARY) ...0123456789\n"
		if got != want {
			t.Errorf("String() = %q; want %q", got, want)
		}
	})
}

// --- TestLoadIndexMissingFile ------------------------------------------------

// TestLoadIndexMissingFile confirms that loadIndex returns an error when the
// .index file does not exist on disk.
func TestLoadIndexMissingFile(t *testing.T) {
	ctx := context.Background()
	c := newTestIndexCipher(t)

	_, err := loadIndex(ctx, "/nonexistent/path/to.index", t.TempDir(), c)
	if err == nil {
		t.Error("loadIndex with missing file: expected error, got nil")
	}
}

// --- TestLoadIndexCorrupted --------------------------------------------------

// TestLoadIndexCorrupted confirms that loadIndex returns an error when the file
// contains data that cannot be decrypted (not valid ciphertext).
func TestLoadIndexCorrupted(t *testing.T) {
	ctx := context.Background()
	c := newTestIndexCipher(t)

	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.index")
	if err := os.WriteFile(badPath, []byte("not valid ciphertext"), 0o600); err != nil {
		t.Fatalf("writing bad file: %v", err)
	}

	_, err := loadIndex(ctx, badPath, dir, c)
	if err == nil {
		t.Error("loadIndex with corrupted file: expected error, got nil")
	}
}

// --- TestIndexSort -----------------------------------------------------------

// TestIndexSort verifies that IndexSlice sorts by Description alphabetically
// using sort.Sort, and validates the sort.Interface helper methods directly.
func TestIndexSort(t *testing.T) {
	hash := strings.Repeat("0", 64)
	indexes := IndexSlice{
		{Description: "zebra", Hash: hash},
		{Description: "apple", Hash: hash},
		{Description: "mango", Hash: hash},
	}

	if n := indexes.Len(); n != 3 {
		t.Fatalf("Len() = %d; want 3", n)
	}

	// Before sorting: zebra=0, apple=1, mango=2 — Less(1,2) = apple < mango = true.
	if !indexes.Less(1, 2) {
		t.Errorf("Less(apple, mango) = false; want true")
	}
	// Swap and verify.
	indexes.Swap(0, 1)
	if indexes[0].Description != "apple" || indexes[1].Description != "zebra" {
		t.Errorf("Swap(0,1) did not exchange elements")
	}
	// Restore original order before sort.Sort.
	indexes.Swap(0, 1)

	// Verify sort.Sort produces ascending alphabetical order.
	sort.Sort(indexes)
	want := []string{"apple", "mango", "zebra"}
	for i, w := range want {
		if indexes[i].Description != w {
			t.Errorf("indexes[%d].Description = %q; want %q", i, indexes[i].Description, w)
		}
	}
}
