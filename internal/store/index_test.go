// index_test.go tests the Index struct methods: IsBinary and String formatting.
package store

import (
	"strings"
	"testing"
)

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

// --- TestIndexSort -----------------------------------------------------------

// TestIndexSort verifies that IndexSlice sorts by Description alphabetically.
func TestIndexSort(t *testing.T) {
	hash := strings.Repeat("0", 64)
	indexes := IndexSlice{
		{Description: "zebra", Hash: hash},
		{Description: "apple", Hash: hash},
		{Description: "mango", Hash: hash},
	}

	// Use sort package via the interface methods directly.
	n := indexes.Len()
	if n != 3 {
		t.Fatalf("Len() = %d; want 3", n)
	}

	// apple < mango should hold.
	appleIdx, mangoIdx := 1, 2 // after original order: zebra=0, apple=1, mango=2
	if !indexes.Less(appleIdx, mangoIdx) {
		t.Errorf("Less(apple, mango) = false; want true")
	}

	// Swap zebra and apple.
	indexes.Swap(0, 1)
	if indexes[0].Description != "apple" || indexes[1].Description != "zebra" {
		t.Errorf("Swap(0,1) did not exchange elements")
	}
}
