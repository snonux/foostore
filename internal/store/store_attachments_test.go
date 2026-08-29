package store

import (
	"os"
	"testing"
)

func TestListAttachments_geheim(t *testing.T) {
	ctx, st, cfg, _, _ := testSetup(t)
	initGitRepo(t, cfg.DataDir)

	if err := st.Add(ctx, "keys/foo.txt", "parent notes"); err != nil {
		t.Fatalf("Add parent: %v", err)
	}
	if err := st.Import(ctx, writeTempFile(t, []byte("bin1")), "keys/foo.txt/one.bin", true); err != nil {
		t.Fatalf("Import one.bin: %v", err)
	}
	if err := st.Import(ctx, writeTempFile(t, []byte("bin2")), "keys/foo.txt/two.bin", true); err != nil {
		t.Fatalf("Import two.bin: %v", err)
	}
	// Nested binary under a different parent segment must not appear.
	if err := st.Import(ctx, writeTempFile(t, []byte("bin3")), "keys/foo.txt/sub/three.bin", true); err != nil {
		t.Fatalf("Import nested: %v", err)
	}
	// Text child must not appear.
	if err := st.Add(ctx, "keys/foo.txt/readme.md", "child text"); err != nil {
		t.Fatalf("Add text child: %v", err)
	}

	names, err := st.ListAttachments(ctx, "keys/foo.txt")
	if err != nil {
		t.Fatalf("ListAttachments: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("ListAttachments = %v; want [one.bin two.bin]", names)
	}
	if names[0] != "one.bin" || names[1] != "two.bin" {
		t.Errorf("ListAttachments = %v; want sorted [one.bin two.bin]", names)
	}
}

func TestListAttachments_geheim_missingParent(t *testing.T) {
	ctx, st, _, _, _ := testSetup(t)

	names, err := st.ListAttachments(ctx, "keys/missing")
	if err != nil {
		t.Fatalf("ListAttachments: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("ListAttachments = %v; want empty slice", names)
	}
}

func TestListAttachments_geheim_emptyParent(t *testing.T) {
	ctx, st, _, _, _ := testSetup(t)

	if _, err := st.ListAttachments(ctx, ""); err == nil {
		t.Fatal("expected error for empty parent")
	}
}

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	path := t.TempDir() + "/attach.bin"
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestIsBinaryDescription_suffixOnly(t *testing.T) {
	if !isBinaryDescription("quicklog-release.jks") {
		t.Error("expected .jks suffix to be binary")
	}
	if isBinaryDescription("notes.txt") {
		t.Error("expected .txt suffix to be text")
	}
}
