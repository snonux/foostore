package cli

import (
	"testing"

	"codeberg.org/snonux/foostore/internal/keepass"
)

func TestSplitDescriptionPath(t *testing.T) {
	group, title, err := keepass.SplitDescriptionPath("foo/bar/baz")
	if err != nil {
		t.Fatalf("SplitDescriptionPath: %v", err)
	}
	if title != "baz" {
		t.Fatalf("title = %q; want baz", title)
	}
	if len(group) != 2 || group[0] != "foo" || group[1] != "bar" {
		t.Fatalf("group path = %v; want [foo bar]", group)
	}
}

func TestSanitizeRelativePathRejectsTraversal(t *testing.T) {
	if _, err := keepass.SanitizeRelativePath("../secret"); err == nil {
		t.Fatal("SanitizeRelativePath should reject traversal path")
	}
}

func TestExtractPasswordFromContent(t *testing.T) {
	password, notes := extractPasswordFromContent("user: alice\npassword: s3cr3t\nurl: example.com\n")
	if password != "s3cr3t" {
		t.Fatalf("password = %q; want s3cr3t", password)
	}
	if notes != "user: alice\nurl: example.com" {
		t.Fatalf("notes = %q; want without password line", notes)
	}
}
