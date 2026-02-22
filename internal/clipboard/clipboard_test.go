package clipboard

import (
	"context"
	"os"
	"testing"
)

// TestExtract_basic verifies the simplest possible "user:pass" input.
func TestExtract_basic(t *testing.T) {
	user, password, censored, err := extract("user:pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" {
		t.Errorf("user: got %q, want %q", user, "user")
	}
	if password != "pass" {
		t.Errorf("password: got %q, want %q", password, "pass")
	}
	if censored != "user:CENSORED" {
		t.Errorf("censored: got %q, want %q", censored, "user:CENSORED")
	}
}

// TestExtract_with_other_text verifies that surrounding text is preserved and
// only the secret portion is replaced.
func TestExtract_with_other_text(t *testing.T) {
	user, password, censored, err := extract("login user:secret123 notes")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" {
		t.Errorf("user: got %q, want %q", user, "user")
	}
	if password != "secret123" {
		t.Errorf("password: got %q, want %q", password, "secret123")
	}
	if censored != "login user:CENSORED notes" {
		t.Errorf("censored: got %q, want %q", censored, "login user:CENSORED notes")
	}
}

// TestExtract_multiple_colons verifies the greedy behaviour of \S+:\S+ when
// there are multiple colons in a single whitespace-delimited token.
//
// With input "user:pass:extra", the regex (\S+):(\S+) is greedy on both sides.
// Because \S+ before the colon can match anything that is not whitespace, the
// engine backtracks to find the last colon that still satisfies the pattern,
// so group 1 = "user:pass" and group 2 = "extra". The entire whitespace token
// is replaced with one "user:pass:CENSORED" in the censored output, which
// matches the Ruby gsub behaviour (one replacement per token).
func TestExtract_multiple_colons(t *testing.T) {
	user, password, censored, err := extract("user:pass:extra")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// \S+ before the colon is greedy: it consumes "user:pass", leaving "extra".
	if user != "user:pass" {
		t.Errorf("user: got %q, want %q", user, "user:pass")
	}
	if password != "extra" {
		t.Errorf("password: got %q, want %q", password, "extra")
	}
	// The entire token is one \S+ run so the replacement is applied once.
	if censored != "user:pass:CENSORED" {
		t.Errorf("censored: got %q, want %q", censored, "user:pass:CENSORED")
	}
}

// TestExtract_no_match verifies that an error is returned when no colon token exists.
func TestExtract_no_match(t *testing.T) {
	_, _, _, err := extract("no colon here")
	if err == nil {
		t.Fatal("expected error for input without colon, got nil")
	}
}

// TestExtract_empty verifies that an empty string returns an error.
func TestExtract_empty(t *testing.T) {
	_, _, _, err := extract("")
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

// TestNew_darwin verifies that New returns the macOS command when UNAME=Darwin.
func TestNew_darwin(t *testing.T) {
	t.Setenv("UNAME", "Darwin")
	c := New("gpaste-client", "pbcopy")
	if c.cmd != "pbcopy" {
		t.Errorf("cmd: got %q, want %q", c.cmd, "pbcopy")
	}
}

// TestNew_linux verifies that New returns the gnome command when UNAME is unset.
func TestNew_linux(t *testing.T) {
	os.Unsetenv("UNAME")
	c := New("gpaste-client", "pbcopy")
	if c.cmd != "gpaste-client" {
		t.Errorf("cmd: got %q, want %q", c.cmd, "gpaste-client")
	}
}

// TestPaste_empty_cmd verifies that Paste returns an error when no command is configured.
func TestPaste_empty_cmd(t *testing.T) {
	c := &Clipboard{cmd: ""}
	err := c.Paste(context.Background(), "user:pass")
	if err == nil {
		t.Fatal("expected error for empty cmd, got nil")
	}
}

// TestPaste_with_cat uses "cat" as a stand-in clipboard command to verify that
// Paste runs end-to-end without error on the current platform.
// "cat" reads stdin and exits 0, which is sufficient to exercise the full
// Paste flow without requiring an actual clipboard daemon.
func TestPaste_with_cat(t *testing.T) {
	c := &Clipboard{cmd: "cat"}
	err := c.Paste(context.Background(), "user:pass")
	if err != nil {
		t.Fatalf("Paste with 'cat' command failed: %v", err)
	}
}
