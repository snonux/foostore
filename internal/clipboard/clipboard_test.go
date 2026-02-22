package clipboard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---- extract ---------------------------------------------------------------

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

// TestExtract_multiple_separate_tokens verifies that matchRe picks the first
// token and censorRe replaces all tokens when multiple user:pass pairs exist.
func TestExtract_multiple_separate_tokens(t *testing.T) {
	user, password, censored, err := extract("a:1 b:2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "a" {
		t.Errorf("user: got %q, want %q", user, "a")
	}
	if password != "1" {
		t.Errorf("password: got %q, want %q", password, "1")
	}
	// Both tokens must be censored.
	if censored != "a:CENSORED b:CENSORED" {
		t.Errorf("censored: got %q, want %q", censored, "a:CENSORED b:CENSORED")
	}
}

// TestExtract_multiple_colons verifies the greedy behaviour of \S+:\S+ when
// there are multiple colons in a single whitespace-delimited token.
//
// With input "user:pass:extra", the regex (\S+):(\S+) is greedy on both sides.
// The engine backtracks to find the last colon that still satisfies the pattern,
// so group 1 = "user:pass" and group 2 = "extra".  This matches Ruby's behaviour.
func TestExtract_multiple_colons(t *testing.T) {
	user, password, censored, err := extract("user:pass:extra")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user:pass" {
		t.Errorf("user: got %q, want %q", user, "user:pass")
	}
	if password != "extra" {
		t.Errorf("password: got %q, want %q", password, "extra")
	}
	if censored != "user:pass:CENSORED" {
		t.Errorf("censored: got %q, want %q", censored, "user:pass:CENSORED")
	}
}

// TestExtract_trailing_colon verifies that a trailing colon with no password
// (e.g. "user:") does not match because \S+ requires at least one character.
func TestExtract_trailing_colon(t *testing.T) {
	_, _, _, err := extract("user:")
	if err == nil {
		t.Fatal("expected error for 'user:' (empty password), got nil")
	}
}

// TestExtract_leading_colon verifies that a leading colon (empty user) does
// not match because \S+ before the colon requires at least one character.
func TestExtract_leading_colon(t *testing.T) {
	_, _, _, err := extract(":pass")
	if err == nil {
		t.Fatal("expected error for ':pass' (empty user), got nil")
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

// TestExtract_whitespace_only verifies that whitespace-only input returns an error.
func TestExtract_whitespace_only(t *testing.T) {
	_, _, _, err := extract("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only input, got nil")
	}
}

// ---- New -------------------------------------------------------------------

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
	t.Setenv("UNAME", "")
	c := New("gpaste-client", "pbcopy")
	if c.cmd != "gpaste-client" {
		t.Errorf("cmd: got %q, want %q", c.cmd, "gpaste-client")
	}
}

// ---- Paste -----------------------------------------------------------------

// TestPaste_empty_cmd verifies that Paste returns an error when no command is configured.
func TestPaste_empty_cmd(t *testing.T) {
	c := &Clipboard{cmd: ""}
	err := c.Paste(context.Background(), "user:pass")
	if err == nil {
		t.Fatal("expected error for empty cmd, got nil")
	}
}

// TestPaste_password_reaches_stdin verifies that only the password — not the
// full data string — is written to the clipboard command's stdin.
// A shell script captures stdin to a temp file so we can assert its content.
func TestPaste_password_reaches_stdin(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "clipboard.txt")
	script := filepath.Join(t.TempDir(), "capture.sh")
	scriptContent := "#!/bin/sh\ncat > " + outFile + "\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o755); err != nil {
		t.Fatalf("WriteFile script: %v", err)
	}

	c := &Clipboard{cmd: script}
	if err := c.Paste(context.Background(), "user:s3cr3t"); err != nil {
		t.Fatalf("Paste: %v", err)
	}

	// The clipboard command runs in a detached goroutine. Poll for the output
	// file with a short sleep between attempts — in practice the shell script
	// exits within a few milliseconds.
	for range 100 {
		if _, err := os.Stat(outFile); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Errorf("clipboard content: got %q, want %q", string(got), "s3cr3t")
	}
}

// TestPaste_bad_command verifies that Paste returns an error when the clipboard
// command does not exist.
func TestPaste_bad_command(t *testing.T) {
	c := &Clipboard{cmd: "/nonexistent/command"}
	err := c.Paste(context.Background(), "user:pass")
	if err == nil {
		t.Fatal("expected error for nonexistent command, got nil")
	}
}
