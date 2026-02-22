// Package shell_test exercises the public API of the shell package.
// Because Shell requires a real TTY for readline to initialise, tests that
// construct a Shell instance are skipped automatically when running in a
// non-interactive environment (e.g. CI pipelines).
package shell_test

import (
	"os"
	"testing"

	"codeberg.org/snonux/foostore/internal/shell"
)

// isTTY returns true when stdin is connected to an actual terminal.
// readline.NewFromConfig will still succeed without a TTY (it falls back to
// non-interactive mode), so we do not need to skip on that basis alone.
func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// TestNew verifies that New returns a non-nil Shell without an error when
// given a valid (no-op) completion function.
// The test is skipped when stdin is not a TTY, because readline may behave
// differently and the intent is to test real interactive initialisation.
func TestNew(t *testing.T) {
	if !isTTY() {
		t.Skip("skipping TestNew: stdin is not a TTY")
	}

	completionFn := func(prefix string) []string {
		// Return a fixed set of candidates for testing purposes.
		all := []string{"add", "get", "list", "delete"}
		var matches []string
		for _, c := range all {
			if len(c) >= len(prefix) && c[:len(prefix)] == prefix {
				matches = append(matches, c)
			}
		}
		return matches
	}

	s, err := shell.New(completionFn)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("New() returned nil Shell")
	}

	// Close must not panic or return an error.
	s.Close()
}

// TestNewNonTTY verifies that New does not panic and either succeeds or
// returns a meaningful error when stdin is not a terminal.
func TestNewNonTTY(t *testing.T) {
	if isTTY() {
		t.Skip("skipping TestNewNonTTY: stdin is a TTY, need non-TTY environment")
	}

	completionFn := func(prefix string) []string { return nil }

	// We accept either success or failure here — the important thing is no panic.
	s, err := shell.New(completionFn)
	if err != nil {
		// Non-TTY environments may legitimately fail; that is acceptable.
		t.Logf("New() returned error in non-TTY environment (expected): %v", err)
		return
	}
	if s == nil {
		t.Fatal("New() returned nil Shell without an error")
	}
	s.Close()
}
