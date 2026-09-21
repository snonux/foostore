//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
)

// buildBinary compiles the foostore command once per test into a temp dir so
// the tests exercise the real main(), including its argument short-circuits.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "foostore")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// writeFixtureDB writes a synthetic KeePass database (password "testpass")
// with one entry Machine/token whose Password is "s3cret-value".
func writeFixtureDB(t *testing.T) string {
	t.Helper()
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	machine := gokeepasslib.NewGroup()
	machine.Name = "Machine"
	e := gokeepasslib.NewEntry()
	e.Values = append(e.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "token"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "s3cret-value"}})
	machine.Entries = append(machine.Entries, e)
	root.Groups = append(root.Groups, machine)
	db.Content.Root.Groups = []gokeepasslib.Group{root}

	path := filepath.Join(t.TempDir(), "fixture.kdbx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	return path
}

// runBinary runs bin with args in a scrubbed environment (fresh HOME, no PIN)
// plus env, stdin closed, and optionally the passphrase on inherited fd 3. It
// returns the exit code, stdout and stderr.
func runBinary(t *testing.T, bin string, env []string, passphrase string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append([]string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if passphrase != "" {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString(passphrase + "\n"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		defer func() { _ = r.Close() }()
		cmd.ExtraFiles = []*os.File{r} // becomes fd 3 in the child
	}

	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running %s: %v", bin, err)
	}
	return code, stdout.String(), stderr.String()
}

// TestMainMachineReadShortCircuit pins that main() routes every spelling of a
// read invocation to the machine-facing command before any interactive
// initialisation — including global and read flags placed before the command
// word, and with FOOSTORE_SHELL set — so exit codes stay the documented ones
// and nothing prompts.
func TestMainMachineReadShortCircuit(t *testing.T) {
	bin := buildBinary(t)
	db := writeFixtureDB(t)
	fd := []string{"FOOSTORE_READ_PASSPHRASE_FD=3", "FOOSTORE_SHELL=1"}

	t.Run("flag-first invocation returns the exact secret", func(t *testing.T) {
		code, out, stderr := runBinary(t, bin, fd, "testpass",
			"--kdbx-path", db, "read", "--field", "Password", "Machine/token")
		if code != 0 || out != "s3cret-value" {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q; want 0 and exactly the secret", code, out, stderr)
		}
	})

	t.Run("plain invocation returns the exact secret", func(t *testing.T) {
		code, out, stderr := runBinary(t, bin, fd, "testpass",
			"read", "--kdbx-path", db, "--field", "Password", "Machine/token")
		if code != 0 || out != "s3cret-value" {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})

	t.Run("mis-ordered read flag before the command word does not reach interactive init", func(t *testing.T) {
		// No credential source: the interactive path would prompt or FATAL
		// with exit 3; the machine path must report locked (6).
		code, out, stderr := runBinary(t, bin, []string{"FOOSTORE_SHELL=1"}, "",
			"--field", "Password", "--kdbx-path", db, "read", "Machine/token")
		if code != 6 || out != "" {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q; want 6 (locked) and no output", code, out, stderr)
		}
		if strings.Contains(stderr, "FATAL") {
			t.Fatalf("stderr %q shows the interactive initialisation ran", stderr)
		}
	})

	t.Run("wrong passphrase exits locked", func(t *testing.T) {
		code, out, _ := runBinary(t, bin, fd, "not-the-passphrase",
			"--kdbx-path", db, "read", "--field", "Password", "Machine/token")
		if code != 6 || out != "" {
			t.Fatalf("exit = %d, stdout = %q; want 6 and no output", code, out)
		}
	})

	t.Run("missing entry exits 4", func(t *testing.T) {
		code, out, _ := runBinary(t, bin, fd, "testpass",
			"--kdbx-path", db, "read", "--field", "Password", "Machine/absent")
		if code != 4 || out != "" {
			t.Fatalf("exit = %d, stdout = %q; want 4 and no output", code, out)
		}
	})

	t.Run("usage error exits 2", func(t *testing.T) {
		code, out, _ := runBinary(t, bin, fd, "testpass", "--kdbx-path", db, "read")
		if code != 2 || out != "" {
			t.Fatalf("exit = %d, stdout = %q; want 2 and no output", code, out)
		}
	})

	for _, args := range [][]string{
		{"--kdbx-path", "read", "--field", "Password", "Machine/token"},
		{"--field", "read", "Machine/token"},
		{"--timeout", "read", "Machine/token"},
		{"--backend", "read", "Machine/token"},
	} {
		t.Run("command word swallowed by an unset variable is a usage error: "+strings.Join(args, " "), func(t *testing.T) {
			code, out, stderr := runBinary(t, bin, []string{"FOOSTORE_SHELL=1"}, "", args...)
			if code != 2 || out != "" || strings.Contains(stderr, "FATAL") {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q; want 2, no output, no interactive init", code, out, stderr)
			}
		})
	}

	t.Run("empty --kdbx-path is a usage error, not the default store", func(t *testing.T) {
		code, out, _ := runBinary(t, bin, fd, "testpass",
			"--kdbx-path", "", "read", "--field", "Password", "Machine/token")
		if code != 2 || out != "" {
			t.Fatalf("exit = %d, stdout = %q; want 2 and no output", code, out)
		}
	})
}

// TestMainClosedStdoutIsAnIOFailure pins that a consumer closing its end of
// stdout early gets the documented I/O exit code (8) rather than the process
// dying of SIGPIPE.
func TestMainClosedStdoutIsAnIOFailure(t *testing.T) {
	bin := buildBinary(t)
	db := writeFixtureDB(t)
	fd := []string{"FOOSTORE_READ_PASSPHRASE_FD=3", "FOOSTORE_SHELL=1"}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close() // nobody will ever read the secret
	defer func() { _ = w.Close() }()

	cmd := exec.Command(bin, "--kdbx-path", db, "read", "--field", "Password", "Machine/token")
	cmd.Env = append([]string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}, fd...)
	cmd.Stdout = w
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.WriteString("testpass\n"); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	defer func() { _ = pr.Close() }()
	cmd.ExtraFiles = []*os.File{pr}

	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 8 {
		t.Fatalf("err = %v; want exit code 8 (an ordinary I/O failure, not death by SIGPIPE)", err)
	}
}
