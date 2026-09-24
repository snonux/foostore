//go:build unix

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"

	"github.com/snonux/foostore/internal/config"
)

// Secret material used by the fixtures. Every failing read is checked against
// these: stdout must stay empty and stderr must never contain them.
const (
	readTestPassphrase = "testpass"
	readTestSecret     = "s3cret-value"
)

// setField sets key=value on a test entry without importing keepass.
func setField(e *gokeepasslib.Entry, key, value string) {
	for i := range e.Values {
		if e.Values[i].Key == key {
			e.Values[i].Value.Content = value
			return
		}
	}
	e.Values = append(e.Values, gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}})
}

// createReadCLITestDB writes a small KeePass database for read tests, unlocked
// with the password "testpass": one text entry Machine/token (Password
// "s3cret-value") and one attachment Machine/blob/blob.bin containing NUL
// bytes and a trailing newline.
func createReadCLITestDB(t *testing.T) string {
	t.Helper()
	return createReadCLITestDBWith(t, gokeepasslib.NewPasswordCredentials(readTestPassphrase))
}

// createReadCLITestDBWith is createReadCLITestDB with caller-chosen credentials
// (for example password plus key file).
func createReadCLITestDBWith(t *testing.T, creds *gokeepasslib.DBCredentials) string {
	t.Helper()

	db := gokeepasslib.NewDatabase()
	db.Credentials = creds

	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	machine := gokeepasslib.NewGroup()
	machine.Name = "Machine"

	token := gokeepasslib.NewEntry()
	setField(&token, "Title", "token")
	setField(&token, "Password", readTestSecret)
	machine.Entries = append(machine.Entries, token)

	blob := gokeepasslib.NewEntry()
	setField(&blob, "Title", "blob")
	bin := db.AddBinary([]byte("BIN\x00DATA\n"))
	blob.Binaries = append(blob.Binaries, bin.CreateReference("blob.bin"))
	machine.Entries = append(machine.Entries, blob)

	root.Groups = append(root.Groups, machine)
	db.Content.Root.Groups = []gokeepasslib.Group{root}

	tmp, err := os.CreateTemp(t.TempDir(), "cli-read-*.kdbx")
	if err != nil {
		t.Fatalf("creating temp kdbx: %v", err)
	}
	defer func() { _ = tmp.Close() }()
	if err := gokeepasslib.NewEncoder(tmp).Encode(db); err != nil {
		t.Fatalf("encoding test db: %v", err)
	}
	return tmp.Name()
}

// createDashNamedEntriesDB writes entries and attachments whose identities are
// literally "-h" / "--help", so machine read can exercise -- + success path.
func createDashNamedEntriesDB(t *testing.T) string {
	t.Helper()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(readTestPassphrase)

	root := gokeepasslib.NewGroup()
	root.Name = "Root"

	// Titles directly under the top-level group yield identities "-h" / "--help".
	for _, e := range []struct {
		title, password string
	}{
		{"-h", "secret-for-dash-h"},
		{"--help", "secret-for-dash-help"},
	} {
		entry := gokeepasslib.NewEntry()
		setField(&entry, "Title", e.title)
		setField(&entry, "Password", e.password)
		root.Entries = append(root.Entries, entry)
	}

	dash := gokeepasslib.NewGroup()
	dash.Name = "Dash"
	parent := gokeepasslib.NewEntry()
	setField(&parent, "Title", "parent")
	setField(&parent, "Password", "unused")
	binH := db.AddBinary([]byte("attach-dash-h\x00\n"))
	binHelp := db.AddBinary([]byte("attach-dash-help\n"))
	parent.Binaries = append(parent.Binaries,
		binH.CreateReference("-h"),
		binHelp.CreateReference("--help"),
	)
	dash.Entries = append(dash.Entries, parent)
	root.Groups = append(root.Groups, dash)
	db.Content.Root.Groups = []gokeepasslib.Group{root}

	tmp, err := os.CreateTemp(t.TempDir(), "cli-read-dash-*.kdbx")
	if err != nil {
		t.Fatalf("creating temp kdbx: %v", err)
	}
	defer func() { _ = tmp.Close() }()
	if err := gokeepasslib.NewEncoder(tmp).Encode(db); err != nil {
		t.Fatalf("encoding dash-named test db: %v", err)
	}
	return tmp.Name()
}

// createDuplicateTitleDB writes a database whose two entries share one
// identity, so an exact read must report it as ambiguous.
func createDuplicateTitleDB(t *testing.T) string {
	t.Helper()
	dup := gokeepasslib.NewDatabase()
	dup.Credentials = gokeepasslib.NewPasswordCredentials(readTestPassphrase)
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	dupes := gokeepasslib.NewGroup()
	dupes.Name = "Dupes"
	for i := 0; i < 2; i++ {
		e := gokeepasslib.NewEntry()
		setField(&e, "Title", "dupe")
		setField(&e, "Password", readTestSecret)
		dupes.Entries = append(dupes.Entries, e)
	}
	root.Groups = append(root.Groups, dupes)
	dup.Content.Root.Groups = []gokeepasslib.Group{root}
	path := filepath.Join(t.TempDir(), "dupes.kdbx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := gokeepasslib.NewEncoder(f).Encode(dup); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeReadConfig writes ~/.config/foostore.json under home verbatim.
func writeReadConfig(t *testing.T, home, content string) {
	t.Helper()
	dir := filepath.Join(home, ".config")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "foostore.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// setupReadHome prepares home as an operator would: when pass is non-empty an
// owner-only passphrase file is written and named by kdbx_pass_file, and every
// extra key/value lands in the config file too (for example kdbx_key_file).
func setupReadHome(t *testing.T, home, pass string, extra map[string]string) {
	t.Helper()
	cfg := map[string]string{}
	for k, v := range extra {
		cfg[k] = v
	}
	if pass != "" {
		passFile := filepath.Join(home, "kdbx.pass")
		if err := os.WriteFile(passFile, []byte(pass+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg["kdbx_pass_file"] = passFile
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeReadConfig(t, home, string(data))
}

// newReadHome returns a fresh HOME set up by setupReadHome.
func newReadHome(t *testing.T, pass string, extra map[string]string) string {
	t.Helper()
	home := t.TempDir()
	setupReadHome(t, home, pass, extra)
	return home
}

// runReadMachine runs readCommand in a fresh HOME whose passphrase file holds
// pass (empty pass configures no credential source). See runReadIn.
func runReadMachine(t *testing.T, pass string, argv []string) (int, string, string) {
	t.Helper()
	return runReadIn(t, newReadHome(t, pass, nil), nil, argv)
}

// runReadMachineEnv is runReadMachine plus extra environment variables.
func runReadMachineEnv(t *testing.T, pass string, env map[string]string, argv []string) (int, string, string) {
	t.Helper()
	return runReadIn(t, newReadHome(t, pass, nil), env, argv)
}

// runReadIn executes readCommand with the given HOME, a swapped stderr, and the
// supplied environment on top of a scrubbed credential environment (no ambient
// PIN or passphrase descriptor, so a stray $PIN can never make a case pass). It returns the exit code, the exact stdout
// bytes and the captured stderr.
//
// It also enforces the contract invariants shared by every case: a failing
// read leaves stdout empty, and no diagnostic ever contains the passphrase or
// the stored secret.
func runReadIn(t *testing.T, home string, env map[string]string, argv []string) (int, string, string) {
	t.Helper()

	t.Setenv("HOME", home)
	unsetenv(t, "PIN")
	unsetenv(t, passphraseFDEnv)
	for k, v := range env {
		t.Setenv(k, v)
	}

	var stdout bytes.Buffer
	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-*.txt")
	if err != nil {
		t.Fatalf("creating stderr capture: %v", err)
	}
	defer func() { _ = stderrFile.Close() }()
	oldStderr := os.Stderr
	os.Stderr = stderrFile
	defer func() { os.Stderr = oldStderr }()

	code := readCommand(context.Background(), argv, &stdout)

	if _, err := stderrFile.Seek(0, 0); err != nil {
		t.Fatalf("rewinding stderr capture: %v", err)
	}
	stderrData, err := io.ReadAll(stderrFile)
	if err != nil {
		t.Fatalf("reading stderr capture: %v", err)
	}
	stderr := string(stderrData)

	if code != 0 && stdout.Len() != 0 {
		t.Errorf("failing read (exit %d) wrote %q to stdout; stdout must stay empty", code, stdout.String())
	}
	for _, secret := range []string{readTestPassphrase, readTestSecret} {
		if strings.Contains(stderr, secret) {
			t.Errorf("stderr %q leaks secret material %q", stderr, secret)
		}
	}
	return code, stdout.String(), stderr
}

// unsetenv removes key for the duration of the test (restored afterwards).
// Setting it to "" is not the same: the read command treats an exported empty
// descriptor variable as a mistake.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "") // registers the restore of the original value
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}

// passphraseFD returns a descriptor number carrying content, as an operator
// would inherit one. The descriptor is a dup of a pipe's read end: the code
// under test consumes and closes it, so the test must not touch that number
// again. With closeWriter false the writer stays open (and silent) until test
// cleanup, modelling a stalled producer.
func passphraseFD(t *testing.T, content string, closeWriter bool) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if content != "" {
		if _, err := w.WriteString(content); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if closeWriter {
		_ = w.Close()
	} else {
		// Closing the writer at cleanup unblocks the abandoned reader so it
		// closes its dup instead of lingering.
		t.Cleanup(func() { _ = w.Close() })
	}
	return fd
}

func TestParseReadFlags(t *testing.T) {
	tests := []struct {
		name      string
		argv      []string
		wantErr   bool
		wantRef   string
		wantField string
	}{
		{name: "bare reference", argv: []string{"Machine/token"}, wantRef: "Machine/token"},
		{name: "field selection", argv: []string{"--field", "Password", "Machine/token"}, wantRef: "Machine/token", wantField: "Password"},
		{name: "self-documenting no-op flags", argv: []string{"--exact", "--raw", "--non-interactive", "Machine/token"}, wantRef: "Machine/token"},
		{name: "global flags interleave", argv: []string{"--backend", "keepass", "Machine/token", "--kdbx-path", "/tmp/x.kdbx"}, wantRef: "Machine/token"},
		{name: "terminator addresses a reference that starts with a dash", argv: []string{"--", "-odd/title"}, wantRef: "-odd/title"},
		{name: "flags before the terminator still apply", argv: []string{"--field", "Password", "--", "-odd"}, wantRef: "-odd", wantField: "Password"},
		{name: "missing reference", argv: []string{}, wantErr: true},
		{name: "two references", argv: []string{"a", "b"}, wantErr: true},
		{name: "two references after the terminator", argv: []string{"--", "a", "b"}, wantErr: true},
		{name: "unknown flag", argv: []string{"--wat", "a"}, wantErr: true},
		{name: "dash-prefixed reference without terminator", argv: []string{"-odd"}, wantErr: true},
		{name: "equals-form flags are rejected", argv: []string{"--field=Password", "Machine/token"}, wantErr: true},
		{name: "dangling value flag", argv: []string{"--field"}, wantErr: true},
		{name: "repeated --field", argv: []string{"--field", "A", "--field", "B", "x"}, wantErr: true},
		{name: "repeated --kdbx-path", argv: []string{"--kdbx-path", "a", "--kdbx-path", "b", "x"}, wantErr: true},
		{name: "invalid timeout", argv: []string{"--timeout", "soon", "a"}, wantErr: true},
		{name: "non-positive timeout", argv: []string{"--timeout", "0s", "a"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseReadFlags(tc.argv)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseReadFlags(%v) succeeded, want error", tc.argv)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseReadFlags(%v): %v", tc.argv, err)
			}
			if opts.reference != tc.wantRef || opts.field != tc.wantField {
				t.Fatalf("opts = %+v, want reference %q field %q", opts, tc.wantRef, tc.wantField)
			}
		})
	}
}

func TestMachineReadArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []string
		wantOK  bool
		wantErr bool
	}{
		{name: "plain read", args: []string{"read", "--field", "Password", "a/b"}, want: []string{"--field", "Password", "a/b"}, wantOK: true},
		{name: "global flags before the command keep their order", args: []string{"--kdbx-path", "/x.kdbx", "--backend", "keepass", "read", "--field", "Password", "a/b"}, want: []string{"--kdbx-path", "/x.kdbx", "--backend", "keepass", "--field", "Password", "a/b"}, wantOK: true},
		{name: "read's own flag before the command word is still a read", args: []string{"--field", "Password", "read", "a/b"}, want: []string{"--field", "Password", "a/b"}, wantOK: true},
		{name: "timeout before the command word", args: []string{"--timeout", "5s", "read", "a/b"}, want: []string{"--timeout", "5s", "a/b"}, wantOK: true},
		{name: "empty flag value is preserved for parseReadFlags to reject", args: []string{"--kdbx-path", "", "read", "a/b"}, want: []string{"--kdbx-path", "", "a/b"}, wantOK: true},
		{name: "value-less flag before the command word", args: []string{"--exact", "read", "a/b"}, want: []string{"--exact", "a/b"}, wantOK: true},
		{name: "a reference that is spelled like an interactive command stays a reference", args: []string{"--field", "Password", "read", "ls"}, want: []string{"--field", "Password", "ls"}, wantOK: true},
		{name: "explicit command word makes a flag value spelled read unambiguous", args: []string{"read", "--field", "read", "a/b"}, want: []string{"--field", "read", "a/b"}, wantOK: true},

		// An unset, unquoted shell variable swallows the command word.
		{name: "unset variable swallowed the command word after --kdbx-path", args: []string{"--kdbx-path", "read", "--field", "Password", "X"}, wantOK: true, wantErr: true},
		{name: "unset variable swallowed the command word after --backend", args: []string{"--backend", "read", "X"}, wantOK: true, wantErr: true},
		{name: "unset variable swallowed the command word after --field", args: []string{"--field", "read", "Vault/x"}, wantOK: true, wantErr: true},
		{name: "unset variable swallowed the command word after --timeout", args: []string{"--timeout", "read", "Vault/x"}, wantOK: true, wantErr: true},

		// A read-only flag without any command word is inferred as a read.
		{name: "--exact without a command word", args: []string{"--exact", "Vault/x"}, want: []string{"--exact", "Vault/x"}, wantOK: true},
		{name: "--raw without a command word", args: []string{"--raw", "Vault/x"}, want: []string{"--raw", "Vault/x"}, wantOK: true},
		{name: "--non-interactive without a command word", args: []string{"--non-interactive", "Vault/x"}, want: []string{"--non-interactive", "Vault/x"}, wantOK: true},
		{name: "--field without a command word", args: []string{"--field", "Password", "Vault/x"}, want: []string{"--field", "Password", "Vault/x"}, wantOK: true},
		{name: "--timeout without a command word", args: []string{"--timeout", "5s", "Vault/x"}, want: []string{"--timeout", "5s", "Vault/x"}, wantOK: true},

		{name: "--field=value without a command word", args: []string{"--field=Password", "Vault/x"}, want: []string{"--field=Password", "Vault/x"}, wantOK: true},
		{name: "--timeout=value without a command word", args: []string{"--timeout=5s", "Vault/x"}, want: []string{"--timeout=5s", "Vault/x"}, wantOK: true},

		// Ordinary interactive usage must be left alone.
		{name: "ls", args: []string{"ls"}, wantOK: false},
		{name: "a search for the term read", args: []string{"search", "read"}, wantOK: false},
		{name: "cat of an entry called read", args: []string{"cat", "read"}, wantOK: false},
		{name: "bare search term that merely starts with read", args: []string{"read-only-notes"}, wantOK: false},
		{name: "global flags then a search for read", args: []string{"--kdbx-path", "/x.kdbx", "search", "read"}, wantOK: false},
		{name: "backend then another command", args: []string{"--backend", "keepass", "ls"}, wantOK: false},
		{name: "backend then shell", args: []string{"--backend", "keepass", "shell"}, wantOK: false},
		{name: "kdbx path then cat", args: []string{"--kdbx-path", "/x.kdbx", "cat", "foo"}, wantOK: false},
		{name: "no arguments", args: nil, wantOK: false},
		{name: "only global flags", args: []string{"--backend", "keepass"}, wantOK: false},
		{name: "dangling value flag", args: []string{"--backend"}, wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := MachineReadArgs(tc.args)
			if ok != tc.wantOK || (err != nil) != tc.wantErr {
				t.Fatalf("MachineReadArgs(%v) = %v, ok=%v, err=%v; want ok=%v err=%v", tc.args, got, ok, err, tc.wantOK, tc.wantErr)
			}
			if tc.wantOK && !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("MachineReadArgs(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestInteractiveReadDispatchIsNeverSuccess pins that the interactive
// dispatcher can never turn "read" into a silent success with empty output.
func TestInteractiveReadDispatchIsNeverSuccess(t *testing.T) {
	code, _, handled := (&CLI{}).dispatchSimple(context.Background(), []string{"read", "x"}, "read")
	if !handled {
		t.Fatal("the read command must be handled (not fall through to search)")
	}
	if code != readExitUsage {
		t.Fatalf("exit = %d, want %d (usage)", code, readExitUsage)
	}
}

func TestBuildBackendRejectsUnknownName(t *testing.T) {
	_, _, err := buildBackend(context.Background(), &config.Config{}, "keepass-typo")
	if err == nil {
		t.Fatal("an unknown backend name must fail instead of falling through to another store")
	}
	if !strings.Contains(err.Error(), "keepass-typo") {
		t.Fatalf("error %q should name the rejected backend", err)
	}
}

func TestReadHelp(t *testing.T) {
	// Gonf's contract probe is exactly `read --help`: exit 0, usagePrefix and
	// notFoundLine on stdout, empty stderr.
	code, stdout, stderr := runReadMachine(t, "", []string{"--help"})
	if code != 0 {
		t.Fatalf("--help exit = %d, want 0", code)
	}
	if stderr != "" {
		t.Fatalf("--help stderr = %q, want empty", stderr)
	}
	const usagePrefix = "usage: foostore read "
	if !strings.HasPrefix(stdout, usagePrefix) {
		t.Fatalf("--help stdout = %q, want prefix %q", stdout, usagePrefix)
	}
	const notFoundLine = "4 not found (the only suppressible code)"
	if !strings.Contains(stdout, notFoundLine) {
		t.Fatalf("--help stdout missing gonf probe marker %q", notFoundLine)
	}
}

func TestReadSoleShortHelpIsUsageError(t *testing.T) {
	// A bare -h is far likelier to be an accidental reference (REF=-h) than a
	// help request; it must not exit 0 with usage on stdout, and must not look
	// like a generic unknown-flag rejection.
	code, stdout, stderr := runReadMachine(t, "", []string{"-h"})
	if code != readExitUsage || stdout != "" || !strings.Contains(stderr, "usage:") {
		t.Fatalf("read -h = exit %d, stdout %q, stderr %q; want usage error with empty stdout", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "-h is not help") || !strings.Contains(stderr, "--help") {
		t.Fatalf("stderr %q should say -h is not help and point at --help", stderr)
	}
	if strings.Contains(stderr, `unknown flag "-h"`) {
		t.Fatalf("stderr %q must not use the generic unknown-flag path for sole -h", stderr)
	}
}

func TestReadHelpMixedWithArgumentsIsUsageError(t *testing.T) {
	cases := [][]string{
		{"--field", "Password", "-h"},
		{"--field", "Password", "Machine/token", "--help"},
		{"--help", "Machine/token"},
		{"-h", "--field", "Password"},
	}
	for _, argv := range cases {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			code, stdout, stderr := runReadMachine(t, "", argv)
			if code != readExitUsage || stdout != "" || !strings.Contains(stderr, "usage:") {
				t.Fatalf("read %q = exit %d, stdout %q, stderr %q; want usage error with empty stdout", argv, code, stdout, stderr)
			}
		})
	}
}

func TestReadHelpAfterTerminatorIsLiteralReference(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	for _, reference := range []string{"--help", "-h"} {
		t.Run("absent/"+reference, func(t *testing.T) {
			argv := []string{"--kdbx-path", dbPath, "--field", "Password", "--", reference}
			code, stdout, stderr := runReadMachine(t, readTestPassphrase, argv)
			if code != readExitNotFound || stdout != "" || strings.Contains(stderr, "usage:") {
				t.Fatalf("read %q = exit %d, stdout %q, stderr %q; want not-found for a literal reference", argv, code, stdout, stderr)
			}
		})
	}
}

func TestReadDashNamedLiteralAfterTerminatorSucceeds(t *testing.T) {
	dbPath := createDashNamedEntriesDB(t)
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{
			name: "entry titled -h",
			argv: []string{"--kdbx-path", dbPath, "--field", "Password", "--", "-h"},
			want: "secret-for-dash-h",
		},
		{
			name: "entry titled --help",
			argv: []string{"--kdbx-path", dbPath, "--field", "Password", "--", "--help"},
			want: "secret-for-dash-help",
		},
		{
			name: "attachment named -h",
			argv: []string{"--kdbx-path", dbPath, "--", "Dash/parent/-h"},
			want: "attach-dash-h\x00\n",
		},
		{
			name: "attachment named --help",
			argv: []string{"--kdbx-path", dbPath, "--", "Dash/parent/--help"},
			want: "attach-dash-help\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runReadMachine(t, readTestPassphrase, tc.argv)
			if code != 0 || stdout != tc.want || stderr != "" {
				t.Fatalf("read %q = exit %d, stdout %q, stderr %q; want 0, %q, empty stderr",
					tc.argv, code, stdout, stderr, tc.want)
			}
		})
	}
}

func TestReadWithoutArgumentsIsUsageError(t *testing.T) {
	old := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	os.Stderr = devNull
	defer func() { os.Stderr = old }()

	if code := Read(context.Background(), nil); code != readExitUsage {
		t.Fatalf("Read(nil) = %d, want %d (usage)", code, readExitUsage)
	}
}

func TestReadMachineSuccess(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	field := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("reads exact bytes via the passphrase file", func(t *testing.T) {
		code, out, _ := runReadMachine(t, readTestPassphrase, field)
		if code != 0 || out != readTestSecret {
			t.Fatalf("exit = %d, stdout = %q; want 0 and exactly %q", code, out, readTestSecret)
		}
	})

	t.Run("reads exact attachment bytes including NUL and trailing newline", func(t *testing.T) {
		code, out, _ := runReadMachine(t, readTestPassphrase,
			[]string{"--kdbx-path", dbPath, "Machine/blob/blob.bin"})
		if code != 0 || out != "BIN\x00DATA\n" {
			t.Fatalf("exit = %d, stdout = %q; want 0 and exactly BIN\\0DATA\\n", code, out)
		}
	})

	t.Run("reads via inherited passphrase file descriptor", func(t *testing.T) {
		fd := passphraseFD(t, readTestPassphrase+"\n", true)
		code, out, _ := runReadMachineEnv(t, "", map[string]string{passphraseFDEnv: strconv.Itoa(fd)}, field)
		if code != 0 || out != readTestSecret {
			t.Fatalf("exit = %d, stdout = %q; want 0 and exactly %q", code, out, readTestSecret)
		}
	})

	t.Run("strips a CRLF terminator from the descriptor passphrase", func(t *testing.T) {
		fd := passphraseFD(t, readTestPassphrase+"\r\n", true)
		code, out, _ := runReadMachineEnv(t, "", map[string]string{passphraseFDEnv: strconv.Itoa(fd)}, field)
		if code != 0 || out != readTestSecret {
			t.Fatalf("exit = %d, stdout = %q; want 0 and exactly %q", code, out, readTestSecret)
		}
	})

}

// TestReadMachineCredentialPriority pins the source order and the absence of
// silent fallbacks between sources.
func TestReadMachineCredentialPriority(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	field := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("descriptor wins over a wrong passphrase file", func(t *testing.T) {
		fd := passphraseFD(t, readTestPassphrase, true)
		code, out, _ := runReadMachineEnv(t, "wrong",
			map[string]string{passphraseFDEnv: strconv.Itoa(fd)}, field)
		if code != 0 || out != readTestSecret {
			t.Fatalf("exit = %d, stdout = %q; want the descriptor to take priority", code, out)
		}
	})

	t.Run("a wrong descriptor passphrase is not rescued by a correct passphrase file", func(t *testing.T) {
		fd := passphraseFD(t, "wrong", true)
		code, _, _ := runReadMachineEnv(t, readTestPassphrase,
			map[string]string{passphraseFDEnv: strconv.Itoa(fd)}, field)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked): no silent fallback past a chosen source", code, readExitLocked)
		}
	})

	// Owner-only modes (0600 and the stricter 0400) are accepted for the
	// passfile.
	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Run("reads via owner-only passfile "+mode.String(), func(t *testing.T) {
			home := t.TempDir()
			passFile := filepath.Join(home, "kdbx.pass")
			if err := os.WriteFile(passFile, []byte(readTestPassphrase+"\n"), mode); err != nil {
				t.Fatal(err)
			}
			writeReadConfig(t, home, `{"kdbx_pass_file": "`+passFile+`"}`)
			code, out, _ := runReadIn(t, home, nil, field)
			if code != 0 || out != readTestSecret {
				t.Fatalf("exit = %d, stdout = %q; want 0 and exactly %q", code, out, readTestSecret)
			}
		})
	}

	t.Run("FOOSTORE_SHELL cannot turn a machine read into a shell", func(t *testing.T) {
		// cli.Read never consults FOOSTORE_SHELL; the read contract holds.
		code, out, _ := runReadMachineEnv(t, readTestPassphrase,
			map[string]string{"FOOSTORE_SHELL": "1"}, field)
		if code != 0 || out != readTestSecret {
			t.Fatalf("exit = %d, stdout = %q; read must bypass the shell override", code, out)
		}
	})
}

func TestReadMachineKeyFile(t *testing.T) {
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	creds, err := gokeepasslib.NewPasswordAndKeyDataCredentials(readTestPassphrase, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := createReadCLITestDBWith(t, creds)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	writeKey := func(t *testing.T, mode os.FileMode) (home, keyPath string) {
		home = t.TempDir()
		keyPath = filepath.Join(home, "db.key")
		if err := os.WriteFile(keyPath, keyBytes, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyPath, mode); err != nil { // beat any umask
			t.Fatal(err)
		}
		setupReadHome(t, home, readTestPassphrase, map[string]string{"kdbx_key_file": keyPath})
		return home, keyPath
	}

	t.Run("owner-only key file unlocks the store", func(t *testing.T) {
		home, _ := writeKey(t, 0o600)
		code, out, _ := runReadIn(t, home, nil, argv)
		if code != 0 || out != readTestSecret {
			t.Fatalf("exit = %d, stdout = %q; want 0 and exactly %q", code, out, readTestSecret)
		}
	})

	t.Run("key file with group access is rejected as locked", func(t *testing.T) {
		home, _ := writeKey(t, 0o640)
		code, _, stderr := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
		if !strings.Contains(stderr, "owner-only") {
			t.Fatalf("stderr = %q, want the owner-only explanation", stderr)
		}
	})

	t.Run("missing key file is locked", func(t *testing.T) {
		home := t.TempDir()
		setupReadHome(t, home, readTestPassphrase, map[string]string{"kdbx_key_file": filepath.Join(home, "absent.key")})
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	t.Run("empty key file is refused, not treated as no key file", func(t *testing.T) {
		// The library ignores an empty key, so a password-only unlock would
		// otherwise succeed for a keyed store's sibling that has none.
		home := t.TempDir()
		keyPath := filepath.Join(home, "empty.key")
		if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		setupReadHome(t, home, readTestPassphrase, map[string]string{"kdbx_key_file": keyPath})
		plainDB := createReadCLITestDB(t) // password-only database
		code, out, stderr := runReadIn(t, home, nil,
			[]string{"--kdbx-path", plainDB, "--field", "Password", "Machine/token"})
		if code != readExitLocked || out != "" || !strings.Contains(stderr, "empty") {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q; want locked, no output, an 'empty' diagnostic", code, out, stderr)
		}
	})

	t.Run("keyed store without a key file is locked", func(t *testing.T) {
		code, _, _ := runReadMachine(t, readTestPassphrase, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})
}

func TestReadMachineSelectionHints(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	cases := []struct {
		name, reference, field, hint string
	}{
		{"entry needs field", "Machine/token", "", "specify --field NAME"},
		{"attachment rejects field", "Machine/blob/blob.bin", "Password", "drop --field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv := []string{"--kdbx-path", dbPath}
			if tc.field != "" {
				argv = append(argv, "--field", tc.field)
			}
			argv = append(argv, tc.reference)
			code, out, stderr := runReadMachine(t, readTestPassphrase, argv)
			if code != readExitUsage || out != "" || !strings.Contains(stderr, tc.hint) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q; want usage and hint %q", code, out, stderr, tc.hint)
			}
		})
	}
}

func TestReadMachineCredentialFailures(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("rejects a passfile with group permissions", func(t *testing.T) {
		home := t.TempDir()
		passFile := filepath.Join(home, "kdbx.pass")
		if err := os.WriteFile(passFile, []byte(readTestPassphrase+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+passFile+`"}`)
		code, _, stderr := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
		if !strings.Contains(stderr, "owner-only") {
			t.Fatalf("stderr = %q, want the owner-only explanation", stderr)
		}
	})

	t.Run("no credential source fails locked without prompting", func(t *testing.T) {
		code, _, stderr := runReadMachine(t, "", argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
		if !strings.Contains(stderr, passphraseFDEnv) {
			t.Fatalf("stderr = %q, want guidance naming %s", stderr, passphraseFDEnv)
		}
	})

	t.Run("wrong credentials exit locked", func(t *testing.T) {
		code, _, _ := runReadMachine(t, "nope", argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	// Invalid descriptor values are all locked-class failures, and none of
	// them may echo the variable's value: a passphrase pasted in place of a
	// descriptor number must not reach the logs.
	fdCases := []struct {
		name  string
		value string
	}{
		{"non-numeric value", "hunter2-not-a-number"},
		{"negative descriptor", "-3"},
		{"stdout is reserved", "1"},
		{"stderr is reserved", "2"},
		{"descriptor that is not open", "987654"},
		{"plus sign", "+3"},
		{"padded", " 3"},
		{"hex spelling", "0x3"},
		{"wraps to fd 3 on a 32-bit truncation", "4294967299"},
	}
	for _, tc := range fdCases {
		t.Run("invalid descriptor: "+tc.name, func(t *testing.T) {
			code, _, stderr := runReadMachineEnv(t, "", map[string]string{passphraseFDEnv: tc.value}, argv)
			if code != readExitLocked {
				t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
			}
			// Single-digit values (1, 2) legitimately appear in fixed text.
			if len(tc.value) > 2 && strings.Contains(stderr, tc.value) {
				t.Fatalf("stderr %q echoes the descriptor variable's value %q", stderr, tc.value)
			}
		})
	}

}

// TestReadMachineCredentialSourceFailures covers unusable passphrase files and
// descriptors: every one is a locked-class failure.
func TestReadMachineCredentialSourceFailures(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("$PIN is not a machine-read credential source", func(t *testing.T) {
		code, _, _ := runReadMachineEnv(t, "", map[string]string{"PIN": readTestPassphrase}, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked): $PIN must be ignored", code, readExitLocked)
		}
	})

	t.Run("configured but missing passfile is locked", func(t *testing.T) {
		home := t.TempDir()
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+filepath.Join(home, "absent.pass")+`"}`)
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	t.Run("unreadable passfile is locked", func(t *testing.T) {
		// A directory is owner-only and stats fine but cannot be read as a
		// file, exercising the read-error branch without needing root rules.
		home := t.TempDir()
		dir := filepath.Join(home, "passdir")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+dir+`"}`)
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	t.Run("passfile path that cannot be stat'ed is locked", func(t *testing.T) {
		home := t.TempDir()
		file := filepath.Join(home, "regular")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// A path below a regular file fails with ENOTDIR, not ENOENT.
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+filepath.Join(file, "sub")+`"}`)
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	t.Run("explicitly empty kdbx_pass_file is locked", func(t *testing.T) {
		home := t.TempDir()
		writeReadConfig(t, home, `{"kdbx_pass_file": ""}`)
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})
}

// TestReadMachinePassfileContents covers the exact contents accepted by
// protected passphrase files.
func TestReadMachinePassfileContents(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("passfile with an extra blank line unlocks", func(t *testing.T) {
		home := t.TempDir()
		passFile := filepath.Join(home, "kdbx.pass")
		if err := os.WriteFile(passFile, []byte(readTestPassphrase+"\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+passFile+`"}`)
		code, out, _ := runReadIn(t, home, nil, argv)
		if code != 0 || out != readTestSecret {
			t.Fatalf("exit = %d, stdout = %q; want 0 and %q", code, out, readTestSecret)
		}
	})

	t.Run("passfile with trailing space remains locked", func(t *testing.T) {
		home := t.TempDir()
		passFile := filepath.Join(home, "kdbx.pass")
		if err := os.WriteFile(passFile, []byte(readTestPassphrase+" \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+passFile+`"}`)
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	t.Run("empty passfile is locked", func(t *testing.T) {
		home := t.TempDir()
		passFile := filepath.Join(home, "kdbx.pass")
		if err := os.WriteFile(passFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+passFile+`"}`)
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	t.Run("passfile beyond the size bound is locked", func(t *testing.T) {
		home := t.TempDir()
		passFile := filepath.Join(home, "kdbx.pass")
		if err := os.WriteFile(passFile, bytes.Repeat([]byte("x"), maxCredentialBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		writeReadConfig(t, home, `{"kdbx_pass_file": "`+passFile+`"}`)
		code, _, _ := runReadIn(t, home, nil, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

}

// TestPassphraseFileTrimmingMatchesUnlock checks the shared file rule through
// both credential paths, including empty results and preserved whitespace.
func TestPassphraseFileTrimmingMatchesUnlock(t *testing.T) {
	unsetenv(t, passphraseFDEnv)
	tests := []struct {
		name, content, want string
		wantErr             bool
	}{
		{"plain", "pw", "pw", false},
		{"LF", "pw\n", "pw", false},
		{"CRLF", "pw\r\n", "pw", false},
		{"extra blank line", "pw\n\n", "pw", false},
		{"bare CR", "pw\r", "pw", false},
		{"mixed line endings", "pw\r\n\n\r", "pw", false},
		{"interior newline", "p\nw\r\n", "p\nw", false},
		{"trailing space", "pw \n", "pw ", false},
		{"empty", "", "", true},
		{"only line endings", "\r\n\n", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kdbx.pass")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			interactive, interactiveErr := readPasswordFile(path)
			machine, machineErr := readMachinePassphrase(&config.Config{KDBXPassFile: path})
			if (interactiveErr != nil) != tc.wantErr || (machineErr != nil) != tc.wantErr {
				t.Fatalf("interactive error = %v, machine error = %v; want error %t", interactiveErr, machineErr, tc.wantErr)
			}
			if interactive != tc.want || machine != tc.want {
				t.Fatalf("interactive = %q, machine = %q; want %q", interactive, machine, tc.want)
			}
		})
	}
}

// TestReadMachineDescriptorFailures covers unusable passphrase descriptors:
// wrong types, oversized and empty payloads.
func TestReadMachineDescriptorFailures(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("descriptor that is a directory is refused, not read and closed", func(t *testing.T) {
		fd, err := syscall.Open(t.TempDir(), syscall.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = syscall.Close(fd) }()
		code, _, stderr := runReadMachineEnv(t, "", map[string]string{passphraseFDEnv: strconv.Itoa(fd)}, argv)
		if code != readExitLocked || !strings.Contains(stderr, "pipe, socket or regular file") {
			t.Fatalf("exit = %d, stderr = %q; want locked with the descriptor-type explanation", code, stderr)
		}
		if err := syscall.Fstat(fd, new(syscall.Stat_t)); err != nil {
			t.Fatalf("the refused descriptor was closed: %v", err)
		}
	})

	t.Run("oversized descriptor passphrase is locked", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		fd, err := syscall.Dup(int(r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Close()
		go func() { // the pipe buffer is smaller than the payload
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxCredentialBytes+1))
			_ = w.Close()
		}()
		code, _, _ := runReadMachineEnv(t, "", map[string]string{passphraseFDEnv: strconv.Itoa(fd)}, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})

	t.Run("empty descriptor passphrase is locked", func(t *testing.T) {
		fd := passphraseFD(t, "\n", true)
		code, _, _ := runReadMachineEnv(t, "", map[string]string{passphraseFDEnv: strconv.Itoa(fd)}, argv)
		if code != readExitLocked {
			t.Fatalf("exit = %d, want %d (locked)", code, readExitLocked)
		}
	})
}

func TestReadMachineStoreFailures(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	field := func(path, ref string) []string {
		return []string{"--kdbx-path", path, "--field", "Password", ref}
	}

	for _, reference := range []string{"Machine/missing", `Machine/other\name`, `Machine\token`, "Machine/gone ", "Machine/token "} {
		t.Run("not found: "+reference, func(t *testing.T) {
			code, _, _ := runReadMachine(t, readTestPassphrase, field(dbPath, reference))
			if code != readExitNotFound {
				t.Fatalf("exit = %d, want %d (not found)", code, readExitNotFound)
			}
		})
	}

	t.Run("missing field exits 4", func(t *testing.T) {
		code, _, _ := runReadMachine(t, readTestPassphrase,
			[]string{"--kdbx-path", dbPath, "--field", "UserName", "Machine/token"})
		if code != readExitNotFound {
			t.Fatalf("exit = %d, want %d (not found)", code, readExitNotFound)
		}
	})

	t.Run("ambiguous identity exits 5", func(t *testing.T) {
		code, _, _ := runReadMachine(t, readTestPassphrase, field(createDuplicateTitleDB(t), "Dupes/dupe"))
		if code != readExitAmbiguous {
			t.Fatalf("exit = %d, want %d (ambiguous)", code, readExitAmbiguous)
		}
	})

	t.Run("non-canonical spelling exits usage, not the suppressible 4", func(t *testing.T) {
		code, _, _ := runReadMachine(t, readTestPassphrase, field(dbPath, "./Machine/token"))
		if code != readExitUsage {
			t.Fatalf("exit = %d, want %d (usage)", code, readExitUsage)
		}
	})

	t.Run("corrupt store exits 7", func(t *testing.T) {
		garbage := filepath.Join(t.TempDir(), "garbage.kdbx")
		if err := os.WriteFile(garbage, []byte("not a keepass database"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, _ := runReadMachine(t, readTestPassphrase, field(garbage, "Machine/token"))
		if code != readExitCorrupt {
			t.Fatalf("exit = %d, want %d (corrupt)", code, readExitCorrupt)
		}
	})

	t.Run("missing store exits I/O", func(t *testing.T) {
		code, _, _ := runReadMachine(t, readTestPassphrase, field(filepath.Join(t.TempDir(), "missing.kdbx"), "Machine/token"))
		if code != readExitIO {
			t.Fatalf("exit = %d, want %d (I/O)", code, readExitIO)
		}
	})

}

// TestReadMachineConfigAndOutputFailures covers failures that are not about the
// store contents: the configuration and the output channel.
func TestReadMachineConfigAndOutputFailures(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	field := func(path, ref string) []string {
		return []string{"--kdbx-path", path, "--field", "Password", ref}
	}

	t.Run("unresolvable HOME fails instead of using a shared fallback", func(t *testing.T) {
		t.Setenv("HOME", "")
		unsetenv(t, "PIN")
		unsetenv(t, passphraseFDEnv)
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = devNull.Close() }()
		old := os.Stderr
		os.Stderr = devNull
		defer func() { os.Stderr = old }()
		var stdout bytes.Buffer
		if code := readCommand(context.Background(), field(dbPath, "Machine/token"), &stdout); code != readExitIO || stdout.Len() != 0 {
			t.Fatalf("exit = %d, stdout = %q; want %d and no output", code, stdout.String(), readExitIO)
		}
	})

	t.Run("broken config file fails instead of reading the default store", func(t *testing.T) {
		home := t.TempDir()
		writeReadConfig(t, home, `{not json`)
		code, _, stderr := runReadIn(t, home, nil, field(dbPath, "Machine/token"))
		if code != readExitIO {
			t.Fatalf("exit = %d, want %d (I/O): a malformed config must not fall back to defaults", code, readExitIO)
		}
		if !strings.Contains(stderr, "foostore.json") {
			t.Fatalf("stderr = %q, want it to name the config file", stderr)
		}
	})

	t.Run("stdout write failure exits I/O", func(t *testing.T) {
		t.Setenv("HOME", newReadHome(t, readTestPassphrase, nil))
		unsetenv(t, "PIN")
		unsetenv(t, passphraseFDEnv)
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = devNull.Close() }()
		old := os.Stderr
		os.Stderr = devNull
		defer func() { os.Stderr = old }()

		code := readCommand(context.Background(), field(dbPath, "Machine/token"), failingWriter{})
		if code != readExitIO {
			t.Fatalf("exit = %d, want %d (I/O)", code, readExitIO)
		}
	})
}

// failingWriter models a closed stdout pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestReadMachineUsageErrors(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	tests := []struct {
		name string
		argv []string
	}{
		{"no reference", nil},
		{"two references", []string{"a", "b"}},
		{"unknown flag", []string{"--bogus", "Machine/token"}},
		{"entry reference without --field", []string{"--kdbx-path", dbPath, "Machine/token"}},
		{"field on attachment reference", []string{"--field", "Password", "--kdbx-path", dbPath, "Machine/blob/blob.bin"}},
		{"geheim backend", []string{"--backend", "geheim", "--kdbx-path", dbPath, "--field", "Password", "Machine/token"}},
		{"unknown backend name", []string{"--backend", "keepass-typo", "--kdbx-path", dbPath, "--field", "Password", "Machine/token"}},
		{"empty --kdbx-path would select the default store", []string{"--kdbx-path", "", "--field", "Password", "Machine/token"}},
		{"empty --backend would select the default backend", []string{"--backend", "", "--kdbx-path", dbPath, "--field", "Password", "Machine/token"}},
		{"empty --field", []string{"--kdbx-path", dbPath, "--field", "", "Machine/blob/blob.bin"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := runReadMachine(t, readTestPassphrase, tc.argv)
			if code != readExitUsage {
				t.Fatalf("exit = %d, want %d (usage)", code, readExitUsage)
			}
		})
	}

	t.Run("config-selected geheim backend is rejected", func(t *testing.T) {
		home := newReadHome(t, readTestPassphrase, map[string]string{"backend": "geheim"})
		code, _, _ := runReadIn(t, home, nil,
			[]string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"})
		if code != readExitUsage {
			t.Fatalf("exit = %d, want %d (usage)", code, readExitUsage)
		}
	})
}

// TestReadMachineIsBounded pins the bounded-cancellation contract for the
// step that can block indefinitely without any KDF involved: the credential
// source. A writer that never delivers must not hang the consumer.
func TestReadMachineIsBounded(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("stalled passphrase descriptor hits --timeout", func(t *testing.T) {
		fd := passphraseFD(t, "", false)
		start := time.Now()
		code, out, stderr := runReadMachineEnv(t, "",
			map[string]string{passphraseFDEnv: strconv.Itoa(fd)},
			append([]string{"--timeout", "200ms"}, argv...))
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("read took %s, want it bounded near the 200ms timeout", elapsed)
		}
		if code != 1 || out != "" {
			t.Fatalf("exit = %d, stdout = %q; want 1 and no output", code, out)
		}
		if !strings.Contains(stderr, "timed out") {
			t.Fatalf("stderr = %q, want a timeout diagnostic", stderr)
		}
	})

	t.Run("signal cancellation is reported as cancellation", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		unsetenv(t, "PIN")
		t.Setenv(passphraseFDEnv, strconv.Itoa(passphraseFD(t, "", false)))
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = devNull.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		old := os.Stderr
		os.Stderr = devNull
		var stdout bytes.Buffer
		code := readCommand(ctx, argv, &stdout)
		os.Stderr = old

		if code != 1 || stdout.Len() != 0 {
			t.Fatalf("exit = %d, stdout = %q; want 1 and no output", code, stdout.String())
		}
	})
}

// TestReadPassphraseFromFDStripsOneTerminator pins the documented strip rule:
// exactly one trailing "\n" or "\r\n", nothing else.
func TestReadPassphraseFromFDStripsOneTerminator(t *testing.T) {
	tests := []struct{ in, want string }{
		{"pw", "pw"},
		{"pw\n", "pw"},
		{"pw\r\n", "pw"},
		{"pw\n\n", "pw\n"},
		{"pw\r", "pw\r"}, // a bare trailing CR belongs to the passphrase
		{" pw ", " pw "},
	}
	for _, tc := range tests {
		fd := passphraseFD(t, tc.in, true)
		got, err := readPassphraseFromFD(strconv.Itoa(fd))
		if err != nil || got != tc.want {
			t.Fatalf("readPassphraseFromFD(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestReadExitForUnclassifiedIsGenericFailure(t *testing.T) {
	if got := readExitFor(errors.New("something unexpected")); got != 1 {
		t.Fatalf("readExitFor(unclassified) = %d, want 1", got)
	}
}

func TestReadHelpRequiresSoleArgument(t *testing.T) {
	if !wantsReadHelp([]string{"--help"}) {
		t.Fatal("sole --help must request help")
	}
	if wantsReadHelp([]string{"-h"}) {
		t.Fatal("sole -h must not request help; it is a usage error")
	}
	if !isSoleRejectedShortHelp([]string{"-h"}) {
		t.Fatal("sole -h must take the dedicated rejected-short-help path")
	}
	if isSoleRejectedShortHelp([]string{"--help"}) {
		t.Fatal("sole --help is help, not the rejected-short-help path")
	}
	if isSoleRejectedShortHelp([]string{"-h", "Machine/token"}) {
		t.Fatal("mixed -h must not take the dedicated sole -h path")
	}
	if wantsReadHelp([]string{"--", "--help"}) {
		t.Fatal("an argument after -- is a reference, never a help request")
	}
	if wantsReadHelp([]string{"--field", "-h", "Machine/token"}) {
		t.Fatal("a flag's value is data, never a help request")
	}
	if wantsReadHelp([]string{"--field", "Password", "-h"}) {
		t.Fatal("mixed arguments must not request help")
	}
	if wantsReadHelp([]string{"--help", "Machine/token"}) {
		t.Fatal("mixed --help must not request help")
	}
}

// blockingWriter models a consumer that never drains stdout.
type blockingWriter struct{ release chan struct{} }

func (b blockingWriter) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

// TestReadMachineStdoutWriteIsBounded pins that --timeout and signal
// cancellation also cover the final write: a consumer that never reads must
// not hang the read (or swallow SIGTERM) until it is killed.
func TestReadMachineStdoutWriteIsBounded(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	run := func(t *testing.T, ctx context.Context, extra ...string) (int, string) {
		t.Helper()
		t.Setenv("HOME", newReadHome(t, readTestPassphrase, nil))
		unsetenv(t, "PIN")
		unsetenv(t, passphraseFDEnv)
		stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = stderrFile.Close() }()
		old := os.Stderr
		os.Stderr = stderrFile
		release := make(chan struct{})
		defer close(release) // let the abandoned write goroutine finish
		start := time.Now()
		code := readCommand(ctx, append(extra, argv...), blockingWriter{release})
		os.Stderr = old
		if elapsed := time.Since(start); elapsed > 20*time.Second {
			t.Fatalf("read took %s despite the bound", elapsed)
		}
		_, _ = stderrFile.Seek(0, 0)
		data, _ := io.ReadAll(stderrFile)
		return code, string(data)
	}

	t.Run("timeout", func(t *testing.T) {
		code, stderr := run(t, context.Background(), "--timeout", "4s")
		if code != 1 || !strings.Contains(stderr, "timed out") || !strings.Contains(stderr, "stdout") {
			t.Fatalf("exit = %d, stderr = %q; want 1 and a timed-out-while-writing diagnostic", code, stderr)
		}
	})

	t.Run("signal cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(3*time.Second, cancel)
		code, stderr := run(t, ctx)
		if code != 1 || !strings.Contains(stderr, "cancelled") {
			t.Fatalf("exit = %d, stderr = %q; want 1 and a cancellation diagnostic", code, stderr)
		}
	})
}

func TestReadMachineCredentialDefaultsAreNeverImplicit(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	argv := []string{"--kdbx-path", dbPath, "--field", "Password", "Machine/token"}

	t.Run("an owner-only default ~/.master.pass is not picked up", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".master.pass"), []byte(readTestPassphrase+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, _ := runReadIn(t, home, nil, argv) // no config file at all
		if code != readExitLocked || out != "" {
			t.Fatalf("exit = %d, stdout = %q; want locked: the default passfile must not be used", code, out)
		}
	})

	t.Run("an exported empty descriptor variable fails instead of falling through", func(t *testing.T) {
		code, out, stderr := runReadMachineEnv(t, readTestPassphrase, map[string]string{passphraseFDEnv: ""}, argv)
		if code != readExitLocked || out != "" || !strings.Contains(stderr, "set but empty") {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q; want locked with a 'set but empty' diagnostic", code, out, stderr)
		}
	})
}

// TestReadMachineFlagValueSpelledReadAfterCommandWord pins that after an
// explicit command word a flag value spelled "read" is just a value: the
// field is looked up and (not existing) reported as not-found, not rejected.
func TestReadMachineFlagValueSpelledReadAfterCommandWord(t *testing.T) {
	dbPath := createReadCLITestDB(t)
	code, _, stderr := runReadMachine(t, readTestPassphrase,
		[]string{"--kdbx-path", dbPath, "--field", "read", "Machine/token"})
	if code != readExitNotFound {
		t.Fatalf("exit = %d, stderr = %q; want %d (no field named read)", code, stderr, readExitNotFound)
	}
}

// TestReadMachineConfigLoadIsBounded pins that a stalled config file — here a
// FIFO nobody writes to — cannot hang the read past --timeout.
func TestReadMachineConfigLoadIsBounded(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(home, ".config", "foostore.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	// Unblock the abandoned reader at cleanup so it does not linger.
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
			_ = f.Close()
		}
	})

	start := time.Now()
	code, out, stderr := runReadIn(t, home, nil,
		[]string{"--timeout", "300ms", "--kdbx-path", createReadCLITestDB(t), "--field", "Password", "Machine/token"})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("read took %s, want it bounded near the 300ms timeout", elapsed)
	}
	if code != 1 || out != "" || !strings.Contains(stderr, "loading the config file") {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q; want 1, no output, a config-load timeout", code, out, stderr)
	}
}

// TestReadPassphraseFromFDRefusesCloseOnExecDescriptors pins that only a
// descriptor inherited across exec is read: os.Pipe descriptors are
// close-on-exec, like every descriptor the Go runtime opens for itself, and
// must be refused without being consumed or closed.
func TestReadPassphraseFromFDRefusesCloseOnExecDescriptors(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if _, err := w.WriteString(readTestPassphrase + "\n"); err != nil {
		t.Fatal(err)
	}
	fd := int(r.Fd())

	_, err = readPassphraseFromFD(strconv.Itoa(fd))
	if err == nil || !strings.Contains(err.Error(), "close-on-exec") {
		t.Fatalf("error = %v; want the close-on-exec refusal", err)
	}
	if strings.Contains(err.Error(), readTestPassphrase) {
		t.Fatalf("error %q leaks the passphrase", err)
	}
	if err := syscall.Fstat(fd, new(syscall.Stat_t)); err != nil {
		t.Fatalf("the refused descriptor was closed: %v", err)
	}
	buf := make([]byte, 16)
	if n, err := r.Read(buf); err != nil || string(buf[:n]) != readTestPassphrase+"\n" {
		t.Fatalf("the refused descriptor was consumed: read %q, %v", buf[:n], err)
	}
}
