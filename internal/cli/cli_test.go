// Package cli (internal tests) exercise pure package-level helpers and
// dispatch paths that do not require a full CLI setup (no cipher, no store,
// no terminal).
package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/snonux/foostore/internal/clipboard"
	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/crypto"
	"codeberg.org/snonux/foostore/internal/git"
	"codeberg.org/snonux/foostore/internal/shell"
	"codeberg.org/snonux/foostore/internal/store"
)

// testCLI creates a fully wired CLI backed by temporary directories and a real
// cipher so that dispatch paths that touch the store can be exercised.
// No git repo is initialised, so tests must not attempt commits.
func testCLI(t *testing.T) (*CLI, *config.Config) {
	t.Helper()

	dataDir := t.TempDir()
	exportDir := t.TempDir()
	keyDir := t.TempDir()
	keyFile := filepath.Join(keyDir, "key")
	if err := os.WriteFile(keyFile, []byte("testkey1234567890"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	cfg := &config.Config{
		DataDir:   dataDir,
		ExportDir: exportDir,
		KeyFile:   keyFile,
		KeyLength: 32,
		AddToIV:   "Hello world",
	}

	ciph, err := crypto.NewCipher(keyFile, 32, "testpin", "Hello world")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	g := git.New(dataDir)
	st, err := store.New(cfg, ciph, g)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	// No-op completion function; no readline instance needed for dispatch tests.
	sh, err := shell.New(func(string) []string { return nil })
	if err != nil {
		t.Logf("shell.New: %v (non-TTY, skipping test)", err)
		t.Skip("shell.New requires a TTY")
	}
	t.Cleanup(func() { sh.Close() })

	return &CLI{
		cfg:  cfg,
		st:   st,
		g:    g,
		clip: clipboard.New("", ""),
		sh:   sh,
	}, cfg
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	cmds := [][]string{
		{"git", "init", dir},
		{"git", "-C", dir, "config", "user.email", "test@example.com"},
		{"git", "-C", dir, "config", "user.name", "Test"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

// captureStdout redirects os.Stdout to a pipe, calls fn, then returns what was
// written and restores the original Stdout.
func captureStdout(fn func()) string {
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return ""
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// captureStderr redirects os.Stderr to a pipe, calls fn, then returns what was
// written and restores the original Stderr.
func captureStderr(fn func()) string {
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		return ""
	}
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// TestLogMsg verifies that logMsg writes "> <msg>\n" to stdout.
func TestLogMsg(t *testing.T) {
	got := captureStdout(func() { logMsg("hello world") })
	want := "> hello world\n"
	if got != want {
		t.Errorf("logMsg output = %q; want %q", got, want)
	}
}

// TestWarn verifies that warn writes "WARN <msg>\n" to stderr.
func TestWarn(t *testing.T) {
	got := captureStderr(func() { warn("something bad") })
	want := "WARN something bad\n"
	if got != want {
		t.Errorf("warn output = %q; want %q", got, want)
	}
}

// TestPrintHelp verifies that printHelp writes a non-empty help text to stdout
// containing key command names.
func TestPrintHelp(t *testing.T) {
	got := captureStdout(func() { printHelp() })
	for _, cmd := range []string{"ls", "cat", "add", "import", "sync", "version"} {
		if !strings.Contains(got, cmd) {
			t.Errorf("printHelp output missing %q; full output:\n%s", cmd, got)
		}
	}
}

// TestShredFileCli verifies that store.ShredFile removes a temporary file.
// It uses a temp file so no live data is affected.
func TestShredFileCli(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "todelete.txt")
	if err := os.WriteFile(target, []byte("sensitive"), 0o600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	ctx := t.Context()
	if err := store.ShredFile(ctx, target); err != nil {
		t.Fatalf("ShredFile: %v", err)
	}

	if _, err := os.Stat(target); err == nil {
		t.Errorf("file %q still exists after ShredFile", target)
	}
}

// ---- dispatch helpers -------------------------------------------------------
// The following tests use a bare &CLI{} because the tested code paths in
// dispatchSimple never dereference any struct fields — they only call package-
// level helpers (logMsg, warn, printHelp) or read c.lastResult (zero value "").

// TestDispatch_noopCommands runs the stateless dispatchSimple branches and
// confirms they all return exit code 0.
func TestDispatch_noopCommands(t *testing.T) {
	ctx := context.Background()
	c := &CLI{}

	for _, cmd := range []string{"version", "commands", "help", "shell", "exit", "last"} {
		t.Run(cmd, func(t *testing.T) {
			// Capture stdout/stderr to avoid noise in test output.
			_ = captureStdout(func() {
				_ = captureStderr(func() {
					ec := c.dispatch(ctx, []string{cmd})
					if ec != 0 {
						t.Errorf("dispatch(%q) = %d; want 0", cmd, ec)
					}
				})
			})
		})
	}
}

// TestDispatch_version_output confirms that dispatch("version") emits the
// version string to stdout.
func TestDispatch_version_output(t *testing.T) {
	ctx := context.Background()
	c := &CLI{}
	out := captureStdout(func() { c.dispatch(ctx, []string{"version"}) })
	if !strings.Contains(out, "foostore") {
		t.Errorf("version output %q does not contain 'foostore'", out)
	}
}

// TestDispatch_commands_output confirms that dispatch("commands") lists all
// commands to stdout, one per line.
func TestDispatch_commands_output(t *testing.T) {
	ctx := context.Background()
	c := &CLI{}
	out := captureStdout(func() { c.dispatch(ctx, []string{"commands"}) })
	for _, cmd := range []string{"ls", "cat", "add", "sync", "import"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("commands output missing %q; output:\n%s", cmd, out)
		}
	}
}

// ---- cmd* error paths -------------------------------------------------------
// The error paths for missing arguments do not access any struct fields.

// TestCmdAdd_missingArgs verifies cmdAdd returns exit code 1 when no
// description argument is supplied.
func TestCmdAdd_missingArgs(t *testing.T) {
	c := &CLI{}
	ec := c.cmdAdd(context.Background(), []string{"add"})
	if ec != 1 {
		t.Errorf("cmdAdd with no args = %d; want 1", ec)
	}
}

// TestCmdImport_missingArgs verifies cmdImport returns exit code 1 when no
// file argument is supplied.
func TestCmdImport_missingArgs(t *testing.T) {
	c := &CLI{}
	ec := c.cmdImport(context.Background(), []string{"import"})
	if ec != 1 {
		t.Errorf("cmdImport with no args = %d; want 1", ec)
	}
}

// TestCmdImportR_missingArgs verifies cmdImportR returns exit code 1 when no
// directory argument is supplied.
func TestCmdImportR_missingArgs(t *testing.T) {
	c := &CLI{}
	ec := c.cmdImportR(context.Background(), []string{"import_r"})
	if ec != 1 {
		t.Errorf("cmdImportR with no args = %d; want 1", ec)
	}
}

// ---- store-backed dispatch tests --------------------------------------------
// These tests use testCLI() which provides a real but empty store.

// TestDispatch_ls_empty confirms that dispatch("ls") on an empty store
// returns exit code 0 and prints "0 entries".
func TestDispatch_ls_empty(t *testing.T) {
	c, _ := testCLI(t)
	out := captureStdout(func() {
		ec := c.dispatch(context.Background(), []string{"ls"})
		if ec != 0 {
			t.Errorf("dispatch(ls) = %d; want 0", ec)
		}
	})
	if !strings.Contains(out, "0 entries") {
		t.Errorf("ls output %q does not contain '0 entries'", out)
	}
}

// TestDispatch_shred_empty confirms that dispatch("shred") on an empty export
// dir returns exit code 0.
func TestDispatch_shred_empty(t *testing.T) {
	c, _ := testCLI(t)
	ec := c.dispatch(context.Background(), []string{"shred"})
	if ec != 0 {
		t.Errorf("dispatch(shred) = %d; want 0", ec)
	}
}

// TestDispatch_emptyArgv confirms that dispatch with an empty argv on an empty
// store returns exit code 0 (no fzf entries, immediate return).
func TestDispatch_emptyArgv(t *testing.T) {
	c, _ := testCLI(t)
	ec := c.dispatch(context.Background(), []string{})
	if ec != 0 {
		t.Errorf("dispatch([]) = %d; want 0", ec)
	}
}

// TestDispatch_search_empty confirms that dispatch("search", "foo") returns
// exit code 0 when there are no matching entries.
func TestDispatch_search_empty(t *testing.T) {
	c, _ := testCLI(t)
	ec := c.dispatch(context.Background(), []string{"search", "foo"})
	if ec != 0 {
		t.Errorf("dispatch(search,foo) = %d; want 0", ec)
	}
}

// TestDispatch_cat_empty confirms that dispatch("cat", "foo") returns exit
// code 0 when there are no matching entries.
func TestDispatch_cat_empty(t *testing.T) {
	c, _ := testCLI(t)
	ec := c.dispatch(context.Background(), []string{"cat", "foo"})
	if ec != 0 {
		t.Errorf("dispatch(cat,foo) = %d; want 0", ec)
	}
}

// TestDispatch_rm_empty confirms that dispatch("rm", "foo") returns exit code
// 0 when there are no matching entries (nothing to remove).
func TestDispatch_rm_empty(t *testing.T) {
	c, _ := testCLI(t)
	ec := c.dispatch(context.Background(), []string{"rm", "foo"})
	if ec != 0 {
		t.Errorf("dispatch(rm,foo) = %d; want 0", ec)
	}
}

// TestDispatch_unknownCommand confirms that an unrecognised command is treated
// as a search term and returns exit code 0 on an empty store.
func TestDispatch_unknownCommand(t *testing.T) {
	c, _ := testCLI(t)
	ec := c.dispatch(context.Background(), []string{"completelyunknown"})
	if ec != 0 {
		t.Errorf("dispatch(unknown) = %d; want 0", ec)
	}
}

func TestDispatch_gitSimpleCommands(t *testing.T) {
	c, cfg := testCLI(t)
	initGitRepo(t, cfg.DataDir)

	ctx := context.Background()
	for _, cmd := range []string{"status", "reset", "sync"} {
		t.Run(cmd, func(t *testing.T) {
			_ = captureStdout(func() {
				_ = captureStderr(func() {
					ec := c.dispatch(ctx, []string{cmd})
					if ec != 0 {
						t.Errorf("dispatch(%q) = %d; want 0", cmd, ec)
					}
				})
			})
		})
	}
}

func TestDispatch_commitNoChanges(t *testing.T) {
	c, cfg := testCLI(t)
	initGitRepo(t, cfg.DataDir)

	ec := c.dispatch(context.Background(), []string{"commit"})
	if ec != 1 {
		t.Errorf("dispatch(commit) = %d; want 1 when nothing to commit", ec)
	}
}

func TestDispatch_fullCommitNoChanges(t *testing.T) {
	c, cfg := testCLI(t)
	initGitRepo(t, cfg.DataDir)

	ec := c.dispatch(context.Background(), []string{"fullcommit"})
	if ec != 1 {
		t.Errorf("dispatch(fullcommit) = %d; want 1 when commit step fails", ec)
	}
}

func TestDispatchSearch_usesLastResultFallback(t *testing.T) {
	c, cfg := testCLI(t)
	initGitRepo(t, cfg.DataDir)

	ctx := context.Background()
	if err := c.st.Add(ctx, "fallback/entry", "secret"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	c.lastResult = "fallback/entry"

	out := captureStdout(func() {
		ec := c.dispatch(ctx, []string{"search"})
		if ec != 0 {
			t.Fatalf("dispatch(search with fallback) = %d; want 0", ec)
		}
	})
	if !strings.Contains(out, "fallback/entry") {
		t.Fatalf("expected fallback search output to contain entry, got %q", out)
	}
	if c.lastResult != "fallback/entry" {
		t.Fatalf("lastResult = %q; want fallback/entry", c.lastResult)
	}
}

func TestDispatchPickerAction(t *testing.T) {
	c, cfg := testCLI(t)
	initGitRepo(t, cfg.DataDir)

	ctx := context.Background()
	if err := c.st.Add(ctx, "picker/entry.txt", "picker content"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	t.Run("select is no-op", func(t *testing.T) {
		ec := c.dispatchPickerAction(ctx, store.PickerResult{
			Description: "picker/entry.txt",
			Action:      store.PickerSelect,
		})
		if ec != 0 {
			t.Fatalf("dispatchPickerAction(select) = %d; want 0", ec)
		}
	})

	t.Run("cat routes through dispatch", func(t *testing.T) {
		out := captureStdout(func() {
			ec := c.dispatchPickerAction(ctx, store.PickerResult{
				Description: "picker/entry.txt",
				Action:      store.PickerCat,
			})
			if ec != 0 {
				t.Fatalf("dispatchPickerAction(cat) = %d; want 0", ec)
			}
		})
		if !strings.Contains(out, "picker/entry.txt") {
			t.Fatalf("picker cat output missing description, got %q", out)
		}
	})
}

// ---- readPIN ----------------------------------------------------------------

// TestReadPIN_envVar verifies that readPIN returns the $PIN value immediately
// without touching the terminal.
func TestReadPIN_envVar(t *testing.T) {
	t.Setenv("PIN", "s3cret")
	pin, err := readPIN()
	if err != nil {
		t.Fatalf("readPIN: %v", err)
	}
	if pin != "s3cret" {
		t.Errorf("readPIN = %q; want %q", pin, "s3cret")
	}
}

// ---- completionFn -----------------------------------------------------------

// TestCompletionFn_commandsOnly verifies that completionFn (with $PIN unset)
// returns matching command names and nothing else.
func TestCompletionFn_commandsOnly(t *testing.T) {
	t.Setenv("PIN", "") // ensure no store walk
	c, _ := testCLI(t)

	results := c.completionFn("sy")
	if len(results) != 1 || results[0] != "sync" {
		t.Errorf("completionFn(sy) = %v; want [sync]", results)
	}

	results = c.completionFn("")
	if len(results) != len(CommandList) {
		t.Errorf("completionFn('') returned %d results; want %d", len(results), len(CommandList))
	}
}

// ---- makeActionFn -----------------------------------------------------------

// TestMakeActionFn_nil verifies that makeActionFn returns nil for actions
// handled directly by the store (cat, export, pathexport).
func TestMakeActionFn_nil(t *testing.T) {
	c, _ := testCLI(t)
	ctx := context.Background()

	for _, action := range []store.Action{store.ActionCat, store.ActionExport, store.ActionPathExport} {
		fn := c.makeActionFn(ctx, action)
		if fn != nil {
			t.Errorf("makeActionFn(%v) = non-nil; want nil (store handles it internally)", action)
		}
	}
}

// ---- pickerActionArgv -------------------------------------------------------

// TestPickerActionArgv verifies the direct mapping from picker action keys to
// CLI argv commands used by interactive empty-line fzf selection.
func TestPickerActionArgv(t *testing.T) {
	desc := "docs/secret.txt"

	cases := []struct {
		name   string
		action store.PickerAction
		want   []string
	}{
		{name: "select", action: store.PickerSelect, want: nil},
		{name: "cat", action: store.PickerCat, want: []string{"cat", desc}},
		{name: "paste", action: store.PickerPaste, want: []string{"paste", desc}},
		{name: "open", action: store.PickerOpen, want: []string{"open", desc}},
		{name: "edit", action: store.PickerEdit, want: []string{"edit", desc}},
		{name: "unknown", action: store.PickerAction("weird"), want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickerActionArgv(tc.action, desc)
			if len(got) != len(tc.want) {
				t.Fatalf("pickerActionArgv(%q) len = %d; want %d (%v)", tc.action, len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("pickerActionArgv(%q)[%d] = %q; want %q", tc.action, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// ---- remaining dispatchSearch branches --------------------------------------

// TestDispatch_searchActions exercises all SearchActions entries on an empty
// store, confirming each returns exit code 0 without panicking.
func TestDispatch_searchActions(t *testing.T) {
	c, _ := testCLI(t)
	ctx := context.Background()

	// These commands go through dispatchSearch/cmdSearchAction.
	// With an empty store they find no matching entries and return 0.
	for _, cmd := range []string{"paste", "export", "pathexport", "open", "edit", "get"} {
		t.Run(cmd, func(t *testing.T) {
			ec := c.dispatch(ctx, []string{cmd, "nonexistent"})
			if ec != 0 {
				t.Errorf("dispatch(%q, nonexistent) = %d; want 0", cmd, ec)
			}
		})
	}
}

// ---- add/import/import_r with real args (error paths) ----------------------

// TestDispatch_add_noStdinData calls dispatch("add", "desc") when stdin is
// empty (as in a non-interactive test run). cmdAdd should detect no data and
// return exit code 1.
func TestDispatch_add_noStdinData(t *testing.T) {
	c, _ := testCLI(t)
	// Redirect stdin to /dev/null so scanner.Scan returns false immediately.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer null.Close()
	origStdin := os.Stdin
	os.Stdin = null
	defer func() { os.Stdin = origStdin }()

	_ = captureStdout(func() {
		_ = captureStderr(func() {
			ec := c.dispatch(context.Background(), []string{"add", "my/desc"})
			if ec != 1 {
				t.Errorf("dispatch(add,desc) with empty stdin = %d; want 1", ec)
			}
		})
	})
}

// TestDispatch_import_missingFile calls dispatch("import", "/no/such/file")
// which should return exit code 1 after failing to read the source file.
func TestDispatch_import_missingFile(t *testing.T) {
	c, _ := testCLI(t)
	_ = captureStderr(func() {
		ec := c.dispatch(context.Background(), []string{"import", "/no/such/file.txt"})
		if ec != 1 {
			t.Errorf("dispatch(import, missing) = %d; want 1", ec)
		}
	})
}

// TestDispatch_importR_missingDir calls dispatch("import_r", "/no/such/dir")
// which should return exit code 1 after failing to walk the directory.
func TestDispatch_importR_missingDir(t *testing.T) {
	c, _ := testCLI(t)
	_ = captureStderr(func() {
		ec := c.dispatch(context.Background(), []string{"import_r", "/no/such/dir"})
		if ec != 1 {
			t.Errorf("dispatch(import_r, missing) = %d; want 1", ec)
		}
	})
}
