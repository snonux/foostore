// Package cli implements the command-line interface for foostore.
// It mirrors the Ruby CLI class (geheim.rb lines 551-713): parsing argv,
// dispatching commands, and running an optional interactive readline shell.
// Run() is the top-level entry point called by cmd/foostore/main.go.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"codeberg.org/snonux/foostore/internal/clipboard"
	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/crypto"
	"codeberg.org/snonux/foostore/internal/git"
	"codeberg.org/snonux/foostore/internal/shell"
	"codeberg.org/snonux/foostore/internal/store"
	"codeberg.org/snonux/foostore/internal/version"
)

// CommandList is the canonical list of supported commands, ordered to match
// the Ruby COMMANDS constant exactly.  Used for tab-completion and `commands`.
var CommandList = []string{
	"ls", "search", "cat", "paste", "get", "add", "export", "pathexport",
	"open", "edit", "import", "import_r", "rm", "sync", "status", "commit",
	"reset", "fullcommit", "shred", "migrate-kdbx", "version", "commands", "help", "shell",
	"exit", "last",
}

// SearchActions maps command names to store.Action values for commands that
// accept a search term and perform an action on each match.  Mirrors the Ruby
// SEARCH_ACTIONS constant.
var SearchActions = map[string]store.Action{
	"cat":        store.ActionCat,
	"paste":      store.ActionPaste,
	"export":     store.ActionExport,
	"pathexport": store.ActionPathExport,
	"edit":       store.ActionEdit,
	"open":       store.ActionOpen,
}

// CLI holds all runtime dependencies created during New().
// lastResult is updated by dispatch and used as a fallback search term when
// a search-based command is invoked without an explicit term (mirrors Ruby's
// @last_result instance variable).
type CLI struct {
	cfg        *config.Config
	st         *store.Store
	g          *git.Git
	clip       *clipboard.Clipboard
	sh         *shell.Shell
	openKDBX   func(string, string) (KDBXStore, error)
	now        func() time.Time
	lastResult string // most recent search result description
}

// New initialises all runtime dependencies (config, PIN, cipher, store, git,
// clipboard, shell) and returns a ready-to-use CLI.  cmd/foostore/main.go calls
// New with a signal-cancellable context so that long-running operations (fzf,
// external editors) are interrupted cleanly on SIGINT/SIGTERM.
func New(ctx context.Context) (*CLI, error) {
	return newCLI(ctx)
}

// Run dispatches argv (typically os.Args[1:]) to the appropriate handler or
// enters the interactive shell loop.  Returns an exit code suitable for
// os.Exit.  The caller is responsible for calling sh.Close() when done;
// cmd/foostore/main.go does this via defer.
func (c *CLI) Run(ctx context.Context, argv []string) int {
	defer c.sh.Close()
	return c.run(ctx, argv)
}

// newCLI initialises all dependencies: config, PIN, cipher, store, git,
// clipboard, and interactive shell.  Mirrors the Ruby CLI#initialize logic.
func newCLI(ctx context.Context) (*CLI, error) {
	cfg := config.Load()

	pin, err := readPIN()
	if err != nil {
		return nil, fmt.Errorf("reading PIN: %w", err)
	}

	ciph, err := crypto.NewCipher(cfg.KeyFile, cfg.KeyLength, pin, cfg.AddToIV)
	if err != nil {
		return nil, fmt.Errorf("initialising cipher: %w", err)
	}

	g := git.New(cfg.DataDir)

	st, err := store.New(&cfg, ciph, g)
	if err != nil {
		return nil, fmt.Errorf("initialising store: %w", err)
	}

	clip := clipboard.New(cfg.GnomeClipboardCmd, cfg.MacOSClipboardCmd)

	c := &CLI{
		cfg:      &cfg,
		st:       st,
		g:        g,
		clip:     clip,
		openKDBX: OpenKDBXStore,
		now:      time.Now,
	}

	// Create the shell with a completion function that references the CLI.
	// The completionFn must be defined after c is assigned so it can close
	// over c.
	sh, err := shell.New(c.completionFn)
	if err != nil {
		return nil, fmt.Errorf("initialising shell: %w", err)
	}
	c.sh = sh

	return c, nil
}

// readPIN returns the PIN string for encryption.  If the $PIN environment
// variable is set, it is used directly (matching the Ruby ENV['PIN'] check).
// Otherwise the user is prompted with masked input via the shell package.
func readPIN() (string, error) {
	if pin := os.Getenv("PIN"); pin != "" {
		return pin, nil
	}

	pin, err := shell.ReadPassword("< PIN: ")
	if err != nil {
		return "", fmt.Errorf("reading PIN from terminal: %w", err)
	}
	return pin, nil
}

// run dispatches a single command (when argv is non-empty and no shell flag is
// set) or enters the interactive shell loop.  Returns an exit code.
func (c *CLI) run(ctx context.Context, argv []string) int {
	// Enter shell mode when: no arguments, $FOOSTORE_SHELL is set, or the first
	// argument is "shell".  Mirrors the Ruby shell_loop entry conditions.
	enterShell := len(argv) == 0 ||
		os.Getenv("FOOSTORE_SHELL") != "" ||
		(len(argv) > 0 && argv[0] == "shell")

	if enterShell {
		return c.shellLoop(ctx)
	}

	return c.dispatch(ctx, argv)
}

// shellLoop runs the interactive readline loop, reading commands until the
// user presses Ctrl+D (EOF) or types "exit".  Mirrors Ruby#shell_loop.
// c.lastResult is updated by dispatch and accessible between iterations.
func (c *CLI) shellLoop(ctx context.Context) int {
	ec := 0
	logMsg("Interactive mode (vi keys): Ctrl-] for normal mode, i for insert | Enter fuzzy picker | ctrl-t/y/o/e (or alt-t/y/o/e) in picker")

	for {
		line, err := c.sh.ReadLine(ctx)
		if err == io.EOF {
			// Ctrl+D — clean exit.
			break
		}
		if err != nil {
			warn(fmt.Sprintf("readline error: %v", err))
			continue
		}

		argv := strings.Fields(line)
		if len(argv) == 0 {
			// Empty input — run fzf picker.
			result, fzfErr := c.st.FzfInteractive(ctx)
			if fzfErr != nil {
				warn(fzfErr.Error())
				continue
			}
			if result.Description != "" {
				c.lastResult = result.Description
				logMsg(fmt.Sprintf("Picked: %s", result.Description))
				ec = c.dispatchPickerAction(ctx, result)
			}
			continue
		}

		// Handle "last" before dispatch so c.lastResult is printed correctly.
		if argv[0] == "last" {
			fmt.Println(c.lastResult)
			continue
		}

		// "exit" ends the shell loop.
		if argv[0] == "exit" {
			logMsg("Good bye")
			break
		}

		ec = c.dispatch(ctx, argv)
	}

	return ec
}

func pickerActionArgv(action store.PickerAction, description string) []string {
	switch action {
	case store.PickerCat:
		return []string{"cat", description}
	case store.PickerPaste:
		return []string{"paste", description}
	case store.PickerOpen:
		return []string{"open", description}
	case store.PickerEdit:
		return []string{"edit", description}
	default:
		return nil
	}
}

func (c *CLI) dispatchPickerAction(ctx context.Context, result store.PickerResult) int {
	argv := pickerActionArgv(result.Action, result.Description)
	if len(argv) == 0 {
		return 0
	}
	return c.dispatch(ctx, argv)
}

// dispatch routes a parsed argv slice to the appropriate handler.
// It returns an exit code and updates c.lastResult when a non-empty result
// is produced. The function is split into helpers to keep each branch under
// ~50 lines.
func (c *CLI) dispatch(ctx context.Context, argv []string) int {
	if len(argv) == 0 {
		result, err := c.st.Fzf(ctx)
		if err != nil {
			warn(err.Error())
			return 1
		}
		if result != "" {
			c.lastResult = result
		}
		return 0
	}

	cmd := argv[0]

	// Commands handled by dispatchSimple (no search term needed).
	if ec, result, handled := c.dispatchSimple(ctx, argv, cmd); handled {
		if result != "" {
			c.lastResult = result
		}
		return ec
	}

	// Commands that require a search term (argv[1] or fallback to c.lastResult).
	ec, result := c.dispatchSearch(ctx, argv, cmd)
	if result != "" {
		c.lastResult = result
	}
	return ec
}

// dispatchSimple handles commands that don't require a search term:
// ls, add, import, import_r, sync, status, commit, reset, fullcommit,
// shred, version, commands, help, shell, exit, last, and the fzf fallback.
// Returns (exitCode, lastResult, handled).  handled=false when the command
// is not in this set and should fall through to dispatchSearch.
func (c *CLI) dispatchSimple(ctx context.Context, argv []string, cmd string) (int, string, bool) {
	switch cmd {
	case "ls":
		indexes, err := c.st.Search(ctx, ".", store.ActionNone, nil, printIndex)
		if err != nil {
			warn(err.Error())
			return 1, "", true
		}
		logMsg(fmt.Sprintf("%d entries", len(indexes)))
		return 0, "", true

	case "add":
		return c.cmdAdd(ctx, argv), "", true

	case "import":
		return c.cmdImport(ctx, argv), "", true

	case "import_r":
		return c.cmdImportR(ctx, argv), "", true

	case "sync":
		if err := c.g.Sync(ctx, c.cfg.SyncRepos); err != nil {
			warn(err.Error())
			return 1, "", true
		}
		return 0, "", true

	case "status":
		if err := c.g.Status(ctx); err != nil {
			warn(err.Error())
			return 1, "", true
		}
		return 0, "", true

	case "commit":
		if err := c.g.Commit(ctx); err != nil {
			warn(err.Error())
			return 1, "", true
		}
		return 0, "", true

	case "reset":
		if err := c.g.Reset(ctx); err != nil {
			warn(err.Error())
			return 1, "", true
		}
		return 0, "", true

	case "fullcommit":
		return c.cmdFullCommit(ctx), "", true

	case "shred":
		if err := c.st.ShredAllExported(ctx); err != nil {
			warn(err.Error())
			return 1, "", true
		}
		return 0, "", true

	case "migrate-kdbx":
		return c.cmdMigrateKDBX(ctx, argv), "", true

	case "version":
		logMsg(fmt.Sprintf("foostore %s", version.Version))
		return 0, "", true

	case "commands":
		for _, name := range CommandList {
			fmt.Println(name)
		}
		return 0, "", true

	case "help":
		printHelp()
		return 0, "", true

	case "shell":
		// When typed in the shell loop, "shell" is intercepted by run() before
		// dispatch is called, so this branch only fires in one-shot mode where
		// switching to interactive mode is not meaningful.  We print a notice and
		// exit cleanly rather than silently doing nothing.
		logMsg("Use foostore without arguments to enter interactive mode")
		return 0, "", true

	case "exit":
		logMsg("Good bye")
		return 0, "", true

	case "last":
		// In shell mode, "last" is handled before dispatch (shellLoop intercepts
		// it and prints c.lastResult directly).  In one-shot mode there is no
		// persistent lastResult, so we just print empty.
		fmt.Println(c.lastResult)
		return 0, "", true
	}

	// Not a simple command — let dispatchSearch handle it.
	return 0, "", false
}

// dispatchSearch handles commands that accept a search term: search, cat,
// paste, get, export, pathexport, open, edit, rm, and the catch-all.
// When no explicit term is supplied, c.lastResult is used as the fallback,
// mirroring Ruby's `search_term = argv.length < 2 ? last_result : argv[1]`.
func (c *CLI) dispatchSearch(ctx context.Context, argv []string, cmd string) (int, string) {
	term := c.lastResult // fallback to last search result when no term given
	if len(argv) > 1 {
		term = argv[1]
	}

	switch cmd {
	case "search":
		return c.cmdSearchOnly(ctx, term)

	case "get":
		// "get" is an alias for "cat".
		return c.cmdSearchAction(ctx, term, store.ActionCat, nil)

	case "rm":
		if err := c.st.Remove(ctx, term, os.Stdin); err != nil {
			warn(err.Error())
			return 1, ""
		}
		return 0, ""

	case "cat", "paste", "export", "pathexport", "open", "edit":
		action := SearchActions[cmd]
		actionFn := c.makeActionFn(ctx, action)
		return c.cmdSearchAction(ctx, term, action, actionFn)

	default:
		// Unknown command: treat as a search term, mirroring Ruby's else branch.
		// This allows bare search terms to be typed without prefixing "search".
		indexes, err := c.st.Search(ctx, cmd, store.ActionNone, nil, printIndex)
		if err != nil {
			warn(err.Error())
			return 1, ""
		}
		if len(indexes) > 0 {
			return 0, indexes[0].Description
		}
		return 0, ""
	}
}

// cmdAdd reads data from stdin and stores a new secret under the given description.
func (c *CLI) cmdAdd(ctx context.Context, argv []string) int {
	if len(argv) < 2 {
		warn("add requires a description argument")
		return 1
	}
	desc := argv[1]
	// Ruby uses log 'Data: ' which emits "> Data: \n" before reading stdin.
	logMsg("Data: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		warn("no data provided")
		return 1
	}
	data := scanner.Text()

	if err := c.st.Add(ctx, desc, data); err != nil {
		warn(err.Error())
		return 1
	}
	return 0
}

// cmdImport imports a single file into the store.
// argv: import FILE [DEST] [force]
//
// Ruby dest_path logic (from Geheim#import):
//   - No dest given: dest = normalised src_path (full path, "./" stripped)
//   - dest contains a ".": dest is used literally (it is already a full dest path)
//   - dest is a plain directory name: dest = "dir/basename(srcFile)"
func (c *CLI) cmdImport(ctx context.Context, argv []string) int {
	if len(argv) < 2 {
		warn("import requires a file argument")
		return 1
	}

	srcFile := argv[1]
	// Normalise source path the same way Ruby does.
	normSrc := strings.ReplaceAll(srcFile, "//", "/")
	normSrc = strings.TrimPrefix(normSrc, "./")

	dest := normSrc // default: full normalised path, matching Ruby's nil dest_dir branch
	force := false
	if len(argv) >= 3 {
		arg2 := argv[2]
		if arg2 == "force" {
			force = true
		} else if strings.Contains(arg2, ".") {
			// dest_dir contains a "." → use it as the literal dest path.
			dest = arg2
			force = len(argv) >= 4
		} else {
			// Plain directory: dest = dir/basename(src), as Ruby does.
			dest = arg2 + "/" + filepath.Base(srcFile)
			dest = strings.ReplaceAll(dest, "//", "/")
			force = len(argv) >= 4
		}
	}

	if err := c.st.Import(ctx, srcFile, dest, force); err != nil {
		warn(err.Error())
		return 1
	}
	return 0
}

// cmdImportR recursively imports all files in a directory.
// argv: import_r DIR [DEST]
func (c *CLI) cmdImportR(ctx context.Context, argv []string) int {
	if len(argv) < 2 {
		warn("import_r requires a directory argument")
		return 1
	}

	dir := argv[1]
	destDir := "." // default destination is the store root
	if len(argv) >= 3 {
		destDir = argv[2]
	}

	if err := c.st.ImportRecursive(ctx, dir, destDir); err != nil {
		warn(err.Error())
		return 1
	}
	return 0
}

// cmdFullCommit performs a sync → commit → sync sequence to ensure the local
// store is up-to-date before committing and then pushed afterwards.
func (c *CLI) cmdFullCommit(ctx context.Context) int {
	if err := c.g.Sync(ctx, c.cfg.SyncRepos); err != nil {
		warn(err.Error())
		return 1
	}
	if err := c.g.Commit(ctx); err != nil {
		warn(err.Error())
		return 1
	}
	if err := c.g.Sync(ctx, c.cfg.SyncRepos); err != nil {
		warn(err.Error())
		return 1
	}
	return 0
}

// cmdSearchOnly runs a search without any action and returns the result.
func (c *CLI) cmdSearchOnly(ctx context.Context, term string) (int, string) {
	indexes, err := c.st.Search(ctx, term, store.ActionNone, nil, printIndex)
	if err != nil {
		warn(err.Error())
		return 1, ""
	}
	if len(indexes) > 0 {
		return 0, indexes[0].Description
	}
	return 0, ""
}

// cmdSearchAction runs a search with the given action and optional callback.
func (c *CLI) cmdSearchAction(ctx context.Context, term string, action store.Action, actionFn func(context.Context, *store.Index, *store.Data) error) (int, string) {
	indexes, err := c.st.Search(ctx, term, action, actionFn, printIndex)
	if err != nil {
		warn(err.Error())
		return 1, ""
	}
	if len(indexes) > 0 {
		return 0, indexes[0].Description
	}
	return 0, ""
}

func printIndex(idx *store.Index) {
	fmt.Print(idx.String())
}

// makeActionFn returns the appropriate callback function for actions that
// require external tools (paste, open, edit).  For actions handled internally
// by the store (cat, export, pathexport), nil is returned.
func (c *CLI) makeActionFn(ctx context.Context, action store.Action) func(context.Context, *store.Index, *store.Data) error {
	switch action {
	case store.ActionPaste:
		return func(ctx context.Context, idx *store.Index, d *store.Data) error {
			if idx.IsBinary() {
				fmt.Println("Not displaying/pasting binary data!")
				return nil
			}
			return c.clip.Paste(ctx, string(d.Content))
		}

	case store.ActionOpen:
		return func(ctx context.Context, idx *store.Index, d *store.Data) error {
			exportName := filepath.Base(idx.Description)
			if err := d.Export(ctx, c.cfg.ExportDir, exportName); err != nil {
				return err
			}
			path, err := openExported(ctx, c.cfg.ExportDir, exportName)
			if err != nil {
				return err
			}
			// Shred the exported file immediately after opening — mirrors Ruby's
			// `shred_file(file: open_exported(...), delay: 0)` call.
			return store.ShredFile(ctx, path)
		}

	case store.ActionEdit:
		return func(ctx context.Context, idx *store.Index, d *store.Data) error {
			exportName := filepath.Base(idx.Description)
			if err := d.Export(ctx, c.cfg.ExportDir, exportName); err != nil {
				return err
			}
			if err := externalEdit(ctx, c.cfg.ExportDir, c.cfg.EditCmd, exportName); err != nil {
				return err
			}
			return d.ReimportAfterExport(ctx)
		}

	default:
		// cat, export, pathexport are handled directly by the store.
		return nil
	}
}

// completionFn returns all CommandList entries that start with prefix.
// When $PIN is set, it also includes index descriptions from the store,
// matching the Ruby setup_readline completion_proc behaviour.
func (c *CLI) completionFn(prefix string) []string {
	var results []string

	for _, cmd := range CommandList {
		if strings.HasPrefix(cmd, prefix) {
			results = append(results, cmd)
		}
	}

	// Include secret descriptions only when $PIN is set in the environment,
	// matching the Ruby completion_proc guard (`if ENV['PIN']`).  Note: users
	// who entered their PIN interactively (not via $PIN) will not get
	// description completion — this mirrors Ruby behaviour but means description
	// completion is only available when $PIN is used (which trades security for
	// convenience).
	if os.Getenv("PIN") != "" {
		ctx := context.Background()
		_ = c.st.WalkIndexes(ctx, "", func(idx *store.Index) error {
			desc := strings.SplitN(idx.Description, ";", 2)[0]
			desc = strings.TrimSpace(desc)
			if strings.HasPrefix(desc, prefix) {
				results = append(results, desc)
			}
			return nil
		})
	}

	return results
}

// openExported detects the current OS and opens the given file with an
// appropriate viewer.  The OS detection extends the Ruby reference with
// xdg-open for Linux (Ruby used evince), runtime.GOOS fallbacks, and
// additional iTerm/Termux heuristics.  Returns the full path on success.
func openExported(ctx context.Context, exportDir, file string) (string, error) {
	fullPath := filepath.Join(exportDir, file)

	var openCmd string
	switch {
	case os.Getenv("UNAME") == "Darwin" || runtime.GOOS == "darwin":
		openCmd = "open"
	case os.Getenv("TERM_PROGRAM") == "iTerm.app":
		openCmd = "open"
	case strings.Contains(os.Getenv("PREFIX"), "com.termux") || runtime.GOOS == "android":
		// Termux on Android.
		openCmd = "termux-open"
	case runtime.GOOS == "windows":
		openCmd = "winopen"
	default:
		// Linux: prefer xdg-open; fall back to evince for PDFs.
		openCmd = "xdg-open"
	}

	cmd := exec.CommandContext(ctx, openCmd, fullPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("opening %q with %q: %w", fullPath, openCmd, err)
	}
	return fullPath, nil
}

// externalEdit launches cfg.EditCmd on the exported file and waits for it to
// exit, then the caller can reimport the (possibly modified) file.
func externalEdit(ctx context.Context, exportDir, editCmd, file string) error {
	fullPath := filepath.Join(exportDir, file)
	cmd := exec.CommandContext(ctx, editCmd, fullPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editing %q with %q: %w", fullPath, editCmd, err)
	}
	return nil
}

// printHelp prints a brief usage summary, mirroring the Ruby CLI#help output.
func printHelp() {
	logMsg(`ls
SEARCHTERM
search SEARCHTERM
cat SEARCHTERM
get SEARCHTERM
add DESCRIPTION
export|pathexport|open|edit FILE
import FILE [DEST_DIRECTORY] [force]
import_r DIRECTORY [DEST_DIRECTORY]
rm SEARCHTERM
sync|status|commit|reset|fullcommit
shred
migrate-kdbx [--db PATH] [--pass-file PATH] [--binary-out PATH] [--dry-run]
version
commands
help
shell`)
}

// ---- Logging helpers (mirror Ruby Log module) --------------------------------

// logMsg prints a "> " prefixed message to stdout.
func logMsg(msg string) { fmt.Printf("> %s\n", msg) }

// warn prints a "WARN " prefixed message to stderr.
func warn(msg string) { fmt.Fprintf(os.Stderr, "WARN %s\n", msg) }
