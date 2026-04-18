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

	"codeberg.org/snonux/foostore/internal/backend"
	"codeberg.org/snonux/foostore/internal/clipboard"
	"codeberg.org/snonux/foostore/internal/config"
	"codeberg.org/snonux/foostore/internal/crypto"
	"codeberg.org/snonux/foostore/internal/git"
	"codeberg.org/snonux/foostore/internal/keepass"
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
//
// st is declared as backend.Backend (interface) rather than *store.Store
// (concrete type) so that alternative backends (e.g. KeePass) can be swapped
// in without touching the dispatch or shell-loop logic. The current geheim
// backend is *store.Store, which satisfies Backend via the compile-time check
// in internal/backend/backend.go.
//
// g is declared as git.Gitter (interface) rather than *git.Git so that the
// keepass backend can supply a git.NoOp when the kdbx file lives outside a git
// repository. Dispatch code requires no nil checks; it always calls through the
// interface regardless of whether real git operations or no-ops are performed.
//
// effectiveBackend is the resolved backend name (after applying the --backend
// flag override on top of cfg.Backend).  Guards such as cmdMigrateKDBX use
// this field so they reflect the actual runtime backend, not just the config file value.
type CLI struct {
	cfg              *config.Config
	st               backend.Backend
	g                git.Gitter // real *git.Git or *git.NoOp when kdbx is outside a repo
	clip             *clipboard.Clipboard
	sh               *shell.Shell
	openKDBX         func(string, string) (KDBXStore, error)
	now              func() time.Time
	lastResult       string // most recent search result description
	effectiveBackend string // resolved backend: --backend flag > cfg.Backend > "geheim"
}

// New initialises all runtime dependencies (config, PIN, cipher, store, git,
// clipboard, shell) and returns a ready-to-use CLI.  argv (typically
// os.Args[1:] after standard flags) is parsed for --backend and --kdbx-path
// flags before initialisation so the correct backend is instantiated from the
// start.  cmd/foostore/main.go calls New with a signal-cancellable context so
// that long-running operations (fzf, external editors) are interrupted cleanly
// on SIGINT/SIGTERM.
func New(ctx context.Context, argv []string) (*CLI, error) {
	backendName, _ := parseBackendFlag(argv)
	kdbxPath, _ := parseKDBXPathFlag(argv)
	return newCLI(ctx, backendName, kdbxPath)
}

// Run dispatches argv (typically os.Args[1:]) to the appropriate handler or
// enters the interactive shell loop.  The --backend and --kdbx-path flags are
// stripped from argv before dispatch because they were already consumed by New.
// Returns an exit code suitable for os.Exit.  The caller is responsible for
// calling sh.Close() when done; cmd/foostore/main.go does this via defer.
func (c *CLI) Run(ctx context.Context, argv []string) int {
	defer c.sh.Close()
	_, strippedArgv := parseBackendFlag(argv)
	_, strippedArgv = parseKDBXPathFlag(strippedArgv)
	return c.run(ctx, strippedArgv)
}

// parseBackendFlag scans argv for a "--backend VALUE" pair and returns the
// backend name and the remaining argv with that pair removed.  Returns ("", argv)
// when no --backend flag is present.  The flag may appear anywhere in argv.
//
// Note: only the space-separated form "--backend VALUE" is supported.
// The equals form "--backend=VALUE" is NOT parsed and will be silently ignored
// (treated as an unknown argument that propagates to the command dispatcher).
func parseBackendFlag(argv []string) (string, []string) {
	return parseFlagValue("--backend", argv)
}

// parseKDBXPathFlag scans argv for a "--kdbx-path VALUE" pair and returns the
// path and the remaining argv with that pair removed.  Returns ("", argv) when
// no --kdbx-path flag is present.  Overrides cfg.KDBXPath for the process
// lifetime without modifying the config file.
//
// Note: only the space-separated form "--kdbx-path VALUE" is supported.
func parseKDBXPathFlag(argv []string) (string, []string) {
	return parseFlagValue("--kdbx-path", argv)
}

// parseFlagValue is the shared implementation for single-value flag extraction.
// It scans argv for a "FLAG VALUE" pair, removes it, and returns the value and
// the remaining argv.  Returns ("", argv) when the flag is absent.
func parseFlagValue(flag string, argv []string) (string, []string) {
	for i, arg := range argv {
		if arg == flag && i+1 < len(argv) {
			remaining := make([]string, 0, len(argv)-2)
			remaining = append(remaining, argv[:i]...)
			remaining = append(remaining, argv[i+2:]...)
			return argv[i+1], remaining
		}
	}
	return "", argv
}

// newCLI initialises all dependencies: config, PIN/passphrase, cipher or
// keepass credentials, store or keepass backend, git, clipboard, and
// interactive shell.  backendName overrides cfg.Backend when non-empty
// (supplied from the --backend CLI flag); kdbxPath overrides cfg.KDBXPath when
// non-empty (supplied from the --kdbx-path CLI flag).  Empty strings mean "use
// the config file value".  Mirrors the Ruby CLI#initialize logic.
func newCLI(ctx context.Context, backendName, kdbxPath string) (*CLI, error) {
	cfg := config.Load()

	// Apply CLI flag overrides before building the backend.
	if kdbxPath != "" {
		cfg.KDBXPath = kdbxPath
	}

	// Resolve the effective backend: flag overrides config, config defaults to "geheim".
	effectiveBackend := resolveBackend(backendName, cfg.Backend)

	st, g, err := buildBackend(ctx, &cfg, effectiveBackend)
	if err != nil {
		return nil, err
	}

	clip := clipboard.New(cfg.GnomeClipboardCmd, cfg.MacOSClipboardCmd)

	c := &CLI{
		cfg:              &cfg,
		st:               st,
		g:                g,
		clip:             clip,
		openKDBX:         OpenKDBXStore,
		now:              time.Now,
		effectiveBackend: effectiveBackend,
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

// resolveBackend returns the effective backend name given the flag override and
// the config value.  flag takes precedence; config value is used next; the
// last-resort default is "keepass" (matching the config.defaultConfigWithHome
// default so that the two sources of truth stay in sync).
func resolveBackend(flagValue, cfgValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if cfgValue != "" {
		return cfgValue
	}
	return "keepass"
}

// buildBackend constructs the Backend and its associated Gitter based on
// effectiveBackend ("geheim" or "keepass").  Returns the Backend and git client
// so the caller can wire them into the CLI struct.
func buildBackend(ctx context.Context, cfg *config.Config, effectiveBackend string) (backend.Backend, git.Gitter, error) {
	switch effectiveBackend {
	case "keepass":
		return buildKeepassBackend(ctx, cfg)
	default:
		return buildGeheimBackend(cfg)
	}
}

// buildGeheimGit returns a *git.Git pointed at cfg.DataDir.  The geheim data
// directory is always a git repository (it is the store itself), so a real
// git client is always appropriate here — unlike the keepass backend which
// may live outside a repo and needs a NoOp fallback.
func buildGeheimGit(cfg *config.Config) git.Gitter {
	return git.New(cfg.DataDir)
}

// buildGeheimBackend initialises the original AES-encrypted geheim backend:
// reads the PIN, builds the cipher, creates a *store.Store, and points git at
// cfg.DataDir via buildGeheimGit.
func buildGeheimBackend(cfg *config.Config) (backend.Backend, git.Gitter, error) {
	pin, err := readPIN()
	if err != nil {
		return nil, nil, fmt.Errorf("reading PIN: %w", err)
	}

	ciph, err := crypto.NewCipher(cfg.KeyFile, cfg.KeyLength, pin, cfg.AddToIV)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising cipher: %w", err)
	}

	g := buildGeheimGit(cfg)

	st, err := store.New(cfg, ciph, g)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising store: %w", err)
	}

	return st, g, nil
}

// buildKeepassBackend reads the KeePass passphrase and optional key-file bytes,
// then instantiates a keepass.Backend.  The git client is pointed at the
// directory that contains the .kdbx file.
//
// If that directory is a git repository (detected via git rev-parse
// --is-inside-work-tree), a real *git.Git is returned so that sync/status/
// commit/reset operate normally against it.  If the directory is not a git
// repository, a *git.NoOp is returned instead — its methods print an
// informational message ("kdbx file is not in a git repo; skipping") and return
// nil, keeping the UX transparent without crashing.
func buildKeepassBackend(ctx context.Context, cfg *config.Config) (backend.Backend, git.Gitter, error) {
	passphrase, err := readKeepassPassphrase(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("reading keepass passphrase: %w", err)
	}

	keyFileData, err := readKeepassKeyFile(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("reading keepass key file: %w", err)
	}

	st, err := keepass.New(cfg, passphrase, keyFileData)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising keepass backend: %w", err)
	}

	g := buildKeepassGit(cfg.KDBXPath)
	return st, g, nil
}

// buildKeepassGit returns the appropriate Gitter for the directory containing
// the kdbx file.  When the directory is a git repository, a real *git.Git is
// returned.  Otherwise, a *git.NoOp is returned so that callers receive
// informational messages rather than errors when running git commands.
func buildKeepassGit(kdbxPath string) git.Gitter {
	kdbxDir := filepath.Dir(kdbxPath)
	if git.IsGitRepo(kdbxDir) {
		return git.New(kdbxDir)
	}
	return git.NewNoOp()
}

// readKeepassPassphrase resolves the KeePass database passphrase using the
// following priority: $PIN env var → cfg.KDBXPassFile → interactive prompt.
// This mirrors the geheim readPIN() priority while accommodating the extra
// KDBXPassFile option specific to the keepass backend.
func readKeepassPassphrase(cfg *config.Config) (string, error) {
	// 1. $PIN environment variable — same as geheim backend for symmetry.
	if pin := os.Getenv("PIN"); pin != "" {
		return pin, nil
	}

	// 2. KDBXPassFile — a file containing the password (trimmed of newlines).
	if cfg.KDBXPassFile != "" {
		pass, err := readPasswordFile(cfg.KDBXPassFile)
		if err != nil {
			return "", fmt.Errorf("reading KDBXPassFile: %w", err)
		}
		return pass, nil
	}

	// 3. Interactive prompt — same mechanism as geheim's PIN prompt.
	pass, err := shell.ReadPassword("< KeePass passphrase: ")
	if err != nil {
		return "", fmt.Errorf("reading passphrase from terminal: %w", err)
	}
	return pass, nil
}

// readKeepassKeyFile reads the optional KeePass key-file bytes.  Returns nil
// when cfg.KDBXKeyFile is empty (password-only authentication).
func readKeepassKeyFile(cfg *config.Config) ([]byte, error) {
	if cfg.KDBXKeyFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(cfg.KDBXKeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", cfg.KDBXKeyFile, err)
	}
	return data, nil
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
	logMsg(`Global flags (must appear before the command):
  --backend geheim|keepass   select backend (overrides config)
  --kdbx-path PATH           path to .kdbx file (overrides config, keepass only)

Commands:
ls
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
