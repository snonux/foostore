// Package cli implements the command-line interface for foostore.
// It mirrors the Ruby CLI class (geheim.rb lines 551-713): parsing argv,
// dispatching commands, and running an optional interactive readline shell.
// Run() is the top-level entry point called by cmd/foostore/main.go.
//
// Responsibilities are split across several files to keep each focused:
//   - cli.go          — CLI struct, constructors (New/newCLI), Run, shell completion, logging helpers
//   - cli_flags.go    — argv flag parsing (parseBackendFlag, parseKDBXPathFlag, parseFlagValue)
//   - cli_backend.go  — backend factory (buildBackend, buildGeheimBackend, buildKeepassBackend, ...)
//   - cli_dispatch.go — shell loop (shellLoop) and command dispatcher (dispatch, dispatchSimple, dispatchSearch)
//   - cli_commands.go — concrete command handlers (cmdAdd, cmdImport, …) and action-function factories
//   - cli_fish.go     — fish subcommand: generates fish shell integration script (completions + ge wrapper)
//   - cli_paths.go    — shared path utilities (readPasswordFile, resolveHomeDir, expandHome)
//   - migrate_kdbx.go — thin CLI handler for migrate-kdbx; delegates logic to internal/migrate
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/snonux/foostore/internal/backend"
	"github.com/snonux/foostore/internal/clipboard"
	"github.com/snonux/foostore/internal/config"
	"github.com/snonux/foostore/internal/migrate"
	"github.com/snonux/foostore/internal/shell"
	"github.com/snonux/foostore/internal/store"
)

// CommandList is the canonical list of supported commands, ordered to match
// the Ruby COMMANDS constant exactly.  Used for tab-completion and `commands`.
var CommandList = []string{
	"ls", "search", "cat", "paste", "get", "add", "export", "pathexport",
	"open", "edit", "import", "import_r", "attach", "rm", "sync", "status", "commit",
	"reset", "fullcommit", "shred", "migrate-kdbx", "fish", "version", "commands", "help", "shell",
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
// g is declared as Gitter (defined in git.go in this package) rather than
// *git.Git so that the keepass backend can supply a *git.NoOp when the kdbx
// file lives outside a git repository. Dispatch code requires no nil checks;
// it always calls through the interface regardless of whether real git
// operations or no-ops are performed.
//
// effectiveBackend is the resolved backend name (after applying the --backend
// flag override on top of cfg.Backend).  Guards such as cmdMigrateKDBX use
// this field so they reflect the actual runtime backend, not just the config file value.
type CLI struct {
	cfg              *config.Config
	st               backend.Backend
	g                Gitter // real *git.Git or *git.NoOp when kdbx is outside a repo
	clip             *clipboard.Clipboard
	sh               *shell.Shell
	openKDBX         func(string, string) (migrate.KDBXStore, error)
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
		openKDBX:         migrate.OpenKDBXStore,
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

// ---- Logging helpers (mirror Ruby Log module) --------------------------------

// logMsg prints a "> " prefixed message to stdout.
// Placed above printHelp for readability; Go resolves package-level names across the whole file.
func logMsg(msg string) { fmt.Printf("> %s\n", msg) }

// warn prints a "WARN " prefixed message to stderr.
// Placed above printHelp for readability; Go resolves package-level names across the whole file.
func warn(msg string) { fmt.Fprintf(os.Stderr, "WARN %s\n", msg) }

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
attach FILE PARENT [NAME] [force]
rm SEARCHTERM
sync|status|commit|reset|fullcommit
shred
migrate-kdbx [--db PATH] [--pass-file PATH] [--binary-out PATH] [--dry-run]
fish
version
commands
help
shell`)
}
