// Package cli — shell loop and command dispatcher.
//
// This file implements the interactive readline shell loop (shellLoop) and the
// two-tier command dispatcher (dispatch → dispatchSimple | dispatchSearch).
// It intentionally contains no flag parsing or backend construction; those
// responsibilities live in cli_flags.go and cli_backend.go respectively.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/snonux/foostore/internal/store"
	"github.com/snonux/foostore/internal/version"
)

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
			break // Ctrl+D — clean exit.
		}
		if err != nil {
			warn(fmt.Sprintf("readline error: %v", err))
			continue
		}

		argv := strings.Fields(line)
		if len(argv) == 0 {
			ec = c.handleEmptyInput(ctx)
			continue
		}

		// "last" and "exit" are intercepted before dispatch.
		if argv[0] == "last" {
			fmt.Println(c.lastResult)
			continue
		}
		if argv[0] == "exit" {
			logMsg("Good bye")
			break
		}

		ec = c.dispatch(ctx, argv)
	}

	return ec
}

// handleEmptyInput handles an empty input line in the shell loop by running
// the fzf picker.  Updates c.lastResult when a selection is made and
// dispatches the chosen picker action.  Returns an exit code.
func (c *CLI) handleEmptyInput(ctx context.Context) int {
	result, fzfErr := c.st.FzfInteractive(ctx)
	if fzfErr != nil {
		warn(fzfErr.Error())
		return 1
	}
	if result.Description != "" {
		c.lastResult = result.Description
		logMsg(fmt.Sprintf("Picked: %s", result.Description))
		return c.dispatchPickerAction(ctx, result)
	}
	return 0
}

// pickerActionArgv maps a picker action to the argv slice for dispatch.
// Returns nil for actions that do not map to a CLI command (e.g. PickerSelect).
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

// dispatchPickerAction converts a PickerResult into an argv and dispatches it.
// Returns 0 for picker actions that have no CLI command equivalent.
func (c *CLI) dispatchPickerAction(ctx context.Context, result store.PickerResult) int {
	argv := pickerActionArgv(result.Action, result.Description)
	if len(argv) == 0 {
		return 0
	}
	return c.dispatch(ctx, argv)
}

// dispatch routes a parsed argv slice to the appropriate handler.
// It returns an exit code and updates c.lastResult when a non-empty result
// is produced.  The function delegates to dispatchSimple and dispatchSearch.
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

// dispatchSimple handles commands that don't require a search term.
// Returns (exitCode, lastResult, handled).  handled=false means the command
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
		return c.dispatchGitOp(func() error { return c.g.Sync(ctx, c.cfg.SyncRepos) })
	case "status":
		return c.dispatchGitOp(func() error { return c.g.Status(ctx) })
	case "commit":
		return c.dispatchGitOp(func() error { return c.g.Commit(ctx) })
	case "reset":
		return c.dispatchGitOp(func() error { return c.g.Reset(ctx) })
	case "fullcommit":
		return c.cmdFullCommit(ctx), "", true
	case "shred":
		return c.dispatchGitOp(func() error { return c.st.ShredAllExported(ctx) })
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
	case "fish":
		// Print the fish shell integration script to stdout so users can source it:
		//   foostore fish | source
		return c.cmdFish(os.Stdout), "", true
	case "help":
		printHelp()
		return 0, "", true
	case "shell":
		// When typed in the shell loop, "shell" is intercepted by run() before
		// dispatch is called, so this branch only fires in one-shot mode where
		// switching to interactive mode is not meaningful.
		logMsg("Use foostore without arguments to enter interactive mode")
		return 0, "", true
	case "exit":
		logMsg("Good bye")
		return 0, "", true
	case "last":
		// In shell mode "last" is intercepted by shellLoop; in one-shot mode
		// there is no persistent lastResult, so we print the zero value.
		fmt.Println(c.lastResult)
		return 0, "", true
	}

	// Not a simple command — let dispatchSearch handle it.
	return 0, "", false
}

// dispatchGitOp is a small adapter that wraps a no-argument git (or store)
// operation into the (exitCode, lastResult, handled) triple expected by
// dispatchSimple.  Prints a warning and returns exit code 1 on error.
// The context.Context parameter is omitted entirely: each op closure already
// captures ctx from its call site in dispatchSimple, so no forwarding is needed.
func (c *CLI) dispatchGitOp(op func() error) (int, string, bool) {
	if err := op(); err != nil {
		warn(err.Error())
		return 1, "", true
	}
	return 0, "", true
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
		return c.cmdSearchAction(ctx, term, action, c.makeActionFn(ctx, action))
	default:
		// Unknown command: treat as a search term, mirroring Ruby's else branch.
		// This allows bare search terms to be typed without prefixing "search".
		return c.cmdSearchFallback(ctx, cmd)
	}
}

// cmdSearchFallback treats an unrecognised command as a search term.  This
// mirrors the Ruby else branch in dispatch and allows users to type bare
// search terms in the shell loop.
func (c *CLI) cmdSearchFallback(ctx context.Context, term string) (int, string) {
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
