// Package cli — command handler implementations.
//
// This file contains the concrete handler functions for each CLI command
// (add, import, import_r, fullcommit) and the action-function factory
// (makeActionFn) used by dispatchSearch for commands that invoke external
// tools (paste, open, edit).  Helper utilities for opening and editing
// exported files live here as well.
//
// Logging helpers (logMsg, warn) and printHelp are in cli.go.
// Dispatch routing is in cli_dispatch.go.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/snonux/foostore/internal/store"
)

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

	dest, force := resolveImportDest(argv, srcFile, normSrc)

	if err := c.st.Import(ctx, srcFile, dest, force); err != nil {
		warn(err.Error())
		return 1
	}
	return 0
}

// resolveImportDest derives the destination path and force flag from the
// import argv according to the Ruby dest_dir rules:
//   - No dest given: use the full normalised source path.
//   - dest contains ".": treat it as the full literal dest path.
//   - dest is a plain name: dest = "dir/basename(src)".
func resolveImportDest(argv []string, srcFile, normSrc string) (dest string, force bool) {
	dest = normSrc // default: full normalised path, matching Ruby's nil dest_dir branch
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
	return dest, force
}

// cmdAttach imports a file as a binary attachment on an existing parent entry.
// argv: attach FILE PARENT [NAME] [force]
//
// PARENT is the description of an existing text entry. NAME defaults to the
// basename of FILE. The destination path is PARENT/NAME, which the KeePass
// backend stores as a BinaryReference on the parent entry.
func (c *CLI) cmdAttach(ctx context.Context, argv []string) int {
	srcPath, destPath, force, err := resolveAttachArgs(argv)
	if err != nil {
		warn(err.Error())
		return 1
	}
	if err := c.st.Import(ctx, srcPath, destPath, force); err != nil {
		warn(err.Error())
		return 1
	}
	return 0
}

// resolveAttachArgs parses attach argv into source path, destination path, and
// force flag. PARENT is argv[2]; an optional NAME defaults to basename(FILE).
func resolveAttachArgs(argv []string) (srcPath, destPath string, force bool, err error) {
	if len(argv) < 3 {
		return "", "", false, fmt.Errorf("attach requires a file and parent entry argument")
	}
	srcPath = argv[1]
	parent := argv[2]
	var name string
	for i := 3; i < len(argv); i++ {
		switch argv[i] {
		case "force":
			force = true
		default:
			if name != "" {
				return "", "", false, fmt.Errorf("attach: unexpected argument %q", argv[i])
			}
			name = argv[i]
		}
	}
	if name == "" {
		name = filepath.Base(srcPath)
	}
	destPath = strings.TrimRight(parent, "/") + "/" + name
	destPath = strings.ReplaceAll(destPath, "//", "/")
	return srcPath, destPath, force, nil
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

// makeActionFn returns the appropriate callback function for actions that
// require external tools (paste, open, edit).  For actions handled internally
// by the store (cat, export, pathexport), nil is returned.
func (c *CLI) makeActionFn(ctx context.Context, action store.Action) func(context.Context, *store.Index, *store.Data) error {
	switch action {
	case store.ActionPaste:
		return c.makePasteActionFn()
	case store.ActionOpen:
		return c.makeOpenActionFn(ctx)
	case store.ActionEdit:
		return c.makeEditActionFn(ctx)
	default:
		// cat, export, pathexport are handled directly by the store.
		return nil
	}
}

// makePasteActionFn returns an action callback that pastes the decrypted
// content to the OS clipboard, skipping binary entries.
func (c *CLI) makePasteActionFn() func(context.Context, *store.Index, *store.Data) error {
	return func(ctx context.Context, idx *store.Index, d *store.Data) error {
		if idx.IsBinary() {
			fmt.Println("Not displaying/pasting binary data!")
			return nil
		}
		return c.clip.Paste(ctx, string(d.Content))
	}
}

// makeOpenActionFn returns an action callback that exports the entry to a
// temporary file, opens it with the OS-appropriate viewer, and then shreds the
// export immediately after the viewer exits.  The outer _ parameter is unused
// because the cfg reference is captured via the receiver.
func (c *CLI) makeOpenActionFn(_ context.Context) func(context.Context, *store.Index, *store.Data) error {
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
}

// makeEditActionFn returns an action callback that exports the entry, opens it
// in the configured editor, and reimports the (possibly modified) file when the
// editor exits.  The outer _ parameter is unused because cfg is captured via
// the receiver.
func (c *CLI) makeEditActionFn(_ context.Context) func(context.Context, *store.Index, *store.Data) error {
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
}

// openExported detects the current OS and opens the given file with an
// appropriate viewer.  The OS detection extends the Ruby reference with
// xdg-open for Linux (Ruby used evince), runtime.GOOS fallbacks, and
// additional iTerm/Termux heuristics.  Returns the full path on success.
func openExported(ctx context.Context, exportDir, file string) (string, error) {
	fullPath := filepath.Join(exportDir, file)

	openCmd := resolveOpenCmd()
	cmd := exec.CommandContext(ctx, openCmd, fullPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("opening %q with %q: %w", fullPath, openCmd, err)
	}
	return fullPath, nil
}

// resolveOpenCmd returns the OS-appropriate command for opening a file with
// its default application.  Checks environment variables first (UNAME, iTerm,
// Termux) before falling back to runtime.GOOS.
func resolveOpenCmd() string {
	switch {
	case os.Getenv("UNAME") == "Darwin" || runtime.GOOS == "darwin":
		return "open"
	case os.Getenv("TERM_PROGRAM") == "iTerm.app":
		return "open"
	case strings.Contains(os.Getenv("PREFIX"), "com.termux") || runtime.GOOS == "android":
		// Termux on Android.
		return "termux-open"
	case runtime.GOOS == "windows":
		return "winopen"
	default:
		// Linux: prefer xdg-open; fall back to evince for PDFs.
		return "xdg-open"
	}
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

// printIndex prints a single store index entry to stdout.  Used as the
// printFn callback for store.Search throughout the dispatch layer.
func printIndex(idx *store.Index) {
	fmt.Print(idx.String())
}
