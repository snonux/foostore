// main is the thin entry point for the foostore binary.
// It handles the -version flag, sets up a signal-cancellable context,
// initialises the CLI, and exits with the code returned by Run.
// All command logic lives in internal/cli.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"codeberg.org/snonux/foostore/internal/cli"
	"codeberg.org/snonux/foostore/internal/version"
)

func main() {
	args := os.Args[1:]

	// Handle -version / --version before passing args to the CLI so that
	// `foostore -version` exits early without initialising any backend.
	// We check manually rather than using flag.Parse() because that package
	// rejects unknown flags (e.g. --backend, --kdbx-path) before the CLI
	// dispatcher gets a chance to handle them.
	if len(args) == 1 && (args[0] == "-version" || args[0] == "--version") {
		fmt.Println(version.Version)
		os.Exit(0)
	}

	// Short-circuit the "fish" subcommand: it emits a purely static shell
	// integration script and needs no backend, cipher, store, git, or shell
	// initialisation.  Skipping cli.New avoids the KeePass Argon2 KDF cost
	// (~1.8s), which makes every interactive fish shell startup that sources
	// `foostore fish | source` correspondingly faster.
	if len(args) == 1 && args[0] == "fish" {
		binaryPath, err := os.Executable()
		if err != nil {
			binaryPath = "foostore"
		}
		fmt.Print(cli.FishIntegrationScript(binaryPath))
		os.Exit(0)
	}

	// Cancel the context on SIGINT or SIGTERM so that long-running operations
	// (fzf, external editors) terminate gracefully rather than being killed hard.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Pass all args to the CLI. New parses --backend and --kdbx-path from them
	// to select the backend at init time; Run strips those flags before dispatch.
	c, err := cli.New(ctx, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL %v\n", err)
		os.Exit(3)
	}

	os.Exit(c.Run(ctx, args))
}
