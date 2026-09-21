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

	"github.com/snonux/foostore/internal/cli"
	"github.com/snonux/foostore/internal/version"
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
	// (fzf, external editors, machine reads) terminate gracefully rather than
	// being killed hard.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Short-circuit the machine-facing "read" subcommand before any
	// interactive initialisation; see runMachineRead.
	if readArgs, isRead, err := cli.MachineReadArgs(args); isRead {
		os.Exit(runMachineRead(ctx, readArgs, err))
	}

	// Pass all args to the CLI. New parses --backend and --kdbx-path from them
	// to select the backend at init time; Run strips those flags before dispatch.
	c, err := cli.New(ctx, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL %v\n", err)
		os.Exit(3)
	}

	os.Exit(c.Run(ctx, args))
}

// runMachineRead runs the machine-facing "read" command and returns its exit
// code. It must bypass the interactive CLI initialisation entirely so that no
// prompt, shell, clipboard, fzf, or git sync can be inherited, and so its
// distinct exit codes survive. The command is detected after any flags (see
// cli.MachineReadArgs), so a flag-first or mis-ordered invocation cannot fall
// through into the interactive initialisation. invocationErr is a usage
// problem MachineReadArgs already found.
func runMachineRead(ctx context.Context, readArgs []string, invocationErr error) int {
	if invocationErr != nil {
		fmt.Fprintf(os.Stderr, "foostore read: %v\n", invocationErr)
		return cli.ReadExitUsage
	}
	// A consumer that closes its end early must get the documented I/O exit
	// code, not a SIGPIPE death: with SIGPIPE ignored the stdout write fails
	// with EPIPE instead.
	signal.Ignore(syscall.SIGPIPE)
	return cli.Read(ctx, readArgs)
}
