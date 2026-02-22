// main is the thin entry point for the foostore binary.
// It handles the -version flag, sets up a signal-cancellable context,
// initialises the CLI, and exits with the code returned by Run.
// All command logic lives in internal/cli.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"codeberg.org/snonux/foostore/internal/cli"
	"codeberg.org/snonux/foostore/internal/version"
)

func main() {
	// -version prints the build version and exits immediately.
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Version)
		os.Exit(0)
	}

	// Cancel the context on SIGINT or SIGTERM so that long-running operations
	// (fzf, external editors) terminate gracefully rather than being killed hard.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c, err := cli.New(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL %v\n", err)
		os.Exit(3)
	}

	// flag.Args() returns arguments after flags, so flag-aware invocations
	// like `foostore -version` work while plain `foostore cat foo` still passes
	// all args through unchanged.
	os.Exit(c.Run(ctx, flag.Args()))
}
