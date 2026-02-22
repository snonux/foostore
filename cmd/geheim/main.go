// main is the thin entry point for the geheim binary.
// It sets up a signal-cancellable context, initialises the CLI, and exits
// with the code returned by Run.  All command logic lives in internal/cli.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"codeberg.org/snonux/geheim/internal/cli"
)

func main() {
	// Cancel the context on SIGINT or SIGTERM so that long-running operations
	// (fzf, external editors) terminate gracefully rather than being killed hard.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c, err := cli.New(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL %v\n", err)
		os.Exit(3)
	}

	os.Exit(c.Run(ctx, os.Args[1:]))
}
