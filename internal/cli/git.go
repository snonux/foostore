// Package cli — git abstraction for the CLI layer.
//
// This file defines the Gitter interface, which the CLI uses to abstract over
// real git operations (*git.Git) and no-op stubs (*git.NoOp).  The interface
// lives here in the consumer package (internal/cli) rather than in the
// producer package (internal/git), following Go best practice #6 from
// "100 Go Mistakes": interfaces should be defined where they are used, not
// where they are implemented.
//
// Keeping the interface here avoids tight coupling between internal/git and its
// callers: internal/git does not need to know who depends on it, and new
// consumers can define their own narrower interfaces as needed.
package cli

import (
	"context"

	"github.com/snonux/foostore/internal/git"
)

// Gitter abstracts git operations so that the CLI dispatch logic works
// identically whether backed by a real git repository (*git.Git) or a no-op
// stub (*git.NoOp — used when the KeePass database file lives outside a repo).
type Gitter interface {
	// Add stages a single file for the next commit.
	Add(ctx context.Context, filePath string) error

	// Remove stages a file deletion for the next commit.
	Remove(ctx context.Context, filePath string) error

	// Status prints the current git status of the working directory.
	Status(ctx context.Context) error

	// Commit records all staged changes with a generic commit message.
	Commit(ctx context.Context) error

	// Reset discards all uncommitted changes in the working directory.
	Reset(ctx context.Context) error

	// Sync pulls from and pushes to each configured remote repository.
	Sync(ctx context.Context, syncRepos []string) error
}

// Compile-time assertions: both concrete git types must satisfy Gitter.
// These assertions live in the consumer (cli), not the producer (git),
// so that internal/git remains free of any dependency on this package.
var _ Gitter = (*git.Git)(nil)
var _ Gitter = (*git.NoOp)(nil)
