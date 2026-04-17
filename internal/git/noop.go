package git

import (
	"context"
	"fmt"
)

// noOpMessage is the message printed whenever a git operation is skipped
// because the kdbx file is not inside a git repository.
const noOpMessage = "kdbx file is not in a git repo; skipping"

// NoOp is a Gitter implementation whose every method prints an informational
// message and returns nil. It is used when the KeePass database file lives
// outside of a git repository so that sync/status/commit/reset commands remain
// functional and transparent rather than crashing or returning errors.
//
// Keeping the no-op behaviour in its own type (rather than nil-checking in the
// CLI dispatch) respects the Open/Closed Principle: the CLI is open for
// extension (new backends, new git behaviours) without modification.
type NoOp struct{}

// Compile-time assertion: *NoOp must satisfy Gitter.
var _ Gitter = (*NoOp)(nil)

// NewNoOp returns a *NoOp that satisfies Gitter with all operations being
// informational no-ops.
func NewNoOp() *NoOp {
	return &NoOp{}
}

// Add prints the no-op message and returns nil.
func (n *NoOp) Add(_ context.Context, _ string) error {
	fmt.Printf("> %s\n", noOpMessage)
	return nil
}

// Remove prints the no-op message and returns nil.
func (n *NoOp) Remove(_ context.Context, _ string) error {
	fmt.Printf("> %s\n", noOpMessage)
	return nil
}

// Status prints the no-op message and returns nil.
func (n *NoOp) Status(_ context.Context) error {
	fmt.Printf("> %s\n", noOpMessage)
	return nil
}

// Commit prints the no-op message and returns nil.
func (n *NoOp) Commit(_ context.Context) error {
	fmt.Printf("> %s\n", noOpMessage)
	return nil
}

// Reset prints the no-op message and returns nil.
func (n *NoOp) Reset(_ context.Context) error {
	fmt.Printf("> %s\n", noOpMessage)
	return nil
}

// Sync prints the no-op message and returns nil.
func (n *NoOp) Sync(_ context.Context, _ []string) error {
	fmt.Printf("> %s\n", noOpMessage)
	return nil
}
