// Package backend defines the Backend interface that the CLI uses to interact
// with a secret store. Introducing this abstraction (Dependency Inversion
// Principle) allows the CLI to be decoupled from the concrete *store.Store
// type and makes it possible to add alternative backends (e.g. KeePass) without
// touching any CLI code.
//
// The types used in method signatures (store.Index, store.Data, store.Action,
// store.PickerResult) remain in the store package; they are cross-backend value
// types that carry no storage-implementation knowledge.
package backend

import (
	"context"
	"io"

	"codeberg.org/snonux/foostore/internal/store"
)

// Backend is the narrow interface that the CLI calls on a secret store.
// Every method mirrors its counterpart on *store.Store — no method bodies
// change; only the CLI's field type changes from *store.Store to Backend.
//
// Interface segregation note: this is intentionally a single interface because
// the CLI treats the store as one cohesive unit. If future backends need to
// opt out of specific operations (e.g. a read-only backend), those methods can
// return a descriptive error rather than splitting the interface prematurely.
type Backend interface {
	// WalkIndexes iterates over every index entry whose description matches
	// searchTerm (empty matches all) and calls fn for each one.
	WalkIndexes(ctx context.Context, searchTerm string, fn func(*store.Index) error) error

	// LoadData decrypts and returns the data payload for the given index entry.
	LoadData(ctx context.Context, idx *store.Index) (*store.Data, error)

	// Search collects all indexes matching searchTerm, sorts them, applies action
	// to each, and returns the sorted list. The optional actionFn is called for
	// actions that require external tools (paste, open, edit); pass nil when not
	// needed. The optional onMatch is called for each match before applying action.
	Search(
		ctx context.Context,
		searchTerm string,
		action store.Action,
		actionFn func(context.Context, *store.Index, *store.Data) error,
		onMatch func(*store.Index),
	) ([]*store.Index, error)

	// Add stores a new secret with the given description and plaintext data.
	Add(ctx context.Context, description, data string) error

	// Import reads a file from srcPath and stores it under destPath.
	// force=true overwrites an existing entry; false skips silently.
	Import(ctx context.Context, srcPath, destPath string, force bool) error

	// ImportRecursive imports every regular file under directory into destDir.
	ImportRecursive(ctx context.Context, directory, destDir string) error

	// Remove finds all indexes matching searchTerm and prompts the user via input
	// before deleting each matching entry.
	Remove(ctx context.Context, searchTerm string, input io.Reader) error

	// Fzf launches the fzf picker and returns only the selected description.
	Fzf(ctx context.Context) (string, error)

	// FzfInteractive launches the fzf picker with action key bindings and returns
	// both the selected description and the chosen action.
	FzfInteractive(ctx context.Context) (store.PickerResult, error)

	// ShredAllExported securely deletes every file in the export directory.
	ShredAllExported(ctx context.Context) error
}

// Ensure *store.Store satisfies Backend at compile time.
// This line is the single source of truth that the concrete type and the
// interface stay in sync without requiring any runtime check.
var _ Backend = (*store.Store)(nil)
