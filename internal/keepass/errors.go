// Package keepass — machine-facing error classes.
//
// This file defines the sentinel errors that the machine-facing read path
// (internal/cli Read command) maps onto distinct exit codes. Gonf, the
// primary machine consumer, may suppress only ErrNotFound; every other class
// must surface.
package keepass

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	// ErrNotFound reports that an entry, attachment, or field does not
	// exist. This is the only class machine consumers are allowed to
	// suppress (optional lookups).
	ErrNotFound = errors.New("keepass: not found")

	// ErrAmbiguous reports that an exact description matches more than one
	// entry; consumers must never guess between duplicates.
	ErrAmbiguous = errors.New("keepass: ambiguous entry identity")

	// ErrLocked reports that the database could not be unlocked: wrong
	// credentials, or corruption that trips the same wrong-password check
	// (KDBX 3.1 fails the stream-start integrity check, KDBX 4 the header
	// HMAC; wrong credentials are the dominant real-world cause).
	ErrLocked = errors.New("keepass: database locked or credentials rejected")

	// ErrCorrupt reports a store that cannot be parsed: bad signature,
	// broken headers, truncation, undecodable XML, block HMAC failures, or a
	// dangling attachment reference.
	ErrCorrupt = errors.New("keepass: database corrupt or unreadable")

	// ErrIO reports store access failures (missing file, permission
	// denied, read errors). A missing store is an I/O problem, not an
	// absent secret: suppressing it would hide a configuration mistake.
	ErrIO = errors.New("keepass: store I/O error")

	// ErrInvalidSelection reports a request that cannot be answered as
	// asked: empty or unsafe references, a field on an attachment
	// reference, or a missing field name on an entry reference. Callers treat
	// this as a usage error, not a store problem.
	ErrInvalidSelection = errors.New("keepass: invalid field or attachment selection")

	// ErrFieldOnAttachment identifies an attachment selected with a field.
	ErrFieldOnAttachment = errors.New("keepass: attachment does not have fields")

	// ErrMissingField identifies an entry selected without a field name.
	ErrMissingField = errors.New("keepass: entry field name required")
)

// classifyOpenError maps a KeePass database open/decode failure onto the
// machine-facing error classes. The mapping is empirical for gokeepasslib v3:
// wrong credentials fail with a "Wrong password?" error — the stream-start
// integrity check for KDBX 3.1 and the header HMAC for KDBX 4 — so that
// marker is classified as locked/credentials, the dominant real-world cause.
// Genuine header damage reports the same way for KDBX 4; neither class is
// suppressible, so the ambiguity has no caller-facing impact. Filesystem
// failures keep their ErrIO class. Every other open failure (bad signature,
// truncation, block HMAC mismatch, undecodable payload, a recovered decoder
// panic) is treated as corruption: the store is unusable in a way the caller
// must surface, never suppress.
func classifyOpenError(err error) error {
	if err == nil {
		return nil
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("%w: %v", ErrIO, err)
	}
	if strings.Contains(err.Error(), "Wrong password?") {
		return fmt.Errorf("%w: %v", ErrLocked, err)
	}
	return fmt.Errorf("%w: %v", ErrCorrupt, err)
}
