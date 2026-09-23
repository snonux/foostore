// Package cli — machine-facing `foostore read` command.
//
// These files implement the exact, raw, non-interactive read contract used by
// machine consumers (Gonf in particular): one exact entry reference, one
// explicit field or attachment selection, exact bytes on stdout, and distinct
// exit codes for every failure class. It deliberately bypasses the
// interactive CLI initialisation (no shell, no prompt, no clipboard, no fzf,
// no export, no git): a machine read either produces the requested bytes or a
// classified failure.
//
// Exit-code contract (documented in README.md and readUsage):
//
//	0 success — stdout contains exactly the requested bytes
//	1 unexpected runtime failure (including timeouts and signal cancellation)
//	2 usage error (bad flags, missing reference, invalid selection)
//	4 not found — the only code a machine consumer may suppress
//	5 ambiguous — the exact identity matches more than one entry
//	6 locked — credentials rejected, missing, or unusable
//	7 corrupt — the store cannot be parsed
//	8 store I/O failure — including a missing database file
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/snonux/foostore/internal/config"
	"github.com/snonux/foostore/internal/keepass"
)

// Machine-facing read exit codes.
const (
	readExitUsage     = 2
	readExitNotFound  = 4
	readExitAmbiguous = 5
	readExitLocked    = 6
	readExitCorrupt   = 7
	readExitIO        = 8
)

// readDefaultTimeout bounds a machine read: opening a .kdbx involves the KDF
// and file I/O that can hang on a stuck mount. Scripts override it with
// --timeout.
const readDefaultTimeout = 30 * time.Second

// ReadExitUsage lets the entry point report an invocation problem found before Read ran.
const ReadExitUsage = readExitUsage

// readFlags holds the parsed machine-read invocation.
type readFlags struct {
	reference string
	field     string
	timeout   time.Duration
	backend   string
	kdbxPath  string
}

// Read executes the machine-facing read command and returns the process exit
// code. It is short-circuited in cmd/foostore/main.go before the interactive
// CLI initialisation, so FOOSTORE_SHELL and other interactive overrides can
// never turn a machine read into a shell or a prompt.
func Read(ctx context.Context, argv []string) int {
	return readCommand(ctx, argv, os.Stdout)
}

// readCommand implements Read against an injectable stdout so tests can
// capture the exact output bytes. Diagnostics always go to stderr; stdout
// carries only the requested bytes.
func readCommand(ctx context.Context, argv []string, stdout io.Writer) int {
	if wantsReadHelp(argv) {
		// Help is the one non-secret payload allowed on stdout.
		_, _ = fmt.Fprintln(stdout, readUsage)
		return 0
	}
	opts, err := parseReadFlags(argv)
	if err != nil {
		return readUsagef("%s", err)
	}

	// The bound starts before anything can block — including reading the
	// config file, which may sit on a stalled mount or be a FIFO.
	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	cfg, code := loadReadConfig(ctx, opts)
	if code != 0 {
		return code
	}
	return executeRead(ctx, &cfg, opts, stdout)
}

// boundedCall runs fn in a goroutine and stops waiting when ctx ends. The call
// itself cannot be interrupted (file reads take no context), so an abandoned
// one is left to die with the process, which exits right after a bound hit.
func boundedCall[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// ctxFailure reports a timeout or signal cancellation that ended the read at
// the named stage and returns its exit code; ok is false when err is neither.
func ctxFailure(err error, timeout time.Duration, stage string) (code int, ok bool) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return readFail(1, fmt.Errorf("read timed out after %s while %s", timeout, stage)), true
	case errors.Is(err, context.Canceled):
		return readFail(1, fmt.Errorf("read cancelled by signal while %s", stage)), true
	}
	return 0, false
}

// loadReadConfig loads and validates the configuration for one machine read.
// A non-zero code means the failure was already reported on stderr.
//
// Loading is strict: a machine read must never silently fall back to the
// default database and credential sources when the operator's config is
// unreadable or malformed — that would read from the wrong store.
func loadReadConfig(ctx context.Context, opts readFlags) (config.Config, int) {
	cfg, err := boundedCall(ctx, config.LoadStrict)
	if err != nil {
		if code, ok := ctxFailure(err, opts.timeout, "loading the config file"); ok {
			return cfg, code
		}
		return cfg, readFail(readExitIO, err)
	}
	if opts.kdbxPath != "" {
		cfg.KDBXPath = opts.kdbxPath
	}

	// Machine reads are defined for the KeePass backend only: the legacy
	// geheim store is unauthenticated AES-CBC and must not back new
	// integrations. Unknown backend names fail here too — they never
	// silently fall through to a different store.
	switch effective := resolveBackend(opts.backend, cfg.Backend); effective {
	case "keepass":
		return cfg, 0
	case "geheim":
		return cfg, readUsagef("machine-facing read requires the keepass backend (selected %q); the legacy geheim CBC store is not supported for machine reads", effective)
	default:
		return cfg, readUsagef("unknown backend %q; machine-facing read supports only keepass", effective)
	}
}

// executeRead opens the store, resolves the one requested value and writes its
// exact bytes to stdout, mapping every failure onto its documented exit code.
// ctx carries the --timeout bound and the signal cancellation.
func executeRead(ctx context.Context, cfg *config.Config, opts readFlags, stdout io.Writer) int {
	b, err := openKeepassBounded(ctx, cfg)
	if err != nil {
		if code, ok := ctxFailure(err, opts.timeout, "opening the store"); ok {
			return code
		}
		return readFail(readExitFor(err), err)
	}

	raw, err := b.ReadRaw(ctx, opts.reference, opts.field)
	if err != nil {
		return readFail(readExitFor(err), err)
	}

	if err := writeBounded(ctx, stdout, raw); err != nil {
		if code, ok := ctxFailure(err, opts.timeout, "writing stdout"); ok {
			return code
		}
		return readFail(readExitIO, fmt.Errorf("writing stdout: %w", err))
	}
	return 0
}

// writeBounded writes data to w but stops waiting when ctx ends: a consumer
// that never drains a full pipe must not hang the read past --timeout or
// swallow a termination signal. The write itself cannot be interrupted, so an
// abandoned one is left to die with the process, which exits right after; on
// a bound hit the consumer may have received a prefix, and the non-zero exit
// code tells it the bytes are not the requested value.
func writeBounded(ctx context.Context, w io.Writer, data []byte) error {
	done := make(chan error, 1)
	go func() {
		_, err := w.Write(data)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readExitFor maps open and read errors onto the documented exit codes.
func readExitFor(err error) int {
	switch {
	case errors.Is(err, keepass.ErrNotFound):
		return readExitNotFound
	case errors.Is(err, keepass.ErrAmbiguous):
		return readExitAmbiguous
	case errors.Is(err, keepass.ErrLocked):
		return readExitLocked
	case errors.Is(err, keepass.ErrCorrupt):
		return readExitCorrupt
	case errors.Is(err, keepass.ErrIO):
		return readExitIO
	case errors.Is(err, keepass.ErrInvalidSelection):
		return readExitUsage
	default:
		return 1
	}
}

// readUsagef reports a usage error on stderr and returns its exit code.
func readUsagef(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "foostore read: "+format+"\n", args...)
	fmt.Fprint(os.Stderr, readUsage)
	return readExitUsage
}

// readFail reports a classified failure on stderr and returns its exit code.
// Messages contain identities and error classes, never secret bytes.
func readFail(exitCode int, err error) int {
	hint := ""
	switch {
	case errors.Is(err, keepass.ErrFieldOnAttachment):
		hint = "; drop --field to read the raw attachment bytes"
	case errors.Is(err, keepass.ErrMissingField):
		hint = "; specify --field NAME (for example --field Password)"
	}
	fmt.Fprintf(os.Stderr, "foostore read: %v%s\n", err, hint)
	return exitCode
}
