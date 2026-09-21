// Package cli — machine-facing `foostore read` command.
//
// This file implements the exact, raw, non-interactive read contract used by
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
	"math"
	"os"
	"strconv"
	"strings"
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

// passphraseFDEnv names the inherited file descriptor carrying the KeePass
// passphrase: the preferred unattended unlock strategy, because the secret
// travels through a kernel pipe instead of the environment, argv, or a
// globally exported variable.
const passphraseFDEnv = "FOOSTORE_READ_PASSPHRASE_FD"

// readValueFlags are the flags that consume the next argument; MachineReadArgs
// must skip their values when looking for the command word.
var readValueFlags = map[string]bool{"--backend": true, "--kdbx-path": true, "--field": true, "--timeout": true}

// ReadExitUsage is the exit code of a machine-read usage error; exported so
// the process entry point can report an invocation problem MachineReadArgs
// found before Read ran.
const ReadExitUsage = readExitUsage

// readOnlyFlags are flags that only the read command understands; the
// interactive CLI has no use for them.
var readOnlyFlags = map[string]bool{"--field": true, "--timeout": true, "--exact": true, "--raw": true, "--non-interactive": true}

// isReadOnlyEqualsForm reports whether arg is the unsupported --flag=value
// spelling of a read-only value flag. The interactive CLI ignores such
// arguments, so without this a machine caller who forgot the command word and
// used the equals form would land in the interactive unlock and exit 0 with
// nothing on stdout; parseReadFlags rejects the form as an unknown flag.
func isReadOnlyEqualsForm(arg string) bool {
	return strings.HasPrefix(arg, "--field=") || strings.HasPrefix(arg, "--timeout=")
}

// errCommandWordSwallowed explains the argument shape an unquoted empty shell
// variable produces: `--kdbx-path $UNSET read ...` arrives as `--kdbx-path
// read ...`, so the flag ate the command word.
func errCommandWordSwallowed(flag string) error {
	return fmt.Errorf("%s is directly followed by %q, the command word — an unset shell variable? Quote the variable, put the flag after the command word, or spell a store literally named read as ./read", flag, "read")
}

// MachineReadArgs reports whether args (os.Args[1:]) invoke the machine-facing
// read command. Flags may precede the command word in any order — the global
// --backend and --kdbx-path as well as read's own flags, so a mis-ordered
// `foostore --field Password read X` is still a read.
//
// The command word is the first argument that is neither a flag nor a flag's
// value. When it is "read", the returned argument vector is args with the
// command word removed, every flag and value kept in place (including empty
// values, which parseReadFlags then rejects instead of silently selecting a
// default).
//
// Two argument shapes are machine reads even without a usable command word: a
// value flag directly followed by the word "read" (an unset shell variable
// swallowed the command word), which is returned as isRead with a usage error,
// and any flag only the read command understands (--field, --timeout, --exact,
// --raw, --non-interactive), where a missing command word is inferred because
// the interactive CLI has no use for such a flag and would otherwise mishandle
// it. Deciding this before any interactive initialisation is what keeps a
// machine caller's typo from falling through into a prompt, a shell, or an
// interactive keepass unlock. After an explicit command word the flags are
// unambiguous, so `read --field read X` selects a field named "read".
func MachineReadArgs(args []string) (argv []string, isRead bool, err error) {
	sawReadOnlyFlag := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case readValueFlags[arg] && i+1 < len(args) && args[i+1] == "read":
			return nil, true, errCommandWordSwallowed(arg)
		case readValueFlags[arg]:
			sawReadOnlyFlag = sawReadOnlyFlag || readOnlyFlags[arg]
			i++ // skip the flag's value, whatever it is
		case strings.HasPrefix(arg, "-"):
			sawReadOnlyFlag = sawReadOnlyFlag || readOnlyFlags[arg] || isReadOnlyEqualsForm(arg)
		case arg == "read":
			argv = make([]string, 0, len(args)-1)
			argv = append(argv, args[:i]...)
			return append(argv, args[i+1:]...), true, nil
		default:
			return inferredRead(args, sawReadOnlyFlag)
		}
	}
	return inferredRead(args, sawReadOnlyFlag)
}

// inferredRead returns a copy of args as a read invocation when a read-only
// flag was seen, and reports "not a read" otherwise.
func inferredRead(args []string, sawReadOnlyFlag bool) ([]string, bool, error) {
	if !sawReadOnlyFlag {
		return nil, false, nil
	}
	return append([]string(nil), args...), true, nil
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

// readFlags holds the parsed machine-read invocation.
type readFlags struct {
	reference string
	field     string
	timeout   time.Duration
	backend   string
	kdbxPath  string
}

// wantsReadHelp reports whether argv asks for help. It is checked before flag
// parsing so `foostore read --help` documents the contract instead of failing
// as an unknown flag. Values of value flags (`--field -h`) and everything after
// "--" are data, never a help request: usage text must not be mistaken for the
// requested bytes.
func wantsReadHelp(argv []string) bool {
	for i := 0; i < len(argv); i++ {
		switch arg := argv[i]; {
		case arg == "--":
			return false
		case readValueFlags[arg]:
			i++
		case arg == "--help" || arg == "-h":
			return true
		}
	}
	return false
}

// parseReadFlags scans argv for the read command's flags. Value flags use the
// documented space-separated form, take a non-empty value, and may be given at
// most once: a repeated flag is a usage error rather than a silent
// last-one-wins. --exact, --raw and
// --non-interactive are accepted as explicit no-ops so scripts can
// self-document the contract they rely on: read is always exact, raw and
// non-interactive. Anything starting with "-" that remains is rejected instead
// of being silently treated as a reference; "--" ends flag parsing so an entry
// identity that itself starts with "-" can still be addressed.
func parseReadFlags(argv []string) (readFlags, error) {
	opts, timeoutRaw, rest, err := scanReadFlags(argv)
	if err != nil {
		return opts, err
	}

	if timeoutRaw != "" {
		d, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return opts, fmt.Errorf("invalid --timeout %q: %v", timeoutRaw, err)
		}
		if d <= 0 {
			return opts, fmt.Errorf("--timeout must be positive, got %q", timeoutRaw)
		}
		opts.timeout = d
	}

	if len(rest) != 1 {
		return opts, fmt.Errorf("read takes exactly one reference (the exact entry identity), got %d arguments", len(rest))
	}
	opts.reference = rest[0]
	return opts, nil
}

// scanReadFlags walks argv once, applying the value flags and collecting the
// positional arguments. It returns the raw --timeout text so the caller can
// validate it after the scan.
func scanReadFlags(argv []string) (opts readFlags, timeoutRaw string, rest []string, err error) {
	opts.timeout = readDefaultTimeout
	seen := map[string]bool{}

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch arg {
		case "--":
			return opts, timeoutRaw, append(rest, argv[i+1:]...), nil
		case "--exact", "--raw", "--non-interactive":
			// Explicit no-ops; kept out of the positional arguments.
		case "--backend", "--kdbx-path", "--field", "--timeout":
			if i+1 >= len(argv) {
				return opts, timeoutRaw, rest, fmt.Errorf("%s requires a value", arg)
			}
			if seen[arg] {
				return opts, timeoutRaw, rest, fmt.Errorf("%s given more than once", arg)
			}
			seen[arg] = true
			i++
			// An empty value is almost always an unset shell variable; taking
			// it as "not given" would silently select the default store.
			if argv[i] == "" {
				return opts, timeoutRaw, rest, fmt.Errorf("%s requires a non-empty value", arg)
			}
			if arg == "--timeout" {
				timeoutRaw = argv[i]
			} else {
				setReadValueFlag(&opts, arg, argv[i])
			}
		default:
			if strings.HasPrefix(arg, "-") {
				return opts, timeoutRaw, rest, fmt.Errorf("unknown flag %q", arg)
			}
			rest = append(rest, arg)
		}
	}
	return opts, timeoutRaw, rest, nil
}

// setReadValueFlag stores the value of one of the string-valued flags.
func setReadValueFlag(opts *readFlags, flag, value string) {
	switch flag {
	case "--backend":
		opts.backend = value
	case "--kdbx-path":
		opts.kdbxPath = value
	case "--field":
		opts.field = value
	}
}

// openKeepassBounded resolves the credentials and opens the database under the
// bounded context. Everything that can block runs in a goroutine — the
// passphrase read (an inherited FD may never deliver or close), the key file
// read, and the KDF plus decode — so a stuck pipe, stuck mount, or slow host
// cannot hang a machine consumer past the caller's deadline. The goroutine
// itself cannot be interrupted mid-operation (neither os.File reads nor the
// library take a context); the bound only guarantees the consumer stops
// waiting in time, and the process exits right after.
//
// Unusable credentials (missing source, bad mode, unreadable FD or key file)
// are wrapped in keepass.ErrLocked so they map onto the locked exit code.
func openKeepassBounded(ctx context.Context, cfg *config.Config) (*keepass.Backend, error) {
	return boundedCall(ctx, func() (*keepass.Backend, error) {
		passphrase, err := readMachinePassphrase(cfg)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", keepass.ErrLocked, err)
		}
		keyFileData, err := readMachineKeyFile(cfg)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", keepass.ErrLocked, err)
		}
		return keepass.New(cfg, passphrase, keyFileData)
	})
}

// maxCredentialBytes bounds every credential read (passphrase descriptor,
// passphrase file, key file): far above any real passphrase or key file, far
// below anything that could exhaust memory.
const maxCredentialBytes = 1 << 20

// readMachinePassphrase resolves the KeePass passphrase without any
// interaction. Priority:
//
//  1. FOOSTORE_READ_PASSPHRASE_FD — an inherited file descriptor carrying the
//     passphrase (secure inherited secret). The writer must close its end: the
//     passphrase is everything up to end-of-file. The descriptor is consumed
//     and closed.
//  2. cfg.KDBXPassFile — an explicit, operator-configured protected-file
//     tradeoff (config.LoadStrict blanks the built-in default, so only a
//     kdbx_pass_file the config file itself sets counts); see
//     readCredentialFile for the enforced permissions. A missing or lax file
//     fails loudly.
//
// Both sources strip exactly one trailing line terminator ("\n" or "\r\n"),
// so `echo pass > file` works and a passphrase that itself ends in other
// whitespace keeps it.
//
// There is deliberately no $PIN or prompt fallback: an environment variable is
// inherited by every child process and visible in /proc/<pid>/environ, and a
// prompt would block a machine consumer. Without a usable credential source the
// read fails with the locked exit code. Error messages never echo the
// descriptor variable's value, because a mistaken
// FOOSTORE_READ_PASSPHRASE_FD=<the passphrase itself> would leak it.
func readMachinePassphrase(cfg *config.Config) (string, error) {
	if fdStr, set := os.LookupEnv(passphraseFDEnv); set {
		// An exported-but-empty variable is almost always an unset shell
		// variable; falling through to another source would hide that.
		if fdStr == "" {
			return "", fmt.Errorf("%s is set but empty; unset it or give a descriptor number", passphraseFDEnv)
		}
		return readPassphraseFromFD(fdStr)
	}
	if cfg.KDBXPassFile == "" {
		return "", fmt.Errorf("no non-interactive credential source for machine read; pass the passphrase via %s or set kdbx_pass_file explicitly in the config file (a built-in default path is never used)", passphraseFDEnv)
	}
	data, err := readCredentialFile(cfg.KDBXPassFile)
	if err != nil {
		return "", fmt.Errorf("kdbx_pass_file (no %s set): %w", passphraseFDEnv, err)
	}
	return nonEmptyPassphrase(data, "the passphrase file")
}

// nonEmptyPassphrase strips one trailing line terminator from data and
// refuses an empty result.
func nonEmptyPassphrase(data []byte, source string) (string, error) {
	pass := string(data)
	if strings.HasSuffix(pass, "\n") {
		pass = strings.TrimSuffix(strings.TrimSuffix(pass, "\n"), "\r")
	}
	if pass == "" {
		return "", fmt.Errorf("%s delivered an empty passphrase", source)
	}
	return pass, nil
}

// readPassphraseFromFD reads and closes the descriptor named by fdStr. The
// descriptor number is validated without ever echoing fdStr back — nor the
// number itself, since a numeric passphrase set by mistake would be
// indistinguishable from one. Only inherited pipes, sockets and regular files
// are accepted: a stray number that happens to be a runtime-internal
// descriptor (epoll, eventfd, an O_CLOEXEC regular file), a directory or a
// terminal must not be read and closed.
func readPassphraseFromFD(fdStr string) (string, error) {
	fd, err := strconv.Atoi(fdStr)
	if err != nil || fd < 0 || fd > math.MaxInt32 || strconv.Itoa(fd) != fdStr {
		return "", fmt.Errorf("%s must be a plain non-negative file descriptor number", passphraseFDEnv)
	}
	if fd == 1 || fd == 2 {
		return "", fmt.Errorf("%s must not be 1 or 2: stdout and stderr stay reserved for the read output and diagnostics", passphraseFDEnv)
	}
	if err := checkInheritedDescriptor(fd); err != nil {
		return "", err
	}

	// os.NewFile only returns nil for a negative fd, which is rejected above.
	f := os.NewFile(uintptr(fd), "foostore-read-passphrase")
	defer func() { _ = f.Close() }()
	data, err := readBounded(f)
	if err != nil {
		return "", fmt.Errorf("reading passphrase from the inherited descriptor: %w", err)
	}
	return nonEmptyPassphrase(data, "the inherited passphrase descriptor")
}

// readBounded reads r to EOF, refusing more than maxCredentialBytes.
func readBounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxCredentialBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCredentialBytes {
		return nil, fmt.Errorf("more than %d bytes", maxCredentialBytes)
	}
	return data, nil
}

// readMachineKeyFile reads the optional KeePass key file with the same
// protections as the passphrase file: key files are credentials too. An empty
// key file is refused — the library would silently treat it as "no key file",
// so a password-only unlock would succeed although a key file is configured.
func readMachineKeyFile(cfg *config.Config) ([]byte, error) {
	if cfg.KDBXKeyFile == "" {
		return nil, nil
	}
	data, err := readCredentialFile(cfg.KDBXKeyFile)
	if err != nil {
		return nil, fmt.Errorf("kdbx_key_file: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("credential file %q is empty", cfg.KDBXKeyFile)
	}
	return data, nil
}

// readCredentialFile opens path once and checks the handle it then reads —
// never the path a second time — so the permissions cannot change between the
// check and the use. The file must be a regular file owned by the current
// user with no group or world access (0600 and the stricter 0400 both pass),
// so a lax file cannot leak the credential to other local accounts. At most
// maxCredentialBytes are read.
func readCredentialFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening credential file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat credential file %q: %w", path, err)
	}
	if err := requireOwnerOnly(info, path); err != nil {
		return nil, err
	}
	data, err := readBounded(f)
	if err != nil {
		return nil, fmt.Errorf("reading credential file %q: %w", path, err)
	}
	return data, nil
}

// requireOwnerOnly refuses credential files that are not regular files, are
// owned by someone else, or grant any access to group or world: in machine
// mode this is an enforced tradeoff, not a silent default. The ownership and
// permission-bit checks are Unix semantics and live in checkOwnerOnlyPlatform
// (cli_read_unix.go); other platforms have no equivalent to enforce.
func requireOwnerOnly(info os.FileInfo, path string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("credential file %q is not a regular file", path)
	}
	return checkOwnerOnlyPlatform(info, path)
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
	fmt.Fprintf(os.Stderr, "foostore read: %v\n", err)
	return exitCode
}

// readUsage is the machine-facing read help text.
const readUsage = `usage: foostore read [--field NAME] [--kdbx-path PATH] [--backend keepass] [--timeout DURATION] [--exact] [--raw] [--non-interactive] REFERENCE

Reads exactly one secret and writes its raw bytes to stdout.
REFERENCE is the exact entry identity ("Group/Title"); an attachment is
selected by its reference form ("Group/Title/name"). Entry references require
--field NAME (e.g. --field Password); attachment references reject --field.
The reference must match the stored identity exactly (no normalisation);
use -- before a reference that starts with "-".

Exit codes: 0 ok; 1 unexpected failure or timeout; 2 usage;
4 not found (the only suppressible code); 5 ambiguous identity;
6 locked or unusable credentials; 7 corrupt store; 8 store I/O.

Credentials resolve non-interactively: FOOSTORE_READ_PASSPHRASE_FD, then
kdbx_pass_file (regular file, owned by you, no group/world access). The
descriptor's writer must close its end (the passphrase is read to EOF); one
trailing line terminator is stripped. There is no $PIN or prompt fallback.
No shell, no fzf, no export, no git sync.`
