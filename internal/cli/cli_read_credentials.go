package cli

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/snonux/foostore/internal/config"
	"github.com/snonux/foostore/internal/keepass"
)

// passphraseFDEnv names the inherited file descriptor carrying the KeePass
// passphrase: the preferred unattended unlock strategy, because the secret
// travels through a kernel pipe instead of the environment or argv.
const passphraseFDEnv = "FOOSTORE_READ_PASSPHRASE_FD"

// maxCredentialBytes bounds every credential read: far above any real
// passphrase or key file, far below anything that could exhaust memory.
const maxCredentialBytes = 1 << 20

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
// The descriptor strips exactly one trailing line terminator ("\n" or
// "\r\n"). The passphrase file strips all trailing CR and LF characters,
// matching interactive KeePass unlock. Other whitespace is preserved.
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
	pass := trimPassphraseFile(data)
	if pass == "" {
		return "", fmt.Errorf("the passphrase file delivered an empty passphrase")
	}
	return pass, nil
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
