//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkInheritedDescriptor refuses any descriptor that is not an inherited
// pipe, socket or regular file: a stray number that happens to be a
// runtime-internal descriptor (epoll, eventfd, an O_CLOEXEC regular file), a
// directory or a terminal must not be read and closed under its owner.
func checkInheritedDescriptor(fd int) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("the passphrase descriptor is not usable: %w", err)
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFREG:
	default:
		return errors.New("the passphrase descriptor must be a pipe, socket or regular file")
	}

	// A descriptor inherited across exec never has FD_CLOEXEC set, whereas
	// every descriptor the Go runtime or this process opened for itself does.
	// Refusing close-on-exec descriptors keeps a stray number (for example 3
	// with nothing inherited, which can be a runtime-owned regular file) from
	// being read as a passphrase and then closed under its owner.
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 {
		return fmt.Errorf("the passphrase descriptor is not usable: %w", errno)
	}
	if flags&syscall.FD_CLOEXEC != 0 {
		return errors.New("the passphrase descriptor is close-on-exec, so it was not inherited from the parent process")
	}
	return nil
}

// checkOwnerOnlyPlatform enforces the Unix ownership and permission rules on a
// credential file: owned by the current user, no group or world access (0600
// and the stricter 0400 both pass).
func checkOwnerOnlyPlatform(info os.FileInfo, path string) error {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("credential file %q is owned by uid %d, not the current user (uid %d)", path, st.Uid, os.Geteuid())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("credential file %q has mode %04o; machine reads require owner-only access (no group or world permission bits) — run chmod 600 on it or remove the file reference", path, perm)
	}
	return nil
}
