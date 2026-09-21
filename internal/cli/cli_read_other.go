//go:build !unix

package cli

import (
	"errors"
	"os"
)

// checkInheritedDescriptor reports that inherited passphrase descriptors are a
// Unix mechanism: there is no portable way to tell an inherited descriptor
// from one the process opened itself, so the machine read must use
// kdbx_pass_file on this platform.
func checkInheritedDescriptor(int) error {
	return errors.New("inherited passphrase descriptors are not supported on this platform; use kdbx_pass_file")
}

// checkOwnerOnlyPlatform has nothing to enforce: Unix ownership and
// permission bits do not exist on this platform (files report synthetic
// modes), so a check would either always fail or always pass meaninglessly.
func checkOwnerOnlyPlatform(os.FileInfo, string) error { return nil }
