//go:build mage

// Magefile provides build targets for the foostore project.
// Targets: Default (Build), Build, Test, Vet, Install, Uninstall, Clean
// Follows the same style as other projects (e.g. hexai).
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	binary     = "./foostore"
	binaryName = "foostore"
	mainPkg    = "./cmd/foostore"
)

// Default builds the binary so that a bare `mage` invocation is equivalent to `mage build`.
func Default() { mg.Deps(Build) }

// Build compiles the binary to ./foostore.
func Build() error {
	fmt.Println("Building", binary)
	// Remove legacy output path from older builds to avoid confusion.
	_ = os.Remove("./bin/foostore")
	return sh.RunV("go", "build", "-o", binary, mainPkg)
}

// Test runs all tests in the module.
func Test() error {
	fmt.Println("Running tests")
	return sh.RunV("go", "test", "./...")
}

// Vet runs go vet on all packages.
func Vet() error {
	fmt.Println("Vetting")
	return sh.RunV("go", "vet", "./...")
}

// Install builds the binary and copies it to $GOPATH/bin (default ~/go/bin).
func Install() error {
	mg.Deps(Build)

	// Resolve GOPATH; fall back to ~/go when the environment variable is unset.
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolving home directory: %w", err)
		}
		gopath = filepath.Join(home, "go")
	}

	binDir := filepath.Join(gopath, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", binDir, err)
	}

	dest := filepath.Join(binDir, binaryName)
	return sh.RunV("cp", "-v", binary, dest)
}

// Uninstall removes the binary from $GOPATH/bin (default ~/go/bin).
// It is idempotent: if the binary is not installed, it succeeds silently.
func Uninstall() error {
	// Mirror Install()'s GOPATH resolution so the paths always match.
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolving home directory: %w", err)
		}
		gopath = filepath.Join(home, "go")
	}

	dest := filepath.Join(gopath, "bin", binaryName)
	fmt.Println("Uninstalling", dest)
	if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Clean removes the local build artifact.
func Clean() error {
	fmt.Println("Cleaning", binary)
	if err := os.Remove(binary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove("./bin/foostore")
	return nil
}
