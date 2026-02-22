//go:build mage

// Magefile provides build targets for the geheim project.
// Targets: Build, Test, Vet, Install, Uninstall, Clean
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	binary  = "./bin/geheim"
	mainPkg = "./cmd/geheim"
)

// Build compiles the binary to ./bin/geheim.
func Build() error {
	mg.Deps(createBinDir)
	fmt.Println("Building", binary)
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

// Install builds the binary, copies it to ~/.local/bin/geheim, and sets executable permissions.
func Install() error {
	mg.Deps(Build)
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	dest := home + "/.local/bin/geheim"
	fmt.Println("Installing to", dest)
	if err := sh.Copy(dest, binary); err != nil {
		return err
	}
	return os.Chmod(dest, 0755)
}

// Uninstall removes the installed binary from ~/.local/bin/geheim.
// It is idempotent: if the binary is not installed, it succeeds silently.
func Uninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	dest := home + "/.local/bin/geheim"
	fmt.Println("Uninstalling", dest)
	if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Clean removes the ./bin directory.
func Clean() error {
	fmt.Println("Cleaning", "./bin")
	return os.RemoveAll("./bin")
}

// createBinDir ensures ./bin exists before the build step writes the binary.
func createBinDir() error {
	return os.MkdirAll("./bin", 0755)
}
