//go:build mage

// Magefile provides build targets for the geheim project.
// Targets: Build, Test, Install, Uninstall
package main

import (
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

// Install builds the binary and copies it to ~/.local/bin/geheim.
func Install() error {
	mg.Deps(Build)
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	dest := home + "/.local/bin/geheim"
	fmt.Println("Installing to", dest)
	return sh.Copy(dest, binary)
}

// Uninstall removes the installed binary from ~/.local/bin/geheim.
func Uninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	dest := home + "/.local/bin/geheim"
	fmt.Println("Uninstalling", dest)
	return os.Remove(dest)
}

// createBinDir ensures ./bin exists before the build step writes the binary.
func createBinDir() error {
	return os.MkdirAll("./bin", 0755)
}
