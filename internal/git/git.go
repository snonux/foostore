// Package git wraps git operations used by geheim to manage the secret store.
// It mirrors the Git module from the original Ruby implementation (geheim.rb lines 79-123),
// running real git subprocesses rather than using a Go git library.
package git

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
)

// Git provides git operations scoped to the secret store's data directory.
type Git struct {
	dataDir string
}

// New creates a Git helper for the given data directory.
func New(dataDir string) *Git {
	return &Git{dataDir: dataDir}
}

// Add stages a single file for the next commit.
// It changes the working directory to the file's parent so that git add
// receives only the base name, matching the Ruby Dir.chdir pattern.
func (g *Git) Add(ctx context.Context, filePath string) error {
	return run(ctx, filepath.Dir(filePath), "git", "add", filepath.Base(filePath))
}

// Remove stages a file deletion for the next commit using git rm.
// Like Add, it operates in the file's parent directory.
func (g *Git) Remove(ctx context.Context, filePath string) error {
	return run(ctx, filepath.Dir(filePath), "git", "rm", filepath.Base(filePath))
}

// Status prints the current git status of the data directory.
func (g *Git) Status(ctx context.Context) error {
	return run(ctx, g.dataDir, "git", "status")
}

// Commit records all staged changes with a deliberately vague commit message
// so that secret names are not exposed in commit history.
func (g *Git) Commit(ctx context.Context) error {
	return run(ctx, g.dataDir, "git", "commit", "-a", "-m",
		"Changing stuff, not telling what in commit history")
}

// Reset discards all uncommitted changes in the data directory.
func (g *Git) Reset(ctx context.Context) error {
	return run(ctx, g.dataDir, "git", "reset", "--hard")
}

// Sync pulls from and pushes to each configured remote repository in order,
// then prints the final status. This keeps multiple machines in sync.
func (g *Git) Sync(ctx context.Context, syncRepos []string) error {
	fmt.Printf("> Synchronising %s\n", g.dataDir)

	for _, repo := range syncRepos {
		if err := run(ctx, g.dataDir, "git", "pull", repo, "master"); err != nil {
			return err
		}
		if err := run(ctx, g.dataDir, "git", "push", repo, "master"); err != nil {
			return err
		}
	}

	return run(ctx, g.dataDir, "git", "status")
}

// run executes a git command in the given directory, printing each line of
// combined stdout+stderr with a "> " prefix so the user can follow progress.
// It returns an error if the command exits with a non-zero status.
//
// Output is intentionally buffered: all output is captured into a bytes.Buffer
// and printed only after the subprocess exits. This matches the Ruby reference
// implementation (which uses backtick capture) and keeps the "> " prefix logic
// simple. For long-running operations like git pull the user sees no output
// until the command completes — an acceptable tradeoff for a personal tool.
func run(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()

	// Print all output lines regardless of whether the command succeeded,
	// so the user sees error messages from git itself.
	scanner := bufio.NewScanner(&buf)
	for scanner.Scan() {
		fmt.Printf("> %s\n", scanner.Text())
	}

	return err
}
