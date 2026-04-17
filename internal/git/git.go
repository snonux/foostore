// Package git wraps git operations used by foostore to manage the secret store.
// It mirrors the Git module from the original Ruby implementation (geheim.rb lines 79-123),
// running real git subprocesses rather than using a Go git library.
//
// The package exposes a Gitter interface so that callers can accept either a
// real *Git (backed by a git repository) or a *NoOp stub (for directories that
// are not git repositories). This avoids nil-pointer panics in the CLI dispatch
// loop and keeps git-related decisions local to this package.
package git

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Gitter is the interface that both *Git (real git operations) and *NoOp
// (informational no-ops) implement. The CLI holds a Gitter so that it can be
// freely swapped without changing any dispatch logic.
type Gitter interface {
	// Add stages a single file for the next commit.
	Add(ctx context.Context, filePath string) error

	// Remove stages a file deletion for the next commit.
	Remove(ctx context.Context, filePath string) error

	// Status prints the current git status of the working directory.
	Status(ctx context.Context) error

	// Commit records all staged changes with a generic commit message.
	Commit(ctx context.Context) error

	// Reset discards all uncommitted changes in the working directory.
	Reset(ctx context.Context) error

	// Sync pulls from and pushes to each configured remote repository.
	Sync(ctx context.Context, syncRepos []string) error
}

// Git provides git operations scoped to the secret store's data directory.
type Git struct {
	dataDir string
}

// Compile-time assertion: *Git must satisfy Gitter.
var _ Gitter = (*Git)(nil)

// New creates a Git helper for the given data directory.
func New(dataDir string) *Git {
	return &Git{dataDir: dataDir}
}

// IsGitRepo reports whether the given directory is inside a git working tree.
// It runs 'git rev-parse --is-inside-work-tree' in that directory and returns
// true when the command exits with status 0 and outputs "true". This is the
// canonical way to check for a git repo without inspecting the filesystem
// structure directly (works with worktrees, submodules, etc.).
func IsGitRepo(dir string) bool {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
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
