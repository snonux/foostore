package git_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/snonux/geheim/internal/git"
)

// initRepo creates a temporary git repository with a minimal config so that
// git commit works without requiring the user's global identity to be set.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	for _, args := range [][]string{
		{"git", "init", dir},
		{"git", "-C", dir, "config", "user.email", "test@geheim.test"},
		{"git", "-C", dir, "config", "user.name", "Geheim Test"},
	} {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("setup %v: %v\n%s", args, err, out)
		}
	}

	return dir
}

// writeFile creates a file with the given content inside dir.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
	return path
}

// gitOutput runs a raw git command in dir and returns trimmed stdout+stderr.
func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	args = append([]string{"-C", dir}, args...)
	out, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commitAll stages everything in dir and creates a commit so subsequent
// operations have a baseline history to work against.
func commitAll(t *testing.T, dir, msg string) {
	t.Helper()
	for _, args := range [][]string{
		{"git", "-C", dir, "add", "."},
		{"git", "-C", dir, "commit", "-m", msg},
	} {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("commitAll %v: %v\n%s", args, err, out)
		}
	}
}

// TestAdd verifies that Add stages a file so git status reports it as a new file.
func TestAdd(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	path := writeFile(t, dir, "secret.age", "encrypted data")

	if err := g.Add(ctx, path); err != nil {
		t.Fatalf("Add: %v", err)
	}

	status := gitOutput(t, dir, "status", "--short")
	if !strings.Contains(status, "A  secret.age") {
		t.Errorf("expected 'A  secret.age' in status, got: %q", status)
	}
}

// TestRemove verifies that Remove stages a file deletion (git rm) so the file
// disappears from the index after a committed baseline.
func TestRemove(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	path := writeFile(t, dir, "secret.age", "encrypted data")
	commitAll(t, dir, "initial commit")

	if err := g.Remove(ctx, path); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	status := gitOutput(t, dir, "status", "--short")
	if !strings.Contains(status, "D  secret.age") {
		t.Errorf("expected 'D  secret.age' in status, got: %q", status)
	}
}

// TestCommit verifies that Commit records changes with the hardcoded message.
func TestCommit(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	writeFile(t, dir, "secret.age", "encrypted data")
	// Stage the file so there is something to commit.
	if out, err := exec.Command("git", "-C", dir, "add", ".").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}

	if err := g.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	log := gitOutput(t, dir, "log", "--oneline", "-1")
	const want = "Changing stuff, not telling what in commit history"
	if !strings.Contains(log, want) {
		t.Errorf("expected commit message %q in log, got: %q", want, log)
	}
}

// TestStatus verifies that Status runs without error on a clean repository.
func TestStatus(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	if err := g.Status(ctx); err != nil {
		t.Fatalf("Status: %v", err)
	}
}

// TestReset verifies that Reset discards uncommitted working-tree changes.
func TestReset(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	path := writeFile(t, dir, "secret.age", "original")
	commitAll(t, dir, "initial commit")

	// Overwrite the file so there is a dirty working tree.
	if err := os.WriteFile(path, []byte("modified"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	if err := g.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after Reset: %v", err)
	}
	if string(got) != "original" {
		t.Errorf("expected file content 'original' after reset, got: %q", got)
	}
}

// TestAdd_nonexistent_file verifies that Add returns an error when the target
// file does not exist, because git add will fail.
func TestAdd_nonexistent_file(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	err := g.Add(ctx, filepath.Join(dir, "does-not-exist.age"))
	if err == nil {
		t.Fatal("expected error when adding a nonexistent file, got nil")
	}
}

// TestCommit_nothing_to_commit verifies that Commit returns an error (exit 1
// from git) when there is nothing staged, rather than panicking or crashing.
// Callers are expected to guard against this case, but the package must not hide
// the error entirely.
func TestCommit_nothing_to_commit(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	// Create and commit a file so HEAD exists; index is now clean.
	writeFile(t, dir, "secret.age", "data")
	commitAll(t, dir, "initial commit")

	// Nothing staged — git commit should exit non-zero.
	err := g.Commit(ctx)
	if err == nil {
		t.Fatal("expected error when committing with nothing to commit, got nil")
	}
}

// TestRemove_nonexistent_file verifies that Remove returns an error when the
// target is not tracked by git, because git rm exits non-zero in that case.
func TestRemove_nonexistent_file(t *testing.T) {
	dir := initRepo(t)
	g := git.New(dir)
	ctx := context.Background()

	err := g.Remove(ctx, filepath.Join(dir, "ghost.age"))
	if err == nil {
		t.Fatal("expected error when removing a non-tracked file, got nil")
	}
}

// TestSync verifies the pull-push-status loop using two local repos so no
// real network is needed. A bare repo acts as the remote; a working repo
// with an initial commit pushes to it, then Sync pulls and pushes again.
func TestSync(t *testing.T) {
	ctx := context.Background()

	runcmd := func(args ...string) {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}

	// Create a working directory with an initial commit on master.
	workDir := t.TempDir()
	runcmd("git", "init", "--initial-branch=master", workDir)
	runcmd("git", "-C", workDir, "config", "user.email", "test@geheim.test")
	runcmd("git", "-C", workDir, "config", "user.name", "Geheim Test")
	path := filepath.Join(workDir, "init.txt")
	if err := os.WriteFile(path, []byte("init"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runcmd("git", "-C", workDir, "add", ".")
	runcmd("git", "-C", workDir, "commit", "-m", "init")

	// Create a bare repo and push the initial commit into it so master exists.
	bareDir := t.TempDir()
	runcmd("git", "init", "--bare", "--initial-branch=master", bareDir)
	runcmd("git", "-C", workDir, "remote", "add", "localremote", bareDir)
	runcmd("git", "-C", workDir, "push", "localremote", "master")

	g := git.New(workDir)
	if err := g.Sync(ctx, []string{"localremote"}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
}

// TestSync_bad_remote verifies that Sync returns an error when a configured
// remote does not exist, rather than silently succeeding.
func TestSync_bad_remote(t *testing.T) {
	dir := initRepo(t)
	// Create an initial commit so the repo has a valid HEAD.
	writeFile(t, dir, "init.txt", "init")
	commitAll(t, dir, "init")

	g := git.New(dir)
	err := g.Sync(context.Background(), []string{"nonexistent-remote"})
	if err == nil {
		t.Fatal("expected error when syncing with a nonexistent remote, got nil")
	}
}
