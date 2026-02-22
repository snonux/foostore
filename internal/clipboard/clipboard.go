// Package clipboard pipes a password field to the OS clipboard command.
// On macOS (UNAME=Darwin) it uses pbcopy; on Linux it uses gpaste-client.
package clipboard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
)

// Clipboard holds the OS-specific clipboard command to spawn.
// The command receives the password via stdin.
type Clipboard struct {
	cmd string
}

// New returns a Clipboard configured for the current platform.
// If UNAME == "Darwin" the macosCmd is used; otherwise gnomeCmd is used.
// This mirrors the Ruby: ENV['UNAME'] == 'Darwin' ? Config.macos_clipboard_cmd : Config.gnome_clipboard_cmd
func New(gnomeCmd, macosCmd string) *Clipboard {
	cmd := gnomeCmd
	if os.Getenv("UNAME") == "Darwin" {
		cmd = macosCmd
	}
	return &Clipboard{cmd: cmd}
}

// Paste extracts the password from data, pipes it to the clipboard command,
// and prints the censored form of data to stdout so the operator can see
// contextual information without the secret being visible.
//
// The Ruby implementation spawns the clipboard command with an IO pipe and
// detaches the child process. Here we use os/exec with a StdinPipe and
// Wait() for simplicity; the behaviour is equivalent for interactive use.
func (c *Clipboard) Paste(ctx context.Context, data string) error {
	user, password, censored, err := extract(data)
	if err != nil {
		return err
	}

	if c.cmd == "" {
		return fmt.Errorf("can't paste to clipboard")
	}

	// Spawn the clipboard command; the password is written to its stdin.
	clipCmd := exec.CommandContext(ctx, c.cmd) //nolint:gosec // cmd is caller-supplied config

	stdin, err := clipCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("opening stdin pipe for clipboard command: %w", err)
	}

	if err := clipCmd.Start(); err != nil {
		return fmt.Errorf("starting clipboard command %q: %w", c.cmd, err)
	}

	// Write only the password — never the full data — to the clipboard.
	if _, err := fmt.Fprint(stdin, password); err != nil {
		return fmt.Errorf("writing password to clipboard command stdin: %w", err)
	}
	stdin.Close()

	// Print the censored representation so the operator sees context.
	fmt.Println(censored)

	if err := clipCmd.Wait(); err != nil {
		return fmt.Errorf("clipboard command exited with error: %w", err)
	}

	fmt.Printf("> Pasted password for user '%s' to the clipboard\n", user)
	return nil
}

// extract parses data for the first "user:password" token and returns:
//   - user     – everything before the colon in the first match
//   - password – everything after the colon in the first match
//   - censored – data with every "word:secret" token replaced by "word:CENSORED"
//
// Regex mirrors the Ruby: /(\S+):(\S+)/ for matching and substitution.
func extract(data string) (user, password, censored string, err error) {
	// matchRe captures the first non-whitespace:non-whitespace pair.
	matchRe := regexp.MustCompile(`(\S+):(\S+)`)
	// censorRe replaces every such pair; the first capture group is kept.
	censorRe := regexp.MustCompile(`(\S+):\S+`)

	parts := matchRe.FindStringSubmatch(data)
	if parts == nil {
		return "", "", "", fmt.Errorf("no user:password pattern found in data")
	}

	user = parts[1]
	password = parts[2]
	// Replace all occurrences with "$1:CENSORED", preserving the word before the colon.
	censored = censorRe.ReplaceAllString(data, "${1}:CENSORED")
	return user, password, censored, nil
}
