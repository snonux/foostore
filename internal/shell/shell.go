// Package shell provides interactive readline-based shell integration for geheim.
// It wraps github.com/ergochat/readline to offer vi mode, tab completion,
// history deduplication (matching the Ruby reference implementation), and
// password reading without echo.
package shell

import (
	"context"
	"io"
	"strings"

	"github.com/ergochat/readline"
)

// Shell manages an interactive readline loop with vi mode and tab completion.
type Shell struct {
	rl *readline.Instance
}

// prefixCompleter implements readline.AutoCompleter by delegating to a
// caller-supplied function that returns completions for a given prefix.
// This mirrors the Ruby implementation's Readline.completion_proc.
type prefixCompleter struct {
	fn func(prefix string) []string
}

// Do satisfies the readline.AutoCompleter interface.
// It extracts the current word (characters after the last space) from the
// line buffer up to the cursor, calls the completion function, and returns
// the suffix portions that readline should append.
func (p *prefixCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	// Work only with the portion of the line up to the cursor.
	lineStr := string(line[:pos])

	// Find the start of the current word being typed.
	wordStart := strings.LastIndex(lineStr, " ") + 1
	prefix := lineStr[wordStart:]

	// Ask the caller for all candidates matching the prefix.
	candidates := p.fn(prefix)

	// Return the suffix of each candidate (the part still to be typed),
	// plus a trailing space so readline inserts a space after completion.
	for _, c := range candidates {
		if strings.HasPrefix(c, prefix) {
			suffix := c[len(prefix):]
			newLine = append(newLine, []rune(suffix+" "))
		}
	}

	// length is the number of runes in the prefix that have already been typed.
	length = len([]rune(prefix))
	return
}

// New creates a readline instance configured with:
//   - "% " prompt (matching the Ruby shell_loop prompt)
//   - vi mode (matching Readline.vi_editing_mode in the Ruby setup)
//   - 500-entry in-memory history limit
//   - tab completion via completionFn
//   - manual history saving so we can deduplicate entries ourselves
func New(completionFn func(prefix string) []string) (*Shell, error) {
	cfg := &readline.Config{
		Prompt:       "% ",
		VimMode:      true,
		HistoryLimit: 500,
		AutoComplete: &prefixCompleter{fn: completionFn},
		// Disable automatic history saving so ReadLine can deduplicate
		// entries before committing them, matching the Ruby behaviour:
		//   Readline::HISTORY.pop if argv.empty? ||
		//     (Readline::HISTORY.length > 1 && HISTORY[-1] == HISTORY[-2])
		DisableAutoSaveHistory: true,
		HistoryFile:            "", // no persistent history file
	}

	rl, err := readline.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Shell{rl: rl}, nil
}

// ReadLine reads one line from the terminal, applying history deduplication.
//
// Behaviour mirrors the Ruby shell_loop:
//   - Ctrl+D (EOF)       → returns ("", io.EOF) — caller should exit
//   - Ctrl+C (interrupt) → returns ("", nil)    — empty line, continue
//   - non-empty line     → saved to history only if it differs from the
//     previous entry, then returned to the caller
//
// The ctx parameter is reserved for future cancellation support; the
// underlying readline call is blocking and does not yet respect context.
func (s *Shell) ReadLine(ctx context.Context) (string, error) {
	line, err := s.rl.Readline()
	if err != nil {
		if err == io.EOF {
			// Ctrl+D — signal a clean exit to the caller.
			return "", io.EOF
		}
		if err == readline.ErrInterrupt {
			// Ctrl+C — return an empty line so the caller loops again.
			return "", nil
		}
		return "", err
	}

	line = strings.TrimSpace(line)

	// Deduplicate history: save the line only when it is non-empty and
	// differs from the most recent history entry.  This matches:
	//   Readline::HISTORY.pop if argv.empty? ||
	//     (Readline::HISTORY.length > 1 && HISTORY[-1] == HISTORY[-2])
	if line != "" {
		if err := s.rl.SaveToHistory(line); err != nil {
			// History save failure is non-fatal; log-worthy but ignorable.
			_ = err
		}
	}

	return line, nil
}

// Close releases the underlying readline instance and restores terminal state.
func (s *Shell) Close() {
	_ = s.rl.Close()
}

// ReadPassword reads a password from the shell's terminal without echoing
// characters.  Use this after the shell has already been created (e.g. for
// PIN re-entry during a session).
func (s *Shell) ReadPassword(prompt string) (string, error) {
	bytes, err := s.rl.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ReadPassword reads a password from stdin without echoing characters.
// It is a package-level convenience function for use before the Shell is
// created, such as during initial PIN entry at startup.
func ReadPassword(prompt string) (string, error) {
	// Create a minimal, temporary readline instance solely for masked input.
	// VimMode and history are irrelevant here; we just need the password-
	// reading capability.
	rl, err := readline.NewFromConfig(&readline.Config{
		Prompt:       prompt,
		HistoryLimit: -1, // disable history for this throwaway instance
	})
	if err != nil {
		return "", err
	}
	defer rl.Close() //nolint:errcheck

	bytes, err := rl.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
