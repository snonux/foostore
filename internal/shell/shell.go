// Package shell provides interactive readline-based shell integration for foostore.
// It wraps github.com/ergochat/readline to offer vi mode, tab completion,
// history deduplication (matching the Ruby reference implementation), and
// password reading without echo.
package shell

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ergochat/readline"
	"golang.org/x/term"
)

// Shell manages an interactive readline loop with vi mode and tab completion.
type Shell struct {
	rl *readline.Instance
}

func shellPrompt() string {
	if os.Getenv("NO_COLOR") != "" {
		return "% "
	}
	// Bright cyan prompt marker for better visibility.
	return "\x1b[1;96m%\x1b[0m "
}

// viInputFilter provides a small vi-style modal key layer for readline.
// It is used as a reliability fallback because VimMode handling can vary
// by terminal; this keeps navigation deterministic.
type viInputFilter struct {
	normalMode bool
}

func newVIInputFilter() *viInputFilter {
	// Start in insert mode to keep command entry ergonomic.
	return &viInputFilter{normalMode: false}
}

// filter maps typed runes into readline control runes.
// Returns (mappedRune, true) to pass into readline, or (_, false) to swallow.
func (v *viInputFilter) filter(r rune) (rune, bool) {
	switch r {
	case readline.CharEnter, readline.CharCtrlJ:
		// Enter submits the line and returns to insert mode for next prompt.
		v.normalMode = false
		return r, true
	case readline.CharEsc, 29: // Esc or Ctrl-]
		v.normalMode = true
		return 0, false
	}

	if !v.normalMode {
		return r, true
	}

	switch r {
	case 'i':
		v.normalMode = false
		return 0, false
	case 'a':
		v.normalMode = false
		return readline.CharForward, true
	case 'h':
		return readline.CharBackward, true
	case 'j':
		return readline.CharNext, true
	case 'k':
		return readline.CharPrev, true
	case 'l':
		return readline.CharForward, true
	case 'w', 'W':
		return readline.MetaForward, true
	case 'b', 'B':
		return readline.MetaBackward, true
	case '0', '^':
		return readline.CharLineStart, true
	case '$':
		return readline.CharLineEnd, true
	case 'x':
		return readline.MetaDeleteKey, true
	default:
		// In normal mode, unknown keys should not insert text.
		return readline.CharBell, true
	}
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
	viFilter := newVIInputFilter()
	cfg := &readline.Config{
		Prompt:       shellPrompt(),
		VimMode:      false,
		HistoryLimit: 500,
		AutoComplete: &prefixCompleter{fn: completionFn},
		FuncFilterInputRune: func(r rune) (rune, bool) {
			return viFilter.filter(r)
		},
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
// Behaviour:
//   - Ctrl+D (EOF)       → returns ("", io.EOF) — caller should exit
//   - Ctrl+C (interrupt) → returns ("", io.EOF) — caller should exit (same as Ruby's SIGINT)
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
			// Ctrl+C — exit the shell, mirroring the Ruby behaviour where
			// SIGINT terminates the process.
			return "", io.EOF
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

// ReadPassword prints prompt then reads a password from the terminal using
// readline in Vim mode with masked visual feedback ("*").
//
// For non-interactive input (stdin is not a terminal), it falls back to
// reading a single line from stdin.
func ReadPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Print(prompt)
		defer fmt.Println() // move to next line after input is complete

		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	viFilter := newVIInputFilter()
	rl, err := readline.NewFromConfig(&readline.Config{
		FuncFilterInputRune: func(r rune) (rune, bool) {
			return viFilter.filter(r)
		},
		Prompt:                 prompt,
		VimMode:                false,
		EnableMask:             true,
		MaskRune:               '*',
		HistoryFile:            "",
		DisableAutoSaveHistory: true,
	})
	if err != nil {
		return "", err
	}
	defer rl.Close()

	line, err := rl.Readline()
	if err != nil {
		if err == readline.ErrInterrupt {
			return "", fmt.Errorf("interrupted")
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
