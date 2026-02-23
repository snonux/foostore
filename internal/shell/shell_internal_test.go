// package shell (internal test) exercises unexported types that cannot be
// reached from the external shell_test package.
package shell

import (
	"strings"
	"testing"

	"github.com/ergochat/readline"
)

// TestPrefixCompleterDo exercises the Do method of prefixCompleter against a
// fixed candidate list.  No TTY is required because the method is pure logic.
func TestPrefixCompleterDo(t *testing.T) {
	candidates := []string{"add", "edit", "export", "ls", "search"}

	p := &prefixCompleter{
		fn: func(prefix string) []string {
			var out []string
			for _, c := range candidates {
				if strings.HasPrefix(c, prefix) {
					out = append(out, c)
				}
			}
			return out
		},
	}

	cases := []struct {
		name       string
		line       string // full line up to cursor
		wantSuffix []string
		wantLen    int
	}{
		{
			// Empty input: all candidates returned; each suffix is the full word + space.
			name:       "empty prefix",
			line:       "",
			wantSuffix: []string{"add ", "edit ", "export ", "ls ", "search "},
			wantLen:    0,
		},
		{
			// "e" prefix: edit, export.
			name:       "single char prefix",
			line:       "e",
			wantSuffix: []string{"dit ", "xport "},
			wantLen:    1,
		},
		{
			// "ex" prefix: only export.
			name:       "two char prefix",
			line:       "ex",
			wantSuffix: []string{"port "},
			wantLen:    2,
		},
		{
			// "z" prefix: no matches.
			name:       "no match",
			line:       "z",
			wantSuffix: nil,
			wantLen:    1,
		},
		{
			// Line has a space: prefix is the word after the last space.
			// "cat e" → prefix is "e", completions for "e".
			name:       "prefix after space",
			line:       "cat e",
			wantSuffix: []string{"dit ", "xport "},
			wantLen:    1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := []rune(tc.line)
			pos := len(line)
			newLine, length := p.Do(line, pos)

			if length != tc.wantLen {
				t.Errorf("length = %d; want %d", length, tc.wantLen)
			}
			if len(newLine) != len(tc.wantSuffix) {
				t.Errorf("len(newLine) = %d; want %d (%v vs %v)",
					len(newLine), len(tc.wantSuffix), toStrings(newLine), tc.wantSuffix)
				return
			}
			// Build a set for order-independent comparison.
			got := make(map[string]bool, len(newLine))
			for _, r := range newLine {
				got[string(r)] = true
			}
			for _, want := range tc.wantSuffix {
				if !got[want] {
					t.Errorf("missing suffix %q in completions %v", want, toStrings(newLine))
				}
			}
		})
	}
}

// TestVIInputFilter verifies vi-style modal key translation used by shell and
// PIN prompts through FuncFilterInputRune.
func TestVIInputFilter(t *testing.T) {
	v := newVIInputFilter()

	// Insert mode passes regular typing through unchanged.
	if r, ok := v.filter('x'); !ok || r != 'x' {
		t.Fatalf("insert mode passthrough got (%q,%v), want ('x',true)", r, ok)
	}

	// Esc enters normal mode and is swallowed.
	if r, ok := v.filter(readline.CharEsc); ok || r != 0 {
		t.Fatalf("esc got (%q,%v), want (0,false)", r, ok)
	}

	// Normal-mode movement mappings.
	cases := []struct {
		in   rune
		want rune
	}{
		{'h', readline.CharBackward},
		{'j', readline.CharNext},
		{'k', readline.CharPrev},
		{'l', readline.CharForward},
		{'w', readline.MetaForward},
		{'b', readline.MetaBackward},
		{'0', readline.CharLineStart},
		{'$', readline.CharLineEnd},
	}
	for _, tc := range cases {
		if r, ok := v.filter(tc.in); !ok || r != tc.want {
			t.Fatalf("normal mapping %q got (%q,%v), want (%q,true)", tc.in, r, ok, tc.want)
		}
	}

	// "i" returns to insert mode and is swallowed.
	if r, ok := v.filter('i'); ok || r != 0 {
		t.Fatalf("i got (%q,%v), want (0,false)", r, ok)
	}
	if r, ok := v.filter('z'); !ok || r != 'z' {
		t.Fatalf("insert mode after i got (%q,%v), want ('z',true)", r, ok)
	}

	// Ctrl-] should also enter normal mode.
	if r, ok := v.filter(29); ok || r != 0 {
		t.Fatalf("ctrl-] got (%q,%v), want (0,false)", r, ok)
	}
	if r, ok := v.filter('h'); !ok || r != readline.CharBackward {
		t.Fatalf("normal mode after ctrl-] got (%q,%v), want (CharBackward,true)", r, ok)
	}
}

// toStrings converts a [][]rune to []string for readable error output.
func toStrings(runes [][]rune) []string {
	out := make([]string, len(runes))
	for i, r := range runes {
		out[i] = string(r)
	}
	return out
}
