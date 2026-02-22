// package shell (internal test) exercises unexported types that cannot be
// reached from the external shell_test package.
package shell

import (
	"strings"
	"testing"
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

// toStrings converts a [][]rune to []string for readable error output.
func toStrings(runes [][]rune) []string {
	out := make([]string, len(runes))
	for i, r := range runes {
		out[i] = string(r)
	}
	return out
}
