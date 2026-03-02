package picker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Entry represents one selectable row in the interactive picker.
type Entry struct {
	RowID       int
	Description string
	Kind        string
	HashSuffix  string
}

// Selection is the parsed fzf output.
// Key is the pressed key from --expect (e.g. "ctrl-t", "enter", or "").
type Selection struct {
	Description string
	Key         string
}

// Run executes fzf and parses its output into a Selection.
func Run(ctx context.Context, entries []Entry) (Selection, error) {
	if len(entries) == 0 {
		return Selection{}, nil
	}
	if _, err := exec.LookPath("fzf"); err != nil {
		return Selection{}, fmt.Errorf("fzf not found in PATH")
	}

	input, idToDescription := BuildInput(entries)
	args := BuildArgs(
		len(entries),
		os.Getenv("FOOSTORE_TUI_THEME"),
		os.Getenv("FOOSTORE_FZF_OPTS"),
	)

	cmd := exec.CommandContext(ctx, "fzf", args...)
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Non-zero exit (for example ESC cancel) is treated as no selection.
		return Selection{}, nil
	}

	return ParseSelection(out.String(), idToDescription), nil
}

// BuildInput formats picker rows as tab-delimited input and builds an id map.
func BuildInput(entries []Entry) (string, map[string]string) {
	var b strings.Builder
	idToDescription := make(map[string]string, len(entries))
	for _, e := range entries {
		id := strconv.Itoa(e.RowID)
		idToDescription[id] = e.Description
		fmt.Fprintf(
			&b,
			"%s\t%s\t%s\t%s\n",
			id,
			SanitizeField(e.Description),
			SanitizeField(e.Kind),
			SanitizeField(e.HashSuffix),
		)
	}
	return b.String(), idToDescription
}

// BuildArgs returns fzf arguments for the interactive picker.
func BuildArgs(entryCount int, theme, extraOpts string) []string {
	header := "enter select | ctrl-t/alt-t cat | ctrl-y/alt-y paste | ctrl-o/alt-o open | ctrl-e/alt-e edit | esc cancel"
	status := fmt.Sprintf("foostore interactive picker | %d entries | metadata preview only", entryCount)
	args := []string{
		"--height=80%",
		"--layout=reverse",
		"--border",
		"--ansi",
		"--delimiter=\t",
		"--with-nth=2,3,4",
		"--prompt=secret> ",
		"--expect=enter,ctrl-t,ctrl-y,ctrl-o,ctrl-e,alt-t,alt-y,alt-o,alt-e",
		"--bind=ctrl-t:ignore,ctrl-y:ignore,ctrl-o:ignore,ctrl-e:ignore,alt-t:ignore,alt-y:ignore,alt-o:ignore,alt-e:ignore",
		"--header=" + header + "\n" + status,
		"--preview-window=down,6,wrap,border-top",
		"--preview=printf 'entry: %s\\nkind: %s\\nhash suffix: %s\\n' {2} {3} {4}",
		"--color=" + ColorTheme(theme),
	}
	if extra := strings.TrimSpace(extraOpts); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}
	return args
}

// ColorTheme returns the fzf --color value for a named theme.
func ColorTheme(theme string) string {
	switch strings.ToLower(strings.TrimSpace(theme)) {
	case "", "bold":
		return "fg:#f8fafc,bg:#0b1220,hl:#f59e0b,fg+:#ffffff,bg+:#1d4ed8,hl+:#fde047,info:#22d3ee,prompt:#f43f5e,pointer:#10b981,marker:#a78bfa,spinner:#fb7185,header:#38bdf8,border:#334155,separator:#0ea5e9,query:#e2e8f0,label:#f472b6"
	case "clean":
		return "fg:#e5e7eb,bg:#111827,hl:#93c5fd,fg+:#f9fafb,bg+:#1f2937,hl+:#93c5fd,info:#a7f3d0,prompt:#fbbf24,pointer:#34d399,marker:#34d399,spinner:#fbbf24,header:#a7f3d0,border:#374151"
	case "neon":
		return "fg:#d1fae5,bg:#020617,hl:#f0abfc,fg+:#ffffff,bg+:#0f172a,hl+:#f9a8d4,info:#67e8f9,prompt:#22d3ee,pointer:#22c55e,marker:#f472b6,spinner:#a78bfa,header:#38bdf8,border:#1d4ed8,separator:#22d3ee,query:#bbf7d0,label:#f0abfc"
	case "mono":
		return "fg:#e5e5e5,bg:#111111,hl:#ffffff,fg+:#ffffff,bg+:#222222,hl+:#ffffff,info:#d4d4d4,prompt:#ffffff,pointer:#ffffff,marker:#ffffff,spinner:#ffffff,header:#d4d4d4,border:#444444"
	default:
		return ColorTheme("bold")
	}
}

// SanitizeField removes tabs/newlines so each row stays tab-delimited.
func SanitizeField(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// ParseSelection decodes fzf --expect output.
func ParseSelection(output string, idToDescription map[string]string) Selection {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) < 2 {
		return Selection{}
	}

	key := strings.TrimSpace(lines[0])
	row := strings.TrimSpace(lines[1])
	if row == "" {
		return Selection{}
	}

	id := row
	if parts := strings.SplitN(row, "\t", 2); len(parts) > 0 {
		id = strings.TrimSpace(parts[0])
	}

	description, ok := idToDescription[id]
	if !ok || description == "" {
		return Selection{}
	}

	return Selection{
		Description: description,
		Key:         key,
	}
}
