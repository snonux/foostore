// store_picker.go handles fzf/picker integration for the interactive secret browser.
// It wraps the internal/picker package to provide fuzzy-selection with action key
// bindings (cat, paste, open, edit) and maps the raw fzf output back to typed
// PickerResult values consumed by the CLI layer.
package store

import (
	"context"
	"os"
	"sort"
	"strings"

	"github.com/snonux/foostore/internal/picker"
)

// PickerAction describes the action requested from the interactive fzf picker.
type PickerAction string

const (
	PickerSelect PickerAction = "select"
	PickerCat    PickerAction = "cat"
	PickerPaste  PickerAction = "paste"
	PickerOpen   PickerAction = "open"
	PickerEdit   PickerAction = "edit"
)

// PickerResult is the selected description plus the desired action from fzf.
// Description is empty when the picker was cancelled.
type PickerResult struct {
	Description string
	Action      PickerAction
}

// Fzf launches fzf and returns only the selected description for compatibility
// with callers that do not care about picker action keys.
func (s *Store) Fzf(ctx context.Context) (string, error) {
	result, err := s.FzfInteractive(ctx)
	if err != nil {
		return "", err
	}
	return result.Description, nil
}

// FzfInteractive launches fzf with helper bars, preview metadata, and action
// key bindings, then returns both the selected description and action.
func (s *Store) FzfInteractive(ctx context.Context) (PickerResult, error) {
	var indexes IndexSlice
	if err := s.WalkIndexes(ctx, "", func(idx *Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return PickerResult{}, err
	}
	if len(indexes) == 0 {
		return PickerResult{}, nil
	}

	sort.Sort(indexes)
	entries := buildPickerEntries(indexes)

	return runFzfInteractive(ctx, entries)
}

// buildPickerEntries converts a sorted IndexSlice into picker.Entry values,
// annotating each entry with its kind (TEXT/BINARY) and a short hash suffix
// for visual disambiguation in the fzf list.
func buildPickerEntries(indexes IndexSlice) []picker.Entry {
	entries := make([]picker.Entry, 0, len(indexes))
	for i, idx := range indexes {
		kind := "TEXT"
		if idx.IsBinary() {
			kind = "BINARY"
		}
		hashSuffix := ""
		if len(idx.Hash) >= 63 {
			hashSuffix = idx.Hash[53:63]
		}
		entries = append(entries, picker.Entry{
			RowID:       i + 1,
			Description: idx.Description,
			Kind:        kind,
			HashSuffix:  hashSuffix,
		})
	}
	return entries
}

// runFzfInteractive delegates to picker.Run, then maps the raw fzf selection
// (key line + description) to a typed PickerResult. An empty or cancelled
// selection returns a zero PickerResult without error.
func runFzfInteractive(ctx context.Context, entries []picker.Entry) (PickerResult, error) {
	selection, err := picker.Run(ctx, entries)
	if err != nil {
		return PickerResult{}, err
	}

	action, ok := parsePickerAction(selection.Key)
	if !ok {
		return PickerResult{}, nil
	}
	if selection.Description == "" {
		return PickerResult{}, nil
	}

	return PickerResult{
		Description: selection.Description,
		Action:      action,
	}, nil
}

// buildFzfArgs returns the fzf argument slice for the given entry count,
// reading FOOSTORE_TUI_THEME and FOOSTORE_FZF_OPTS from the environment.
// Delegates to picker.BuildArgs so that the fzf argument format stays in one place.
func buildFzfArgs(entryCount int) []string {
	return picker.BuildArgs(
		entryCount,
		os.Getenv("FOOSTORE_TUI_THEME"),
		os.Getenv("FOOSTORE_FZF_OPTS"),
	)
}

// pickerColorTheme returns the fzf --color string for the named TUI theme.
// Delegates to picker.ColorTheme; unknown names fall back to the bold preset.
func pickerColorTheme(theme string) string {
	return picker.ColorTheme(theme)
}

// parsePickerResult decodes a raw fzf --expect output string into a PickerResult.
// idToDescription maps row-ID strings back to their human-readable descriptions.
// Returns a zero PickerResult when the key is unknown or the selection is empty.
func parsePickerResult(output string, idToDescription map[string]string) PickerResult {
	selection := picker.ParseSelection(output, idToDescription)
	action, ok := parsePickerAction(selection.Key)
	if !ok || selection.Description == "" {
		return PickerResult{}
	}
	return PickerResult{
		Description: selection.Description,
		Action:      action,
	}
}

// parsePickerAction maps an fzf key line (e.g. "ctrl-t", "enter") to a typed
// PickerAction. Returns (action, true) on a recognised key, ("", false) otherwise.
func parsePickerAction(keyLine string) (PickerAction, bool) {
	switch strings.TrimSpace(keyLine) {
	case "", "enter":
		return PickerSelect, true
	case "ctrl-t", "alt-t":
		return PickerCat, true
	case "ctrl-y", "alt-y":
		return PickerPaste, true
	case "ctrl-o", "alt-o":
		return PickerOpen, true
	case "ctrl-e", "alt-e":
		return PickerEdit, true
	default:
		return "", false
	}
}
