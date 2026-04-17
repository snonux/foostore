package keepass

import (
	"context"
	"sort"
	"strings"

	"codeberg.org/snonux/foostore/internal/picker"
	"codeberg.org/snonux/foostore/internal/store"
)

// Fzf launches fzf and returns only the selected description.
func (b *Backend) Fzf(ctx context.Context) (string, error) {
	result, err := b.FzfInteractive(ctx)
	if err != nil {
		return "", err
	}
	return result.Description, nil
}

// FzfInteractive launches fzf with action key bindings and returns the
// selected description plus the chosen action.
func (b *Backend) FzfInteractive(ctx context.Context) (store.PickerResult, error) {
	var indexes store.IndexSlice
	if err := b.WalkIndexes(ctx, "", func(idx *store.Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return store.PickerResult{}, err
	}
	if len(indexes) == 0 {
		return store.PickerResult{}, nil
	}

	sort.Sort(indexes)
	entries := buildPickerEntries(indexes)
	return runFzfInteractive(ctx, entries)
}

// buildPickerEntries converts a sorted IndexSlice into picker.Entry rows.
func buildPickerEntries(indexes store.IndexSlice) []picker.Entry {
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

// runFzfInteractive calls picker.Run and maps the chosen key to a PickerAction.
func runFzfInteractive(ctx context.Context, entries []picker.Entry) (store.PickerResult, error) {
	selection, err := picker.Run(ctx, entries)
	if err != nil {
		return store.PickerResult{}, err
	}
	action, ok := parsePickerAction(selection.Key)
	if !ok || selection.Description == "" {
		return store.PickerResult{}, nil
	}
	return store.PickerResult{
		Description: selection.Description,
		Action:      action,
	}, nil
}

// parsePickerAction maps an fzf key string to a PickerAction.
func parsePickerAction(keyLine string) (store.PickerAction, bool) {
	switch strings.TrimSpace(keyLine) {
	case "", "enter":
		return store.PickerSelect, true
	case "ctrl-t", "alt-t":
		return store.PickerCat, true
	case "ctrl-y", "alt-y":
		return store.PickerPaste, true
	case "ctrl-o", "alt-o":
		return store.PickerOpen, true
	case "ctrl-e", "alt-e":
		return store.PickerEdit, true
	default:
		return "", false
	}
}
