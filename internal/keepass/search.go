package keepass

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/snonux/foostore/internal/store"
)

// Search collects all indexes matching searchTerm, sorts by Description,
// calls onMatch and actionFn per entry, and returns the sorted list.
func (b *Backend) Search(
	ctx context.Context,
	searchTerm string,
	action store.Action,
	actionFn func(context.Context, *store.Index, *store.Data) error,
	onMatch func(*store.Index),
) ([]*store.Index, error) {
	var indexes store.IndexSlice
	if err := b.WalkIndexes(ctx, searchTerm, func(idx *store.Index) error {
		indexes = append(indexes, idx)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Sort(indexes)

	for _, idx := range indexes {
		if onMatch != nil {
			onMatch(idx)
		}
		if err := b.applyAction(ctx, idx, action, actionFn); err != nil {
			return indexes, err
		}
	}
	return indexes, nil
}

// applyAction executes the requested action for a single matching Index.
// File-level actions (cat, export) are handled directly; external-tool actions
// (paste, open, edit) are delegated to the caller-supplied actionFn.
func (b *Backend) applyAction(ctx context.Context, idx *store.Index, action store.Action, actionFn func(context.Context, *store.Index, *store.Data) error) error {
	switch action {
	case store.ActionNone:
		return nil
	case store.ActionCat:
		return b.actionCat(ctx, idx)
	case store.ActionExport:
		return b.actionExport(ctx, idx, false)
	case store.ActionPathExport:
		return b.actionExport(ctx, idx, true)
	default:
		if actionFn != nil {
			d, err := b.LoadData(ctx, idx)
			if err != nil {
				return err
			}
			return actionFn(ctx, idx, d)
		}
	}
	return nil
}

// actionCat prints the decrypted content of an index entry to stdout.
// Binary entries are skipped with a warning.
func (b *Backend) actionCat(ctx context.Context, idx *store.Index) error {
	if idx.IsBinary() {
		fmt.Println("Not displaying/pasting binary data!")
		return nil
	}
	d, err := b.LoadData(ctx, idx)
	if err != nil {
		return err
	}
	fmt.Print(d.String())
	return nil
}

// actionExport writes the decrypted content to cfg.ExportDir.
// When fullPath is true the full description path is used; when false only the
// basename is used (matching the :export vs :pathexport behaviour).
func (b *Backend) actionExport(ctx context.Context, idx *store.Index, fullPath bool) error {
	d, err := b.LoadData(ctx, idx)
	if err != nil {
		return err
	}
	destFile := idx.Description
	if !fullPath {
		destFile = filepath.Base(idx.Description)
	}
	return d.Export(ctx, b.cfg.ExportDir, destFile)
}
