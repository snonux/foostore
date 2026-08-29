// store_attachments.go lists binary child entries stored under a parent path.
// On the geheim backend these are separate .index/.data pairs whose
// descriptions are parent/filename; KeePass uses true entry attachments instead.
package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ListAttachments returns the filenames of binary entries stored directly under
// parentDesc. On geheim this means descriptions matching parentDesc/filename
// with no further path nesting.
func (s *Store) ListAttachments(ctx context.Context, parentDesc string) ([]string, error) {
	parentDesc = strings.TrimRight(parentDesc, "/")
	if parentDesc == "" {
		return nil, fmt.Errorf("attachments: empty parent entry")
	}
	prefix := parentDesc + "/"

	var names []string
	if err := s.WalkIndexes(ctx, "", func(idx *Index) error {
		if !strings.HasPrefix(idx.Description, prefix) {
			return nil
		}
		suffix := strings.TrimPrefix(idx.Description, prefix)
		if suffix == "" || strings.Contains(suffix, "/") {
			return nil
		}
		if !isBinaryDescription(suffix) {
			return nil
		}
		names = append(names, suffix)
		return nil
	}); err != nil {
		return nil, err
	}

	sort.Strings(names)
	return names, nil
}

// isBinaryDescription applies the geheim extension heuristic to a single path
// component (typically the attachment filename), not the full nested path.
func isBinaryDescription(description string) bool {
	idx := &Index{Description: description}
	return idx.IsBinary()
}
