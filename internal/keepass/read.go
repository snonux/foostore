// Package keepass — machine-facing exact lookup.
//
// This file implements the raw, non-interactive read contract used by the
// machine-facing `foostore read` command: one exact reference resolves to one
// entry row, and the requested bytes (a named entry field or raw attachment
// content) come back unmodified. It deliberately bypasses the human-oriented
// search/format layer: no regex matching, no formatting, no fallbacks.
package keepass

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
)

// ReadRaw resolves the exact entry identified by description and returns its
// raw bytes: the content of the named field when field is non-empty, or the
// raw attachment bytes when the reference selects an attachment row
// ("Group/Title/attachmentName"). The returned bytes are exactly what is
// stored — trailing newlines and binary content are preserved.
//
// A text entry reference requires field: there is no implicit default field,
// because machine consumers must name what they read. An attachment reference
// must not carry field. Failures map onto the sentinel classes from
// errors.go: ErrNotFound, ErrAmbiguous, ErrCorrupt, and ErrInvalidSelection;
// callers map them onto exit codes.
//
// The identity is the entry's literal position: the names of the groups below
// the database's first top-level group (whatever that group is called), then
// the entry title, then optionally the attachment name, joined with "/". For
// databases written by foostore this is the string `ls` shows. Unlike `ls` it
// never drops or renames anything: a group that happens to be called "Root"
// deeper in the tree stays part of the path, so it cannot alias a sibling
// path. Entries with an empty title have no addressable identity. The
// reference is compared byte for byte — no trimming, separator rewriting or
// path cleaning — so one spelling addresses exactly one entry and a stored
// title that itself contains spaces or backslashes stays reachable.
// A reference with no exact match that is merely a non-canonical spelling of
// another path (padding, "//", "./", a leading "/") is a usage error, not a
// not-found: not-found is the one class consumers may suppress, and a
// mistyped spelling must not look like an absent secret.
//
// Duplicate titles inside one group produce identical descriptions; such
// stores are rejected with ErrAmbiguous instead of guessing.
func (b *Backend) ReadRaw(ctx context.Context, description, field string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keepass read: %w", err)
	}
	if description == "" {
		return nil, fmt.Errorf("%w: empty entry reference", ErrInvalidSelection)
	}

	ve, err := b.resolveExact(description)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keepass read: %w", err)
	}

	if ve.isBinary {
		if field != "" {
			return nil, fmt.Errorf("%w: --field cannot select a field of attachment reference %q; drop --field to read the raw attachment bytes", ErrInvalidSelection, description)
		}
		return b.attachmentBytes(&ve)
	}

	if field == "" {
		return nil, fmt.Errorf("%w: entry reference %q requires --field NAME (for example --field Password); attachment references select raw bytes without --field", ErrInvalidSelection, description)
	}

	value, count := lookupEntryField(ve.entry, field)
	if count > 1 {
		return nil, fmt.Errorf("%w: entry %q has %d fields named %q", ErrAmbiguous, description, count, field)
	}
	if count == 0 {
		return nil, fmt.Errorf("%w: field %q does not exist on entry %q", ErrNotFound, field, description)
	}
	return []byte(value), nil
}

// exactIdentities flattens the group tree below top into virtualEntry rows
// whose descriptions are exact positional identities (see ReadRaw). It mirrors
// walkEntries' row shape — one text row per entry plus one row per attachment —
// but keeps every group name and title literally.
func exactIdentities(top *gokeepasslib.Group) []virtualEntry {
	var rows []virtualEntry
	collectExact(&rows, top, nil)
	return rows
}

// collectExact appends the rows of g's entries and, recursively, of its
// sub-groups. groupPath holds the names of the groups between the top-level
// group and g, so g's own name is only added for the children.
func collectExact(rows *[]virtualEntry, g *gokeepasslib.Group, groupPath []string) {
	for i := range g.Entries {
		e := &g.Entries[i]
		title := e.GetTitle()
		if title == "" {
			continue
		}
		*rows = append(*rows, virtualEntry{
			description: descriptionOf(groupPath, title, ""),
			entry:       e,
		})
		for _, binRef := range e.Binaries {
			attName := attachmentDisplayName(binRef.Name)
			*rows = append(*rows, virtualEntry{
				description:    descriptionOf(groupPath, title, attName),
				isBinary:       true,
				entry:          e,
				attachmentName: attName,
			})
		}
	}
	for i := range g.Groups {
		child := append(append([]string(nil), groupPath...), g.Groups[i].Name)
		collectExact(rows, &g.Groups[i], child)
	}
}

// notFoundOrNonCanonical classifies a reference that matched no entry: a
// spelling that differs from its own cleaned form (or is unsafe, such as a
// traversal) is an invalid selection, everything else is a plain not-found.
func notFoundOrNonCanonical(reference string) error {
	cleaned, err := SanitizeRelativePath(reference)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSelection, err)
	}
	if cleaned != reference {
		return fmt.Errorf("%w: reference %q is not in canonical form (did you mean %q?); references match the stored identity exactly", ErrInvalidSelection, reference, cleaned)
	}
	return fmt.Errorf("%w: no entry %q", ErrNotFound, reference)
}

// resolveExact finds the one row whose identity equals description. A missing
// identity is not-found (or an invalid selection for a mere respelling), and
// several rows with the same identity are ambiguous.
func (b *Backend) resolveExact(description string) (virtualEntry, error) {
	// A KeePass database has exactly one root group. Extra top-level groups
	// would be invisible to the identity walk, turning a secret that exists
	// into a suppressible not-found, so such a store is refused as corrupt.
	if n := len(b.db.Content.Root.Groups); n != 1 {
		return virtualEntry{}, fmt.Errorf("%w: database has %d top-level groups, expected exactly 1", ErrCorrupt, n)
	}

	var matches []virtualEntry
	for _, ve := range exactIdentities(b.root()) {
		if ve.description == description {
			matches = append(matches, ve)
		}
	}
	switch {
	case len(matches) == 0:
		return virtualEntry{}, notFoundOrNonCanonical(description)
	case len(matches) > 1:
		return virtualEntry{}, fmt.Errorf("%w: %d entries share the identity %q; rename the duplicates so identities stay unique", ErrAmbiguous, len(matches), description)
	}
	return matches[0], nil
}

// lookupEntryField returns the raw content of the named field and how many
// fields carry that key. Unlike getEntryField it distinguishes an absent field
// (count 0) from an empty one, because machine consumers must see not-found
// instead of silently empty bytes, and it reports duplicates (count > 1) so
// the caller can refuse to guess between them.
func lookupEntryField(e *gokeepasslib.Entry, key string) (value string, count int) {
	for _, v := range e.Values {
		if v.Key == key {
			if count == 0 {
				value = v.Value.Content
			}
			count++
		}
	}
	return value, count
}

// attachmentBytes resolves the binary reference behind an attachment row and
// returns its decompressed content. A dangling reference is corruption, not
// an absent secret: the row itself proves the reference existed.
func (b *Backend) attachmentBytes(ve *virtualEntry) ([]byte, error) {
	for _, binRef := range ve.entry.Binaries {
		if attachmentDisplayName(binRef.Name) != ve.attachmentName {
			continue
		}
		bin := b.db.FindBinary(binRef.Value.ID)
		if bin == nil {
			return nil, fmt.Errorf("%w: attachment %q references binary data that is no longer present", ErrCorrupt, ve.attachmentName)
		}
		content, err := b.binaryContent(bin)
		if err != nil {
			return nil, fmt.Errorf("%w: reading attachment %q: %v", ErrCorrupt, ve.attachmentName, err)
		}
		return content, nil
	}
	return nil, fmt.Errorf("%w: attachment %q not found on entry %q", ErrNotFound, ve.attachmentName, ve.description)
}

// binaryContent returns the exact stored bytes of an attachment. It replaces
// gokeepasslib's Binary.GetContentBytes, which guesses the storage format from
// the content itself: it base64-decodes any KDBX 4 payload that merely looks
// like base64 and leaves trailing NULs on padded uncompressed KDBX 3.1 data —
// both silently corrupt a secret stored as an attachment. The format is known
// from the database header, so it is decoded accordingly:
//
//   - KDBX 4: the inner-header payload is the raw content, never encoded.
//   - KDBX 3.1: the payload is base64 text inside the XML, gzip-compressed
//     when the Compressed attribute is set.
func (b *Backend) binaryContent(bin *gokeepasslib.Binary) ([]byte, error) {
	if b.db.Header.IsKdbx4() {
		return append([]byte(nil), bin.Content...), nil
	}

	// KeePass writes the base64 on one line; tolerate wrapped lines only, so
	// drop ASCII line breaks and blanks — never Unicode whitespace, which is
	// not part of the base64 alphabet and signals damage.
	encoded := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, string(bin.Content))
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 payload: %w", err)
	}
	if !bin.Compressed.Bool {
		return raw, nil
	}

	return gunzipExact(raw)
}

// gzipHeaderLen is the length of the fixed gzip header; gzip.NewWriter (used by
// gokeepasslib, and therefore by foostore itself) never emits optional header
// fields.
const gzipHeaderLen = 10

// gzipTrailerLen is the CRC32 + ISIZE trailer that ends a gzip stream.
const gzipTrailerLen = 8

// gunzipExact decompresses a gzip payload, returning exact bytes or an error.
//
// One writer artifact is tolerated. gokeepasslib writes KDBX 3.1 attachments
// through a base64 encoder it never flushes, so every attachment written by
// gokeepasslib — hence by foostore — loses up to two bytes at the very end of
// the payload: the tail of the gzip trailer. Go's gzip reader reports that as
// io.ErrUnexpectedEOF after delivering all data. It is accepted only when the
// deflate stream itself provably terminated (flate reached its final block)
// and at most two trailer bytes are missing; a stream cut anywhere else is
// corruption and must not be returned as a secret.
func gunzipExact(raw []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("opening gzip payload: %w", err)
	}
	defer func() { _ = zr.Close() }()
	content, err := io.ReadAll(zr)
	if err == nil {
		return content, nil
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) || len(raw) < gzipHeaderLen || raw[3] != 0 {
		return nil, fmt.Errorf("decompressing payload: %w", err)
	}

	// Re-read the bare deflate stream to learn whether it ended cleanly.
	rest := bytes.NewReader(raw[gzipHeaderLen:])
	content, err = io.ReadAll(flate.NewReader(rest))
	if err != nil {
		return nil, fmt.Errorf("decompressing payload: %w", err)
	}
	trailer := raw[len(raw)-rest.Len():]
	if missing := gzipTrailerLen - len(trailer); missing < 1 || missing > 2 {
		return nil, fmt.Errorf("decompressing payload: gzip trailer is %d bytes short", missing)
	}
	return content, verifyPartialTrailer(content, trailer)
}

// verifyPartialTrailer checks what survives of a gzip trailer (CRC32, then the
// low 32 bits of the length, both little-endian) against the decompressed
// content. Go's gzip reader never got to verify it, so the tolerated
// truncation must not also waive the integrity check: the CRC is fully present
// in every accepted case, and the length bytes that are present are compared
// too.
func verifyPartialTrailer(content, trailer []byte) error {
	if got, want := crc32.ChecksumIEEE(content), binary.LittleEndian.Uint32(trailer[:4]); got != want {
		return fmt.Errorf("decompressing payload: invalid checksum")
	}
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(content)))
	if !bytes.Equal(size[:len(trailer)-4], trailer[4:]) {
		return fmt.Errorf("decompressing payload: invalid length")
	}
	return nil
}
