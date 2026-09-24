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
	"path"
	"strings"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
)

// gzipHeaderLen is the length of the fixed header emitted by gzip.NewWriter;
// gokeepasslib never emits optional header fields.
const gzipHeaderLen = 10

// gzipTrailerLen is the CRC32 and ISIZE trailer at the end of a gzip stream.
const gzipTrailerLen = 8

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
// A reference with no exact match that is an absolute path, bare "." / ".."
// (only when those identities are absent), or whose reference or Clean result
// is still prefixed with "../" is a usage error — including forms like "../."
// and "../foo/.." that Clean to ".." but keep the "../" prefix on the
// reference. Forms that Clean to ".." without a "../" prefix (e.g. "./..",
// "foo/../..") only drop a trailing "/.." title segment and are not-found,
// so Clean never hints onto a stored top-level "..". A Clean rewrite of an
// existing identity ("./Group/Title", "Group//Title", or "./" / ".//" / "./." when a
// top-level "." entry exists) is a usage error with a hint naming the stored
// form when exactly one row matches; when several rows share that cleaned
// identity the miss is ErrAmbiguous — the same exit class as the canonical
// spelling. Clean that only strips a trailing "/." or "/.." title segment
// names a different identity from the parent, so an absent literal reports
// not-found even if the Clean-collapsed parent exists — unless a restored
// candidate is stored (e.g. "S/./" → "S/.", "./S/." → "S/.", "./." → "."),
// in which case the miss is usage+hint or ErrAmbiguous for that identity.
// Spaces and backslashes remain literal on a miss.
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
			return nil, fmt.Errorf("%w: %w: attachment reference %q cannot select a field", ErrInvalidSelection, ErrFieldOnAttachment, description)
		}
		return b.attachmentBytes(&ve)
	}

	if field == "" {
		return nil, fmt.Errorf("%w: %w: entry reference %q requires a field name", ErrInvalidSelection, ErrMissingField, description)
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

// isStructuralPathSyntax reports whether reference uses slash-based path
// syntax rather than a literal identity spelling. Each term is load-bearing:
// a leading '/', Clean collapsing to '.' or '..', a Clean result that still
// traverses upward, or any other Clean rewrite of the reference.
func isStructuralPathSyntax(reference, cleaned string) bool {
	return strings.HasPrefix(reference, "/") ||
		cleaned == "." ||
		cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") ||
		cleaned != reference
}

// countExactIdentity returns how many rows carry the given description.
func countExactIdentity(rows []virtualEntry, description string) int {
	n := 0
	for _, ve := range rows {
		if ve.description == description {
			n++
		}
	}
	return n
}

// dropsTrailingDotTitleSegment reports whether reference's final path segment
// is a literal "." or ".." (after trimming trailing slashes). path.Clean
// collapses those onto the parent path, but a title of "." or ".." is a
// distinct identity from that parent, so a miss must stay not-found rather
// than hinting the Clean-collapsed form — unless a restored candidate matches
// a stored identity (e.g. "S/./" → "S/.", "./S/." → "S/.", "./." → ".").
func dropsTrailingDotTitleSegment(reference string) bool {
	trimmed := strings.TrimRight(reference, "/")
	return strings.HasSuffix(trimmed, "/.") || strings.HasSuffix(trimmed, "/..")
}

// restoreDotTitleIdentities returns candidate stored identities for a
// reference that Clean-collapsed a trailing "/." or "/.." title segment.
// Order: slash-trimmed reference first ("S/./" → "S/."), then Clean's parent
// with the trailing segment restored ("./S/." → "S/."), or "." itself when
// Clean lands on "." from a "/." collapse ("./." / "././" → "."). Never
// returns the Clean-collapsed parent alone (absent "X/." with existing "X"
// stays not-found) and never restores onto ".." (Clean must not hint a
// stored top-level "..").
func restoreDotTitleIdentities(reference, cleaned string) []string {
	trimmed := strings.TrimRight(reference, "/")
	cands := []string{trimmed}

	var suffix string
	switch {
	case strings.HasSuffix(trimmed, "/.."):
		suffix = "/.."
	case strings.HasSuffix(trimmed, "/."):
		suffix = "/."
	default:
		return cands
	}

	var restored string
	switch {
	case cleaned == "." && suffix == "/.":
		restored = "."
	case cleaned != "." && cleaned != ".." && cleaned != "":
		restored = cleaned + suffix
	}
	if restored != "" && restored != trimmed {
		cands = append(cands, restored)
	}
	return cands
}

// notFoundOrNonCanonical classifies a reference that matched no entry.
// Absolute paths, bare "." / ".." (when those identities are absent), and
// references whose raw form or Clean result is still prefixed with "../" are
// usage errors (no tautological "did you mean" when Clean leaves them
// unchanged) — including "../." and "../foo/..", which Clean to ".." but keep
// the "../" prefix. Forms that Clean to ".." without a "../" prefix on the
// reference (e.g. "./..", "foo/../..") hit dropsTrailingDotTitleSegment and
// stay not-found; Clean therefore never hints onto a stored top-level "..".
// A Clean rewrite onto a stored identity is a usage error with a hint when
// exactly one row matches — including when Clean lands on a present
// top-level "." (e.g. "./", ".//", "./." → ".") — and ErrAmbiguous when several
// rows share that cleaned identity (same class as the canonical spelling).
// Clean that only strips a trailing "/." or "/.." title segment onto a
// different identity (Machine/.., X/.) stays not-found when no restored
// candidate is stored; when a restored candidate is stored (S/./ → S/.,
// ./S/. → S/., ./. → .), the miss is usage+hint or ErrAmbiguous for that
// identity instead of the Clean-collapsed parent. The "../" usage arm already
// claims "../"-prefixed forms before the hint arm. path.Clean leaves literal
// backslashes and spaces alone, so those misses stay not-found.
func notFoundOrNonCanonical(reference string, rows []virtualEntry) error {
	cleaned := path.Clean(reference)
	if !isStructuralPathSyntax(reference, cleaned) {
		return fmt.Errorf("%w: no entry %q", ErrNotFound, reference)
	}

	// Absolute or still-traversing forms take precedence over hints so a
	// "../"-prefixed spelling never becomes "did you mean ..?" even when a
	// top-level ".." identity exists. Bare "." / ".." only reach here when
	// those identities are absent (exact match would have succeeded).
	if strings.HasPrefix(reference, "/") || reference == "." || reference == ".." ||
		strings.HasPrefix(reference, "../") || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%w: reference %q is absolute or traverses; identities are relative to the top-level group", ErrInvalidSelection, reference)
	}

	// Respelling of a real identity: when Clean rewrote the reference onto a
	// stored form (including present top-level "."), ambiguous cleaned
	// identities share the canonical ErrAmbiguous exit class; a single match
	// hints the stored spelling. When Clean only dropped a trailing "." / ".."
	// title segment, try restored candidates (slash-trim, restored trailing
	// segment, or "." for "./."-style collapses); otherwise stay not-found
	// rather than hinting the parent.
	if cleaned != reference {
		if dropsTrailingDotTitleSegment(reference) {
			for _, cand := range restoreDotTitleIdentities(reference, cleaned) {
				switch n := countExactIdentity(rows, cand); {
				case n > 1:
					return fmt.Errorf("%w: %d entries share the identity %q; rename the duplicates so identities stay unique", ErrAmbiguous, n, cand)
				case n == 1:
					return fmt.Errorf("%w: reference %q is not in canonical form (did you mean %q?); references match the stored identity exactly", ErrInvalidSelection, reference, cand)
				}
			}
			return fmt.Errorf("%w: no entry %q", ErrNotFound, reference)
		}
		switch n := countExactIdentity(rows, cleaned); {
		case n > 1:
			return fmt.Errorf("%w: %d entries share the identity %q; rename the duplicates so identities stay unique", ErrAmbiguous, n, cleaned)
		case n == 1:
			return fmt.Errorf("%w: reference %q is not in canonical form (did you mean %q?); references match the stored identity exactly", ErrInvalidSelection, reference, cleaned)
		}
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

	rows := exactIdentities(b.root())
	var matches []virtualEntry
	for _, ve := range rows {
		if ve.description == description {
			matches = append(matches, ve)
		}
	}
	switch {
	case len(matches) == 0:
		return virtualEntry{}, notFoundOrNonCanonical(description, rows)
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
