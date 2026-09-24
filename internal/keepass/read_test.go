package keepass

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/snonux/foostore/internal/config"
)

// createReadTestDB builds a KeePass database tailored to the machine-facing
// read tests: duplicate titles in one group (ambiguous identity), a field
// whose value carries a trailing newline (byte exactness), and an attachment
// containing NUL and 0xFF bytes (binary safety). Written with password
// "testpass".
func createReadTestDB(t *testing.T) string {
	t.Helper()
	return createReadTestDBVersion(t, false)
}

// createReadTestDBVersion is createReadTestDB in either KDBX 3.1 (the
// gokeepasslib default) or KDBX 4 (KeePassXC's default) format; the two report
// wrong passwords and store attachments differently.
func createReadTestDBVersion(t *testing.T, kdbx4 bool) string {
	t.Helper()

	var db *gokeepasslib.Database
	if kdbx4 {
		db = gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	} else {
		db = gokeepasslib.NewDatabase()
	}
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")

	addReadFixtureEntries(db)

	tmp, err := os.CreateTemp(t.TempDir(), "read-*.kdbx")
	if err != nil {
		t.Fatalf("creating temp kdbx: %v", err)
	}
	defer func() { _ = tmp.Close() }()
	if err := gokeepasslib.NewEncoder(tmp).Encode(db); err != nil {
		t.Fatalf("encoding test db: %v", err)
	}
	return tmp.Name()
}

// createReadTestDBWithoutTopLevelDot is createReadTestDB minus the top-level
// "." entry, so absent bare "." (and still-absent "..") exercise the absolute/
// traversal usage arm instead of exact match.
func createReadTestDBWithoutTopLevelDot(t *testing.T) string {
	t.Helper()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")
	addReadFixtureEntries(db)

	root := &db.Content.Root.Groups[0]
	filtered := root.Entries[:0]
	for _, e := range root.Entries {
		if e.GetTitle() == "." {
			continue
		}
		filtered = append(filtered, e)
	}
	root.Entries = filtered

	tmp, err := os.CreateTemp(t.TempDir(), "read-nodot-*.kdbx")
	if err != nil {
		t.Fatalf("creating temp kdbx: %v", err)
	}
	defer func() { _ = tmp.Close() }()
	if err := gokeepasslib.NewEncoder(tmp).Encode(db); err != nil {
		t.Fatalf("encoding test db: %v", err)
	}
	return tmp.Name()
}

// addReadFixtureEntries populates the entries and attachment cases shared by
// both KDBX versions.
func addReadFixtureEntries(db *gokeepasslib.Database) {
	root := gokeepasslib.NewGroup()
	root.Name = "Root"

	machine := gokeepasslib.NewGroup()
	machine.Name = "Machine"

	token := gokeepasslib.NewEntry()
	SetEntryField(&token, "Title", "token")
	SetEntryField(&token, "Password", "s3cret-value")
	SetEntryField(&token, "Notes", "line1\nline2\n")
	machine.Entries = append(machine.Entries, token)

	// Two entries with the same title in the same group: their flattened
	// descriptions collide, so an exact read must refuse to guess.
	dupeOne := gokeepasslib.NewEntry()
	SetEntryField(&dupeOne, "Title", "dupe")
	SetEntryField(&dupeOne, "Password", "first")
	dupeTwo := gokeepasslib.NewEntry()
	SetEntryField(&dupeTwo, "Title", "dupe")
	SetEntryField(&dupeTwo, "Password", "second")
	dupes := gokeepasslib.NewGroup()
	dupes.Name = "Dupes"
	dupes.Entries = append(dupes.Entries, dupeOne, dupeTwo)

	// Attachment content deliberately contains NUL, 0xFF and a trailing
	// newline so byte-for-byte fidelity is observable.
	blob := gokeepasslib.NewEntry()
	SetEntryField(&blob, "Title", "blob")
	binContent := []byte("BINARY\x00DATA\xff\n")
	bin := db.AddBinary(binContent)
	blob.Binaries = append(blob.Binaries, bin.CreateReference("blob.bin"))
	machine.Entries = append(machine.Entries, blob)

	// An entry whose stored title itself has a backslash and trailing space:
	// exact matching must reach it even though path-cleaning would not.
	odd := gokeepasslib.NewEntry()
	SetEntryField(&odd, "Title", `odd\name `)
	SetEntryField(&odd, "Password", "odd-value")
	machine.Entries = append(machine.Entries, odd)

	// Dot-titled entries under group "S": present identities that look
	// structural must still resolve by exact match.
	dots := gokeepasslib.NewGroup()
	dots.Name = "S"
	dot := gokeepasslib.NewEntry()
	SetEntryField(&dot, "Title", ".")
	SetEntryField(&dot, "Password", "dot-value")
	dotdot := gokeepasslib.NewEntry()
	SetEntryField(&dotdot, "Title", "..")
	SetEntryField(&dotdot, "Password", "dotdot-value")
	dots.Entries = append(dots.Entries, dot, dotdot)

	// Top-level entry titled "S": coexists with group identities S/. and S/..
	// so Clean("S/./") → "S" must not hint the parent when the literal misses.
	sEntry := gokeepasslib.NewEntry()
	SetEntryField(&sEntry, "Title", "S")
	SetEntryField(&sEntry, "Password", "s-plain-value")

	// Top-level entry titled ".": exact "." reads; Clean respellings "./" /
	// ".//" must hint the stored identity rather than report not-found.
	dotTop := gokeepasslib.NewEntry()
	SetEntryField(&dotTop, "Title", ".")
	SetEntryField(&dotTop, "Password", "top-dot-value")

	// Top-level "X" with no "X/." sibling: Clean("X/.") → "X" must be
	// not-found, not a "did you mean X?" usage error.
	xEntry := gokeepasslib.NewEntry()
	SetEntryField(&xEntry, "Title", "X")
	SetEntryField(&xEntry, "Password", "x-value")

	attach := newAttachEdgeCaseGroup(db)
	root.Entries = append(root.Entries, sEntry, dotTop, xEntry)
	root.Groups = append(root.Groups, machine, dupes, dots, attach)
	db.Content.Root.Groups = []gokeepasslib.Group{root}
}

// newAttachEdgeCaseGroup builds the "Attach" group: an unnamed attachment, two
// attachments sharing one name (ambiguous), and a reference whose binary
// payload is gone (corrupt). db supplies the binaries.
func newAttachEdgeCaseGroup(db *gokeepasslib.Database) gokeepasslib.Group {
	attach := gokeepasslib.NewGroup()
	attach.Name = "Attach"
	unnamed := gokeepasslib.NewEntry()
	SetEntryField(&unnamed, "Title", "unnamed")
	unnamed.Binaries = append(unnamed.Binaries, db.AddBinary([]byte("anon\n")).CreateReference(""))
	twins := gokeepasslib.NewEntry()
	SetEntryField(&twins, "Title", "twins")
	twins.Binaries = append(twins.Binaries,
		db.AddBinary([]byte("one")).CreateReference("same.bin"),
		db.AddBinary([]byte("two")).CreateReference("same.bin"))
	dangling := gokeepasslib.NewEntry()
	SetEntryField(&dangling, "Title", "dangling")
	goneRef := db.AddBinary([]byte("x")).CreateReference("gone.bin")
	goneRef.Value.ID = 4242
	dangling.Binaries = append(dangling.Binaries, goneRef)
	attach.Entries = append(attach.Entries, unnamed, twins, dangling)
	return attach
}

func newReadTestBackend(t *testing.T, dbPath string) *Backend {
	t.Helper()
	cfg := &config.Config{
		KDBXPath:  dbPath,
		ExportDir: filepath.Join(t.TempDir(), "export"),
	}
	b, err := New(cfg, "testpass", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestReadRawExactFieldBytes(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	ctx := context.Background()

	tests := []struct {
		name      string
		reference string
		field     string
		want      string
	}{
		{name: "password field", reference: "Machine/token", field: "Password", want: "s3cret-value"},
		{name: "title field", reference: "Machine/token", field: "Title", want: "token"},
		{name: "trailing newlines preserved byte for byte", reference: "Machine/token", field: "Notes", want: "line1\nline2\n"},
		{name: "stored title with backslash and trailing space is reachable exactly", reference: "Machine/odd\\name ", field: "Password", want: "odd-value"},
		{name: "present entry titled '.' is reachable exactly", reference: "S/.", field: "Password", want: "dot-value"},
		{name: "present entry titled '..' is reachable exactly", reference: "S/..", field: "Password", want: "dotdot-value"},
		{name: "present top-level entry S coexists with S/.", reference: "S", field: "Password", want: "s-plain-value"},
		{name: "present top-level entry titled '.' is reachable exactly", reference: ".", field: "Password", want: "top-dot-value"},
		{name: "present top-level entry X", reference: "X", field: "Password", want: "x-value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := b.ReadRaw(ctx, tc.reference, tc.field)
			if err != nil {
				t.Fatalf("ReadRaw(%q, %q): %v", tc.reference, tc.field, err)
			}
			if string(got) != tc.want {
				t.Fatalf("ReadRaw(%q, %q) = %q, want exactly %q", tc.reference, tc.field, got, tc.want)
			}
		})
	}
}

func TestReadRawAttachmentRawBytes(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))

	// The trailing newline is part of the stored attachment content and
	// must survive untouched — the whole point of the raw contract.
	want := []byte("BINARY\x00DATA\xff\n")
	got, err := b.ReadRaw(context.Background(), "Machine/blob/blob.bin", "")
	if err != nil {
		t.Fatalf("ReadRaw attachment: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("attachment bytes = %q, want exactly %q", got, want)
	}
}

func TestReadRawUnnamedAttachment(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	got, err := b.ReadRaw(context.Background(), "Attach/unnamed/attachment", "")
	if err != nil {
		t.Fatalf("an unnamed attachment is listed as .../attachment and must be readable: %v", err)
	}
	if string(got) != "anon\n" {
		t.Fatalf("bytes = %q, want exactly anon\\n", got)
	}
}

func TestReadRawFailures(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	ctx := context.Background()

	tests := []struct {
		name      string
		reference string
		field     string
		want      error
	}{
		{"unknown entry", "Machine/missing", "Password", ErrNotFound},
		{"absent title with literal backslash", `Machine/other\name`, "Password", ErrNotFound},
		{"backslash spelling of existing path is still absent", `Machine\token`, "Password", ErrNotFound},
		{"absent title with trailing space", "Machine/gone ", "Password", ErrNotFound},
		{"space spelling of existing path is still absent", "Machine/token ", "Password", ErrNotFound},
		{"backslash is not a traversal separator", `..\Machine/token`, "Password", ErrNotFound},
		{"absent dot-titled entry under Machine is not-found, not usage", "Machine/..", "Password", ErrNotFound},
		{"absent ./.. cleans to '..' but names no identity", "./..", "Password", ErrNotFound},
		{"absent X/. is not-found even when X exists", "X/.", "Password", ErrNotFound},
		{"absent S/./ drops trailing /. onto existing S, still not-found", "S/./", "Password", ErrNotFound},
		{"absent rewrite that cleans to nothing stored is not-found", "Machine//gone", "Password", ErrNotFound},
		{"missing field on existing entry", "Machine/token", "UserName", ErrNotFound},
		{"duplicate titles are ambiguous", "Dupes/dupe", "Password", ErrAmbiguous},
		{"Clean respelling of ambiguous identity is still ambiguous", "./Dupes/dupe", "Password", ErrAmbiguous},
		{"doubled-slash respelling of ambiguous identity is still ambiguous", "Dupes//dupe", "Password", ErrAmbiguous},
		{"dot-segment respelling of ambiguous identity is still ambiguous", "./Dupes/./dupe", "Password", ErrAmbiguous},
		{"entry reference without field is invalid", "Machine/token", "", ErrInvalidSelection},
		{"field on attachment reference is invalid", "Machine/blob/blob.bin", "Password", ErrInvalidSelection},
		{"empty reference is invalid", "", "Password", ErrInvalidSelection},
		{"traversal reference is invalid", "../Machine/token", "Password", ErrInvalidSelection},
		{"bare '..' is absolute/traversal usage when absent", "..", "Password", ErrInvalidSelection},
		{"dot segments are a non-canonical spelling, not an alias", "./Machine/./token", "Password", ErrInvalidSelection},
		{"leading slash is a non-canonical spelling", "/Machine/token", "Password", ErrInvalidSelection},
		{"doubled separator is a non-canonical spelling", "Machine//token", "Password", ErrInvalidSelection},
		{"Clean respelling of present top-level '.' is usage with hint", "./", "Password", ErrInvalidSelection},
		{"whitespace padding is a different literal identity", " Machine/token ", "Password", ErrNotFound},
		{"attachment name absent from an existing entry is not found", "Machine/token/nothing.bin", "", ErrNotFound},
		{"two attachments with one name are ambiguous", "Attach/twins/same.bin", "", ErrAmbiguous},
		{"dangling attachment reference is corruption", "Attach/dangling/gone.bin", "", ErrCorrupt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.ReadRaw(ctx, tc.reference, tc.field)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ReadRaw(%q, %q) error = %v, want %v", tc.reference, tc.field, err, tc.want)
			}
		})
	}
}

// TestNotFoundOrNonCanonicalMessages pins ef2 message rules: absolute/traversal
// arms name the top-level-group contract without a tautological "did you mean";
// Clean rewrites of an existing identity still hint the stored form — including
// "./" / ".//" when a top-level "." entry is present; Clean collapses that only
// drop a trailing "/." or "/.." stay not-found without either hint phrase.
// Clean respellings onto an ambiguous identity share ErrAmbiguous with the
// canonical spelling (no usage+hint exit class).
func TestNotFoundOrNonCanonicalMessages(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	ctx := context.Background()

	// Bare "." is present in the fixture and reads by exact match; bare ".."
	// remains absent so the absolute/traversal arm applies. ../Machine/token
	// still has a "../" Clean result; ../. and ../foo/.. Clean to bare ".."
	// but keep the "../" prefix on the reference — both arms are usage, not
	// not-found.
	absolute := []string{"/Machine/token", "..", "../Machine/token", "../.", "../foo/.."}
	for _, ref := range absolute {
		_, err := b.ReadRaw(ctx, ref, "Password")
		if !errors.Is(err, ErrInvalidSelection) {
			t.Fatalf("ReadRaw(%q) error = %v, want ErrInvalidSelection", ref, err)
		}
		msg := err.Error()
		if strings.Contains(msg, "did you mean") {
			t.Fatalf("ReadRaw(%q) error %q must not emit a tautological hint", ref, msg)
		}
		if !strings.Contains(msg, "absolute or traverses") {
			t.Fatalf("ReadRaw(%q) error %q must explain absolute/traversal", ref, msg)
		}
		if !strings.Contains(msg, "identities are relative to the top-level group") {
			t.Fatalf("ReadRaw(%q) error %q must pin the top-level-group contract", ref, msg)
		}
	}

	got, err := b.ReadRaw(ctx, ".", "Password")
	if err != nil {
		t.Fatalf("exact top-level '.' must read: %v", err)
	}
	if string(got) != "top-dot-value" {
		t.Fatalf("exact top-level '.' = %q, want top-dot-value", got)
	}

	_, err = b.ReadRaw(ctx, "./Machine/./token", "Password")
	if !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("rewrite of existing identity: error = %v, want ErrInvalidSelection", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, `did you mean "Machine/token"`) {
		t.Fatalf("rewrite hint missing stored identity: %q", msg)
	}

	_, err = b.ReadRaw(ctx, "./S", "Password")
	if !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("rewrite of existing top-level S: error = %v, want ErrInvalidSelection", err)
	}
	msg = err.Error()
	if !strings.Contains(msg, `did you mean "S"`) {
		t.Fatalf("rewrite of ./S should hint stored S: %q", msg)
	}

	for _, ref := range []string{"./", ".//", ".///"} {
		_, err := b.ReadRaw(ctx, ref, "Password")
		if !errors.Is(err, ErrInvalidSelection) {
			t.Fatalf("ReadRaw(%q) error = %v, want ErrInvalidSelection", ref, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, `did you mean "."?`) {
			t.Fatalf("ReadRaw(%q) error %q must hint stored top-level \".\"", ref, msg)
		}
		if strings.Contains(msg, "absolute or traverses") {
			t.Fatalf("ReadRaw(%q) error %q must use the hint arm, not absolute/traversal", ref, msg)
		}
	}

	// Clean onto an ambiguous stored identity must stay ErrAmbiguous — the
	// same class as the canonical spelling — not usage+hint (CLI exit 2).
	for _, ref := range []string{"./Dupes/dupe", "Dupes//dupe", "./Dupes/./dupe"} {
		_, err := b.ReadRaw(ctx, ref, "Password")
		if !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("ReadRaw(%q) error = %v, want ErrAmbiguous", ref, err)
		}
		msg := err.Error()
		if strings.Contains(msg, "did you mean") {
			t.Fatalf("ReadRaw(%q) error %q must not hint an ambiguous identity", ref, msg)
		}
		if !strings.Contains(msg, `identity "Dupes/dupe"`) {
			t.Fatalf("ReadRaw(%q) error %q must name the shared cleaned identity", ref, msg)
		}
	}

	// ./.. and foo/../.. Clean to ".." without a "../" prefix on the
	// reference, so they stay not-found (unlike ../. / ../foo/.. above).
	notFoundNoHint := []string{"Machine/..", "./..", "foo/../..", "X/.", "S/./"}
	for _, ref := range notFoundNoHint {
		_, err := b.ReadRaw(ctx, ref, "Password")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("ReadRaw(%q) error = %v, want ErrNotFound", ref, err)
		}
		msg := err.Error()
		if strings.Contains(msg, "did you mean") {
			t.Fatalf("ReadRaw(%q) error %q must not hint a Clean-collapsed parent", ref, msg)
		}
		if strings.Contains(msg, "absolute or traverses") {
			t.Fatalf("ReadRaw(%q) error %q must not use the absolute/traversal arm", ref, msg)
		}
	}
}

// TestAbsentBareDotAndDotDotAreUsage pins that bare "." and ".." are absolute/
// traversal usage when those top-level identities are absent. The main read
// fixture includes a top-level "." entry, so this uses a dedicated DB without
// that entry — removing reference == "." from the absolute check must fail.
func TestAbsentBareDotAndDotDotAreUsage(t *testing.T) {
	path := createReadTestDBWithoutTopLevelDot(t)
	b := newReadTestBackend(t, path)
	ctx := context.Background()

	for _, ref := range []string{".", ".."} {
		_, err := b.ReadRaw(ctx, ref, "Password")
		if !errors.Is(err, ErrInvalidSelection) {
			t.Fatalf("ReadRaw(%q) error = %v, want ErrInvalidSelection", ref, err)
		}
		msg := err.Error()
		if strings.Contains(msg, "did you mean") {
			t.Fatalf("ReadRaw(%q) error %q must not emit a tautological hint", ref, msg)
		}
		if !strings.Contains(msg, "absolute or traverses") {
			t.Fatalf("ReadRaw(%q) error %q must explain absolute/traversal", ref, msg)
		}
		if !strings.Contains(msg, "identities are relative to the top-level group") {
			t.Fatalf("ReadRaw(%q) error %q must pin the top-level-group contract", ref, msg)
		}
	}
}

// TestIsStructuralPathSyntax pins the named predicate that detects slash-based
// path syntax (leading '/', Clean to '.'/'..'/'../…', or any Clean rewrite).
// Classification into usage vs not-found also depends on stored identities and
// trailing "/." / "/.." handling in notFoundOrNonCanonical — this predicate
// alone does not decide the exit class.
func TestIsStructuralPathSyntax(t *testing.T) {
	cases := []struct {
		ref, cleaned string
		want         bool
	}{
		{"Machine/token", "Machine/token", false},
		{"/Machine/token", "/Machine/token", true},
		{".", ".", true},
		{"..", "..", true},
		{"../x", "../x", true},
		{"Machine/..", ".", true},
		{"Machine//token", "Machine/token", true},
		{"./Machine/token", "Machine/token", true},
		{"X/.", "X", true},
	}
	for _, tc := range cases {
		if got := isStructuralPathSyntax(tc.ref, tc.cleaned); got != tc.want {
			t.Errorf("isStructuralPathSyntax(%q, %q) = %v, want %v", tc.ref, tc.cleaned, got, tc.want)
		}
	}
}

func TestReadRawSelectionErrorsStayCLIIndependent(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	cases := []struct {
		reference, field string
		want             error
	}{
		{"Machine/token", "", ErrMissingField},
		{"Machine/blob/blob.bin", "Password", ErrFieldOnAttachment},
	}
	for _, tc := range cases {
		_, err := b.ReadRaw(context.Background(), tc.reference, tc.field)
		if err == nil {
			t.Fatalf("ReadRaw(%q, %q) unexpectedly succeeded", tc.reference, tc.field)
		}
		if !errors.Is(err, ErrInvalidSelection) || !errors.Is(err, tc.want) {
			t.Errorf("ReadRaw(%q, %q) = %v; want invalid selection and %v", tc.reference, tc.field, err, tc.want)
		}
		if strings.Contains(err.Error(), "--field") {
			t.Errorf("KeePass error contains CLI flag: %v", err)
		}
	}
}

// TestReadRawFailuresLeakNoSecretBytes pins the sanitized-failure contract:
// diagnostics name identities and error classes, never stored secret values.
func TestReadRawFailuresLeakNoSecretBytes(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	secrets := []string{"s3cret-value", "first", "second", "odd-value", "dot-value", "dotdot-value", "s-plain-value", "top-dot-value", "x-value"}
	cases := []struct{ reference, field string }{
		{"Machine/token", "UserName"},
		{"Machine/token", ""},
		{"Dupes/dupe", "Password"},
		{"Machine/blob/blob.bin", "Password"},
		{"Machine/missing", "Password"},
		{"Machine/..", "Password"},
		{"S/.", "UserName"},
		{"X/.", "Password"},
	}
	for _, tc := range cases {
		_, err := b.ReadRaw(context.Background(), tc.reference, tc.field)
		if err == nil {
			t.Fatalf("ReadRaw(%q, %q) unexpectedly succeeded", tc.reference, tc.field)
		}
		for _, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("ReadRaw(%q, %q) error %q leaks secret %q", tc.reference, tc.field, err, secret)
			}
		}
	}
}

func TestClassifyOpenError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error
	}{
		{name: "path error is I/O", in: &os.PathError{Op: "open", Path: "x", Err: os.ErrPermission}, want: ErrIO},
		{name: "wrapped path error is I/O", in: fmt.Errorf("opening: %w", &os.PathError{Op: "open", Path: "x", Err: os.ErrNotExist}), want: ErrIO},
		{name: "KDBX 3.1 wrong password is locked", in: errors.New("decoding: Wrong password? Database integrity check failed"), want: ErrLocked},
		{name: "KDBX 4 wrong password is locked", in: errors.New("decoding: Wrong password? HMAC-SHA256 of header mismatching"), want: ErrLocked},
		{name: "block HMAC failure is corrupt", in: errors.New("failed to verify HMAC"), want: ErrCorrupt},
		{name: "header hash mismatch is corrupt", in: errors.New("HeaderHash invalid"), want: ErrCorrupt},
		{name: "unknown failure is corrupt, never suppressible", in: errors.New("something unexpected"), want: ErrCorrupt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyOpenError(tc.in)
			if !errors.Is(got, tc.want) {
				t.Fatalf("classifyOpenError(%v) = %v, want %v", tc.in, got, tc.want)
			}
			if errors.Is(got, ErrNotFound) {
				t.Fatalf("open failure %v must never classify as the suppressible ErrNotFound", tc.in)
			}
		})
	}
	if got := classifyOpenError(nil); got != nil {
		t.Fatalf("classifyOpenError(nil) = %v, want nil", got)
	}
}

func TestReadRawHonoursCancelledContext(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.ReadRaw(ctx, "Machine/token", "Password")
	if err == nil {
		t.Fatal("cancelled context must fail the read")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want wrapped context.Canceled", err)
	}
}

// TestNewWrongCredentialsLocked pins the empirical classification with the
// real decoder for both on-disk formats: wrong credentials must surface as
// ErrLocked — never as a suppressible not-found and never as corruption.
func TestNewWrongCredentialsLocked(t *testing.T) {
	for _, kdbx4 := range []bool{false, true} {
		name := "KDBX3.1"
		if kdbx4 {
			name = "KDBX4"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{KDBXPath: createReadTestDBVersion(t, kdbx4)}
			_, err := New(cfg, "wrong-passphrase", nil)
			if !errors.Is(err, ErrLocked) {
				t.Fatalf("error = %v, want ErrLocked", err)
			}
			if _, err := New(cfg, "testpass", nil); err != nil {
				t.Fatalf("correct passphrase must still open the store: %v", err)
			}
		})
	}
}

// TestNewTruncatedFileIsCorruptNotPanic pins that a partially written store —
// the most realistic corruption — is reported as ErrCorrupt. gokeepasslib
// panics on some truncation points; New must convert that into an error.
func TestNewTruncatedFileIsCorruptNotPanic(t *testing.T) {
	for _, kdbx4 := range []bool{false, true} {
		full, err := os.ReadFile(createReadTestDBVersion(t, kdbx4))
		if err != nil {
			t.Fatal(err)
		}
		// Sweep many cut points: some hit header parsing, some block
		// boundaries, some mid-block (the panicking case). A KDBX 4 file
		// missing only its trailing empty terminator block still carries the
		// complete payload and legitimately opens, so the sweep stops short
		// of that tail.
		for cut := 1; cut < len(full)-64; cut += len(full)/37 + 1 {
			path := filepath.Join(t.TempDir(), "trunc.kdbx")
			if err := os.WriteFile(path, full[:cut], 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := New(&config.Config{KDBXPath: path}, "testpass", nil)
			if err == nil {
				t.Fatalf("kdbx4=%v cut=%d: truncated store opened successfully", kdbx4, cut)
			}
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrLocked) {
				t.Fatalf("kdbx4=%v cut=%d: error = %v, want ErrCorrupt (or ErrLocked)", kdbx4, cut, err)
			}
		}
	}
}

// TestReadRawKDBX4 covers the KDBX 4 attachment storage path end to end.
func TestReadRawKDBX4(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDBVersion(t, true))
	got, err := b.ReadRaw(context.Background(), "Machine/blob/blob.bin", "")
	if err != nil {
		t.Fatalf("ReadRaw attachment: %v", err)
	}
	if string(got) != "BINARY\x00DATA\xff\n" {
		t.Fatalf("attachment bytes = %q", got)
	}
	got, err = b.ReadRaw(context.Background(), "Machine/token", "Password")
	if err != nil || string(got) != "s3cret-value" {
		t.Fatalf("field read = %q, %v", got, err)
	}
}

// TestReadRawExactPositionalIdentity pins that identities are literal
// positions: a group merely named "Root" is part of the path (it must not alias
// its parent), and the top-level group's own name is never part of it.
func TestReadRawExactPositionalIdentity(t *testing.T) {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")

	newEntry := func(title, pass string) gokeepasslib.Entry {
		e := gokeepasslib.NewEntry()
		SetEntryField(&e, "Title", title)
		SetEntryField(&e, "Password", pass)
		return e
	}
	nested := gokeepasslib.NewGroup()
	nested.Name = "Root"
	nested.Entries = append(nested.Entries, newEntry("tok", "nested-value"), newEntry("", "untitled-value"))
	vault := gokeepasslib.NewGroup()
	vault.Name = "Vault"
	vault.Entries = append(vault.Entries, newEntry("tok", "outer-value"))
	vault.Groups = append(vault.Groups, nested)
	top := gokeepasslib.NewGroup()
	top.Name = "MyDatabase" // KeePass clients name the top group after the database
	top.Groups = append(top.Groups, vault)
	db.Content.Root.Groups = []gokeepasslib.Group{top}

	path := filepath.Join(t.TempDir(), "positional.kdbx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	b := newReadTestBackend(t, path)

	for ref, want := range map[string]string{
		"Vault/tok":      "outer-value",
		"Vault/Root/tok": "nested-value",
	} {
		got, err := b.ReadRaw(context.Background(), ref, "Password")
		if err != nil || string(got) != want {
			t.Fatalf("ReadRaw(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
	for _, ref := range []string{"MyDatabase/Vault/tok", "Vault/Root/", "Vault/(untitled)", "Vault/Root/(untitled)"} {
		if _, err := b.ReadRaw(context.Background(), ref, "Password"); err == nil {
			t.Fatalf("ReadRaw(%q) succeeded, want a failure: no such identity", ref)
		}
	}
}

// TestNewGarbageFileCorrupt pins that a non-kdbx file classifies as corrupt.
func TestNewGarbageFileCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.kdbx")
	if err := os.WriteFile(path, []byte("this is not a keepass database"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{KDBXPath: path}
	_, err := New(cfg, "testpass", nil)
	if err == nil {
		t.Fatal("garbage file must fail")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

// TestNewMissingFileIO pins that a missing store is an I/O failure — not the
// suppressible not-found, because a missing store is a configuration mistake.
func TestNewMissingFileIO(t *testing.T) {
	cfg := &config.Config{KDBXPath: filepath.Join(t.TempDir(), "missing.kdbx")}
	_, err := New(cfg, "testpass", nil)
	if err == nil {
		t.Fatal("missing store must fail")
	}
	if !errors.Is(err, ErrIO) {
		t.Fatalf("error = %v, want ErrIO", err)
	}
}

// setBinaryPayload replaces the stored payload of bin with a correctly encoded
// one, independent of gokeepasslib's writer (which never flushes its base64
// encoder and so drops up to two bytes of the tail). KDBX 4 keeps raw content;
// KDBX 3.1 stores base64 text, gzip-compressed when compressed is set.
func setBinaryPayload(t *testing.T, db *gokeepasslib.Database, bin *gokeepasslib.Binary, content []byte, compressed bool) {
	t.Helper()
	if db.Header.IsKdbx4() {
		bin.Content = append([]byte(nil), content...)
		return
	}
	payload := content
	if compressed {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		payload = buf.Bytes()
	}
	bin.Content = []byte(base64.StdEncoding.EncodeToString(payload))
	bin.Compressed = w.NewBoolWrapper(compressed)
}

// writeDBWithAttachment writes a database holding one attachment,
// Vault/item/data.bin, in the requested format and returns its path. mutate
// may adjust the binary before encoding.
func writeDBWithAttachment(t *testing.T, kdbx4 bool, mutate func(*gokeepasslib.Database, *gokeepasslib.Binary)) string {
	t.Helper()
	var db *gokeepasslib.Database
	if kdbx4 {
		db = gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	} else {
		db = gokeepasslib.NewDatabase()
	}
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")

	item := gokeepasslib.NewEntry()
	SetEntryField(&item, "Title", "item")
	bin := db.AddBinary([]byte("placeholder"))
	mutate(db, bin)
	item.Binaries = append(item.Binaries, bin.CreateReference("data.bin"))

	vault := gokeepasslib.NewGroup()
	vault.Name = "Vault"
	vault.Entries = append(vault.Entries, item)
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Groups = append(root.Groups, vault)
	db.Content.Root.Groups = []gokeepasslib.Group{root}

	path := filepath.Join(t.TempDir(), "attach.kdbx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReadRawAttachmentContentIsExact pins byte-exact attachments across every
// storage format and payload shape. Base64-looking and NUL-padded-looking
// payloads are the realistic secrets that gokeepasslib's own content helper
// mangles (it guesses base64 for KDBX 4 and leaves trailing NULs on padded
// uncompressed KDBX 3.1 data).
func TestReadRawAttachmentContentIsExact(t *testing.T) {
	payloads := map[string][]byte{
		"base64-shaped 4 chars":    []byte("abcd"),
		"valid padded base64":      []byte("dGVzdA=="),
		"valid unpadded base64":    []byte("QUJD"),
		"single byte":              []byte("a"),
		"empty":                    {},
		"binary with NUL and 0xff": []byte("BIN\x00DATA\xff\n"),
		"large repetitive 3 MiB":   bytes.Repeat([]byte("x"), 3<<20),
	}
	formats := []struct {
		name       string
		kdbx4      bool
		compressed bool
		libWriter  bool // keep gokeepasslib's own (trailer-truncating) writer
	}{
		{name: "KDBX4", kdbx4: true},
		{name: "KDBX3.1 uncompressed", compressed: false},
		{name: "KDBX3.1 gzip", compressed: true},
		{name: "KDBX3.1 gzip via gokeepasslib writer", compressed: true, libWriter: true},
	}
	for _, format := range formats {
		for name, content := range payloads {
			t.Run(format.name+"/"+name, func(t *testing.T) {
				path := writeDBWithAttachment(t, format.kdbx4, func(db *gokeepasslib.Database, bin *gokeepasslib.Binary) {
					if format.libWriter {
						if err := bin.SetContent(content); err != nil {
							t.Fatal(err)
						}
						return
					}
					setBinaryPayload(t, db, bin, content, format.compressed)
				})
				got, err := newReadTestBackend(t, path).ReadRaw(context.Background(), "Vault/item/data.bin", "")
				if err != nil {
					t.Fatalf("ReadRaw: %v", err)
				}
				if !bytes.Equal(got, content) {
					t.Fatalf("attachment bytes differ: got %d bytes %.40q, want %d bytes %.40q", len(got), got, len(content), content)
				}
			})
		}
	}
}

// TestReadRawCorruptAttachmentPayload pins that a damaged KDBX 3.1 attachment
// payload is an error, never partial bytes returned as a secret.
func TestReadRawCorruptAttachmentPayload(t *testing.T) {
	content := bytes.Repeat([]byte("secret-data-"), 200)
	gz := func() []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(content)
		_ = zw.Close()
		return buf.Bytes()
	}()
	// A stored (uncompressed) deflate block lets a single data byte be flipped
	// without breaking the deflate stream, so only the CRC can catch it.
	stored := func() []byte {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.NoCompression)
		_, _ = zw.Write(content)
		_ = zw.Close()
		return buf.Bytes()
	}()
	flipped := append([]byte(nil), stored...)
	flipped[gzipHeaderLen+5+10] ^= 0xff // inside the stored block's data
	badSize := append([]byte(nil), stored...)
	badSize[len(badSize)-3] ^= 0xff // a length byte that survives a 1-byte cut
	tests := []struct {
		name    string
		payload []byte // gzip bytes before base64
		raw     string // when set, stored verbatim instead of base64(payload)
	}{
		{name: "bit flip with the full trailer present", payload: flipped},
		{name: "bit flip hidden by a two-byte trailer truncation", payload: flipped[:len(flipped)-2]},
		{name: "wrong length byte hidden by a one-byte trailer truncation", payload: badSize[:len(badSize)-1]},
		{name: "not base64 at all", raw: "@@@ not base64 @@@"},
		{name: "not gzip", payload: []byte("plain text, not gzip")},
		{name: "deflate stream cut mid-way", payload: gz[:len(gz)/2]},
		{name: "trailer three bytes short", payload: gz[:len(gz)-3]},
		{name: "trailer completely missing", payload: gz[:len(gz)-gzipTrailerLen]},
		{name: "corrupted deflate data", payload: append(append([]byte(nil), gz[:20]...), bytes.Repeat([]byte{0xff}, len(gz)-20)...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeDBWithAttachment(t, false, func(db *gokeepasslib.Database, bin *gokeepasslib.Binary) {
				stored := tc.raw
				if stored == "" {
					stored = base64.StdEncoding.EncodeToString(tc.payload)
				}
				bin.Content = []byte(stored)
				bin.Compressed = w.NewBoolWrapper(true)
			})
			got, err := newReadTestBackend(t, path).ReadRaw(context.Background(), "Vault/item/data.bin", "")
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("ReadRaw = %.40q, %v; want ErrCorrupt", got, err)
			}
			if len(got) != 0 {
				t.Fatalf("a corrupt attachment returned %d partial bytes", len(got))
			}
		})
	}
}

func TestReadRawSecondAttachmentOfOneEntry(t *testing.T) {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpass")
	e := gokeepasslib.NewEntry()
	SetEntryField(&e, "Title", "multi")
	first, second := db.AddBinary([]byte("first-content")), db.AddBinary([]byte("second-content"))
	e.Binaries = append(e.Binaries, first.CreateReference("a.bin"), second.CreateReference("b.bin"))
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Entries = append(root.Entries, e)
	db.Content.Root.Groups = []gokeepasslib.Group{root}
	path := filepath.Join(t.TempDir(), "multi.kdbx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	b := newReadTestBackend(t, path)
	for ref, want := range map[string]string{"multi/a.bin": "first-content", "multi/b.bin": "second-content"} {
		got, err := b.ReadRaw(context.Background(), ref, "")
		if err != nil || string(got) != want {
			t.Fatalf("ReadRaw(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
}

// TestReadRawMultipleTopLevelGroupsIsCorrupt pins that a store whose entries
// could hide outside the walked group is refused instead of answering with a
// suppressible not-found for secrets that exist.
func TestReadRawMultipleTopLevelGroupsIsCorrupt(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	extra := gokeepasslib.NewGroup()
	extra.Name = "Second"
	e := gokeepasslib.NewEntry()
	SetEntryField(&e, "Title", "hidden")
	extra.Entries = append(extra.Entries, e)
	b.db.Content.Root.Groups = append(b.db.Content.Root.Groups, extra)

	_, err := b.ReadRaw(context.Background(), "Second/hidden", "Password")
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

// TestNewRejectsUnusableKeyMaterialAsLocked pins that key material the library
// cannot use is a locked-class failure whose message never quotes the key
// bytes (the library error names the first invalid byte).
func TestNewRejectsUnusableKeyMaterialAsLocked(t *testing.T) {
	cfg := &config.Config{KDBXPath: createReadTestDB(t)}
	key := []byte("<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>SECRETXYZ!!</Data></Key></KeyFile>")
	_, err := New(cfg, "testpass", key)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "'S'") {
		t.Fatalf("error %q leaks key-file bytes", err)
	}
}

func TestReadRawDuplicateFieldKeysAreAmbiguous(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	for _, ve := range exactIdentities(b.root()) {
		if ve.description == "Machine/token" {
			ve.entry.Values = append(ve.entry.Values,
				gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "shadow"}})
		}
	}
	_, err := b.ReadRaw(context.Background(), "Machine/token", "Password")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("error = %v, want ErrAmbiguous", err)
	}
	if strings.Contains(err.Error(), "shadow") || strings.Contains(err.Error(), "s3cret-value") {
		t.Fatalf("error %q leaks a field value", err)
	}
}

// TestReadRawBase64Whitespace pins that only ASCII line wrapping is tolerated
// inside a KDBX 3.1 base64 payload.
func TestReadRawBase64Whitespace(t *testing.T) {
	content := []byte("wrapped-secret-bytes")
	encoded := base64.StdEncoding.EncodeToString(content)
	wrapped := encoded[:8] + "\r\n" + encoded[8:16] + "\n  " + encoded[16:]

	read := func(stored string) ([]byte, error) {
		path := writeDBWithAttachment(t, false, func(_ *gokeepasslib.Database, bin *gokeepasslib.Binary) {
			bin.Content = []byte(stored)
			bin.Compressed = w.NewBoolWrapper(false)
		})
		return newReadTestBackend(t, path).ReadRaw(context.Background(), "Vault/item/data.bin", "")
	}
	if got, err := read(wrapped); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("ASCII-wrapped base64: got %q, %v; want %q", got, err, content)
	}
	for _, ws := range []string{"\u00a0", "\u0085", "\u2028"} {
		if got, err := read(encoded[:8] + ws + encoded[8:]); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Unicode whitespace %q inside base64: got %q, %v; want ErrCorrupt", ws, got, err)
		}
	}
}

// TestInteractiveBinaryDataResolvesUnnamedAttachment pins that the interactive
// attachment path uses the same display-name rule as the listing, so an
// unnamed attachment that is listed as ".../attachment" can also be opened.
func TestInteractiveBinaryDataResolvesUnnamedAttachment(t *testing.T) {
	b := newReadTestBackend(t, createReadTestDB(t))
	for _, ve := range walkEntries(b.root()) {
		if ve.description != "Attach/unnamed/attachment" {
			continue
		}
		d, err := b.binaryData(&ve)
		if err != nil {
			t.Fatalf("binaryData: %v", err)
		}
		if len(d.Content) == 0 {
			t.Fatal("binaryData returned no content for an unnamed attachment")
		}
		return
	}
	t.Fatal("the unnamed attachment is not listed")
}

// TestSanitizeRelativePathIsSlashBased pins the normalization used by other
// KeePass paths. Exact reads deliberately use literal identity semantics
// instead, including for backslashes and surrounding spaces.
func TestSanitizeRelativePathIsSlashBased(t *testing.T) {
	ok := map[string]string{
		"Machine/token":    "Machine/token",
		"/Machine/token":   "Machine/token",
		"Machine//token":   "Machine/token",
		"./Machine/./tok":  "Machine/tok",
		`Machine\token`:    "Machine/token",
		"  Machine/token ": "Machine/token",
		"a/b/../c":         "a/c",
	}
	for in, want := range ok {
		got, err := SanitizeRelativePath(in)
		if err != nil || got != want {
			t.Errorf("SanitizeRelativePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", ".", "..", "../x", "../../x", "a/../..", `..\x`} {
		if got, err := SanitizeRelativePath(in); err == nil {
			t.Errorf("SanitizeRelativePath(%q) = %q, want an error", in, got)
		}
	}
}
