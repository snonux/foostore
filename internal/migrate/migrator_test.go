package migrate_test

import (
	"context"
	"strings"
	"testing"

	"codeberg.org/snonux/foostore/internal/migrate"
	"codeberg.org/snonux/foostore/internal/store"
)

// ---- ExtractPasswordFromContent tests ----------------------------------------

func TestExtractPasswordFromContent(t *testing.T) {
	cases := []struct {
		name          string
		input         string
		wantPassword  string
		wantNotesHas  string
		wantNotesMiss string
	}{
		{
			name:          "password line extracted",
			input:         "user: alice\npassword: s3cr3t\nurl: example.com\n",
			wantPassword:  "s3cr3t",
			wantNotesHas:  "user: alice",
			wantNotesMiss: "password: s3cr3t",
		},
		{
			name:          "pass shorthand extracted",
			input:         "pass: abc123\nhost: db.local",
			wantPassword:  "abc123",
			wantNotesHas:  "host: db.local",
			wantNotesMiss: "pass: abc123",
		},
		{
			name:          "case insensitive",
			input:         "PASSWORD: hidden\nother: line",
			wantPassword:  "hidden",
			wantNotesHas:  "other: line",
			wantNotesMiss: "PASSWORD",
		},
		{
			name:          "no password line",
			input:         "just notes\nno password here",
			wantPassword:  "",
			wantNotesHas:  "just notes",
			wantNotesMiss: "",
		},
		{
			name:          "only first password line taken",
			input:         "password: first\npassword: second",
			wantPassword:  "first",
			wantNotesMiss: "first",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pw, notes := migrate.ExtractPasswordFromContent(tc.input)
			if pw != tc.wantPassword {
				t.Errorf("password = %q; want %q", pw, tc.wantPassword)
			}
			if tc.wantNotesHas != "" && !strings.Contains(notes, tc.wantNotesHas) {
				t.Errorf("notes %q should contain %q", notes, tc.wantNotesHas)
			}
			if tc.wantNotesMiss != "" && strings.Contains(notes, tc.wantNotesMiss) {
				t.Errorf("notes %q should NOT contain %q", notes, tc.wantNotesMiss)
			}
		})
	}
}

// ---- Run tests with fakes ----------------------------------------------------

// fakeWalker implements StoreWalker using an in-memory list of entries.
type fakeWalker struct {
	indexes []*store.Index
	// dataByDesc maps description to raw content bytes.
	dataByDesc map[string][]byte
}

func (w *fakeWalker) WalkIndexes(_ context.Context, _ string, fn func(*store.Index) error) error {
	for _, idx := range w.indexes {
		if err := fn(idx); err != nil {
			return err
		}
	}
	return nil
}

func (w *fakeWalker) LoadData(_ context.Context, idx *store.Index) (*store.Data, error) {
	content := w.dataByDesc[idx.Description]
	return &store.Data{Content: content}, nil
}

// fakeKDBX records calls to UpsertTextEntry and UpsertBinaryEntry.
type fakeKDBX struct {
	texts    []string
	binaries []string
	saved    bool
}

func (k *fakeKDBX) UpsertTextEntry(groupPath []string, title, password, notes string) (bool, error) {
	k.texts = append(k.texts, title+"|"+password)
	return false, nil
}

func (k *fakeKDBX) UpsertBinaryEntry(groupPath []string, title, filename string, content []byte) (bool, error) {
	k.binaries = append(k.binaries, title)
	return false, nil
}

func (k *fakeKDBX) Save() error {
	k.saved = true
	return nil
}

func makeIndex(description string) *store.Index {
	return &store.Index{Description: description}
}

func TestRun_dryRun(t *testing.T) {
	walker := &fakeWalker{
		indexes: []*store.Index{
			makeIndex("work/notes"),
			makeIndex("images/logo.png"),
		},
		dataByDesc: map[string][]byte{
			"work/notes":      []byte("password: secret\nsome notes"),
			"images/logo.png": {0, 1, 2},
		},
	}

	var logged []string
	logFn := func(msg string) { logged = append(logged, msg) }
	warnFn := func(string) {}

	opts := migrate.Options{DryRun: true}
	stats, err := migrate.Run(context.Background(), walker, nil, opts, logFn, warnFn)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("Total = %d; want 2", stats.Total)
	}
	if stats.TextMigrated != 1 {
		t.Errorf("TextMigrated = %d; want 1", stats.TextMigrated)
	}
	if stats.BinaryMigrated != 1 {
		t.Errorf("BinaryMigrated = %d; want 1", stats.BinaryMigrated)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d; want 0", stats.Errors)
	}
	// Verify dry-run log messages are emitted for both entry types.
	foundText := false
	foundBinary := false
	for _, msg := range logged {
		if strings.Contains(msg, "DRY-RUN text migrate") {
			foundText = true
		}
		if strings.Contains(msg, "DRY-RUN binary migrate") {
			foundBinary = true
		}
	}
	if !foundText {
		t.Errorf("no 'DRY-RUN text migrate' message in logged: %v", logged)
	}
	if !foundBinary {
		t.Errorf("no 'DRY-RUN binary migrate' message in logged: %v", logged)
	}
}

func TestRun_liveWrites(t *testing.T) {
	walker := &fakeWalker{
		indexes: []*store.Index{
			makeIndex("finance/budget"),
			makeIndex("attachments/report.pdf"),
		},
		dataByDesc: map[string][]byte{
			"finance/budget":         []byte("password: money\nnotes line"),
			"attachments/report.pdf": {5, 6, 7},
		},
	}

	kdbx := &fakeKDBX{}
	opts := migrate.Options{DryRun: false}
	stats, err := migrate.Run(context.Background(), walker, kdbx, opts, func(string) {}, func(string) {})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.TextMigrated != 1 || stats.BinaryMigrated != 1 {
		t.Errorf("stats = %+v; want text=1 binary=1", stats)
	}
	if len(kdbx.texts) != 1 || !strings.Contains(kdbx.texts[0], "money") {
		t.Errorf("texts = %v; want password field 'money'", kdbx.texts)
	}
	if len(kdbx.binaries) != 1 {
		t.Errorf("binaries = %v; want 1 entry", kdbx.binaries)
	}
}
