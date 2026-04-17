// Package keepass provides a read-only backend.Backend implementation that
// reads secrets from a KeePass (.kdbx) database. It flattens KeePass groups
// into Description="Group/Subgroup/Title" entries and formats content as
// "Password:...\nUser:...\nURL:...\nNotes:\n..." text.
package keepass

import (
	"regexp"
	"strings"
)

// Content field patterns — compiled once at package init to avoid
// per-call regex allocation.
var (
	passwordPattern = regexp.MustCompile(`(?i)^\s*pass(?:word)?\s*:\s*(.*)\s*$`)
	userPattern     = regexp.MustCompile(`(?i)^\s*user(?:name)?\s*:\s*(.*)\s*$`)
	urlPattern      = regexp.MustCompile(`(?i)^\s*url\s*:\s*(.*)\s*$`)
	// notesPattern matches the "Notes:" header with nothing after the colon.
	// This is intentional: formatContent always emits "Notes:\n" on its own
	// line so that everything following the header is treated as multi-line
	// notes body. A "Notes: value" form on the same line is not produced by
	// formatContent and would be silently ignored during parseContent; that
	// case is explicitly unsupported to keep the parser simple.
	notesPattern = regexp.MustCompile(`(?i)^\s*notes\s*:\s*$`)
)

// formatContent builds the canonical multi-line text representation for a
// KeePass entry. The stable field order (Password / User / URL / Notes)
// ensures round-trips through parseContent are lossless.
//
// Output format:
//
//	Password: <value>
//	User: <value>
//	URL: <value>
//	Notes:
//	<notes lines>
func formatContent(password, user, url, notes string) []byte {
	var b strings.Builder
	b.WriteString("Password: ")
	b.WriteString(password)
	b.WriteByte('\n')
	b.WriteString("User: ")
	b.WriteString(user)
	b.WriteByte('\n')
	b.WriteString("URL: ")
	b.WriteString(url)
	b.WriteByte('\n')
	b.WriteString("Notes:\n")
	if notes != "" {
		b.WriteString(notes)
		if !strings.HasSuffix(notes, "\n") {
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
}

// parseContent is the inverse of formatContent. It tolerates missing or
// reordered fields and handles a multi-line Notes section. Lines that appear
// before a "Notes:" header are matched against the password/user/url patterns;
// everything after "Notes:" is collected verbatim.
//
// This generalises extractPasswordFromContent from internal/cli/migrate_kdbx.go
// to also handle User: and URL: fields.
func parseContent(content []byte) (password, user, url, notes string) {
	lines := strings.Split(string(content), "\n")
	inNotes := false
	var notesLines []string

	for _, line := range lines {
		if inNotes {
			notesLines = append(notesLines, line)
			continue
		}
		if notesPattern.MatchString(line) {
			inNotes = true
			continue
		}
		if m := passwordPattern.FindStringSubmatch(line); len(m) == 2 && password == "" {
			password = strings.TrimSpace(m[1])
			continue
		}
		if m := userPattern.FindStringSubmatch(line); len(m) == 2 && user == "" {
			user = strings.TrimSpace(m[1])
			continue
		}
		if m := urlPattern.FindStringSubmatch(line); len(m) == 2 && url == "" {
			url = strings.TrimSpace(m[1])
			continue
		}
	}

	notes = strings.TrimRight(strings.Join(notesLines, "\n"), "\n")
	return password, user, url, notes
}
