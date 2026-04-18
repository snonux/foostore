// Package cli — flag parsing helpers.
//
// This file contains the low-level argv scanning functions that extract
// global flags (--backend, --kdbx-path) before the command is dispatched.
// They are intentionally separate from the backend factory and the CLI struct
// so that flag parsing can be tested and reasoned about in isolation.
package cli

// parseBackendFlag scans argv for a "--backend VALUE" pair and returns the
// backend name and the remaining argv with that pair removed.  Returns ("", argv)
// when no --backend flag is present.  The flag may appear anywhere in argv.
//
// Note: only the space-separated form "--backend VALUE" is supported.
// The equals form "--backend=VALUE" is NOT parsed and will be silently ignored
// (treated as an unknown argument that propagates to the command dispatcher).
func parseBackendFlag(argv []string) (string, []string) {
	return parseFlagValue("--backend", argv)
}

// parseKDBXPathFlag scans argv for a "--kdbx-path VALUE" pair and returns the
// path and the remaining argv with that pair removed.  Returns ("", argv) when
// no --kdbx-path flag is present.  Overrides cfg.KDBXPath for the process
// lifetime without modifying the config file.
//
// Note: only the space-separated form "--kdbx-path VALUE" is supported.
func parseKDBXPathFlag(argv []string) (string, []string) {
	return parseFlagValue("--kdbx-path", argv)
}

// parseFlagValue is the shared implementation for single-value flag extraction.
// It scans argv for a "FLAG VALUE" pair, removes it, and returns the value and
// the remaining argv.  Returns ("", argv) when the flag is absent.
func parseFlagValue(flag string, argv []string) (string, []string) {
	for i, arg := range argv {
		if arg == flag && i+1 < len(argv) {
			remaining := make([]string, 0, len(argv)-2)
			remaining = append(remaining, argv[:i]...)
			remaining = append(remaining, argv[i+2:]...)
			return argv[i+1], remaining
		}
	}
	return "", argv
}
