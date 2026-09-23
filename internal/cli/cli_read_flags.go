package cli

import (
	"fmt"
	"strings"
	"time"
)

// readFlagTarget identifies where a value flag stores its argument.
type readFlagTarget uint8

const (
	readNoValue readFlagTarget = iota
	readBackendValue
	readPathValue
	readFieldValue
	readTimeoutValue
)

type readFlagSpec struct {
	target   readFlagTarget
	readOnly bool
}

// readFlagSpecs is the sole declaration of accepted read flags. Detection,
// help scanning, and parsing all consult the same value and read-only traits.
var readFlagSpecs = map[string]readFlagSpec{
	"--backend":         {target: readBackendValue},
	"--kdbx-path":       {target: readPathValue},
	"--field":           {target: readFieldValue, readOnly: true},
	"--timeout":         {target: readTimeoutValue, readOnly: true},
	"--exact":           {readOnly: true},
	"--raw":             {readOnly: true},
	"--non-interactive": {readOnly: true},
}

// isReadOnlyEqualsForm catches a read-only value flag with unsupported = syntax.
func isReadOnlyEqualsForm(arg string) bool {
	name, _, equals := strings.Cut(arg, "=")
	spec, known := readFlagSpecs[name]
	return equals && known && spec.readOnly && spec.target != readNoValue
}

// wantsReadHelp reports whether argv asks for help. It is checked before flag
// parsing so `foostore read --help` documents the contract instead of failing
// as an unknown flag. Values of value flags (`--field -h`) and everything after
// "--" are data, never a help request: usage text must not be mistaken for the
// requested bytes.
func wantsReadHelp(argv []string) bool {
	for i := 0; i < len(argv); i++ {
		switch arg := argv[i]; {
		case arg == "--":
			return false
		case readFlagSpecs[arg].target != readNoValue:
			i++
		case arg == "--help" || arg == "-h":
			return true
		}
	}
	return false
}

// parseReadFlags scans argv for the read command's flags. Value flags use the
// documented space-separated form, take a non-empty value, and may be given at
// most once: a repeated flag is a usage error rather than a silent
// last-one-wins. --exact, --raw and
// --non-interactive are accepted as explicit no-ops so scripts can
// self-document the contract they rely on: read is always exact, raw and
// non-interactive. Anything starting with "-" that remains is rejected instead
// of being silently treated as a reference; "--" ends flag parsing so an entry
// identity that itself starts with "-" can still be addressed.
func parseReadFlags(argv []string) (readFlags, error) {
	opts, timeoutRaw, rest, err := scanReadFlags(argv)
	if err != nil {
		return opts, err
	}

	if timeoutRaw != "" {
		d, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return opts, fmt.Errorf("invalid --timeout %q: %v", timeoutRaw, err)
		}
		if d <= 0 {
			return opts, fmt.Errorf("--timeout must be positive, got %q", timeoutRaw)
		}
		opts.timeout = d
	}

	if len(rest) != 1 {
		return opts, fmt.Errorf("read takes exactly one reference (the exact entry identity), got %d arguments", len(rest))
	}
	opts.reference = rest[0]
	return opts, nil
}

// scanReadFlags walks argv once, applying the value flags and collecting the
// positional arguments. It returns the raw --timeout text so the caller can
// validate it after the scan.
func scanReadFlags(argv []string) (opts readFlags, timeoutRaw string, rest []string, err error) {
	opts.timeout = readDefaultTimeout
	seen := map[string]bool{}

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			return opts, timeoutRaw, append(rest, argv[i+1:]...), nil
		case readFlagSpecs[arg].target != readNoValue:
			if i+1 >= len(argv) {
				return opts, timeoutRaw, rest, fmt.Errorf("%s requires a value", arg)
			}
			if seen[arg] {
				return opts, timeoutRaw, rest, fmt.Errorf("%s given more than once", arg)
			}
			seen[arg] = true
			i++
			// An empty value is almost always an unset shell variable; taking
			// it as "not given" would silently select the default store.
			if argv[i] == "" {
				return opts, timeoutRaw, rest, fmt.Errorf("%s requires a non-empty value", arg)
			}
			setReadValueFlag(&opts, &timeoutRaw, readFlagSpecs[arg].target, argv[i])
		case readFlagSpecs[arg].readOnly:
			// Explicit no-ops; kept out of positional arguments.
		default:
			if strings.HasPrefix(arg, "-") {
				return opts, timeoutRaw, rest, fmt.Errorf("unknown flag %q", arg)
			}
			rest = append(rest, arg)
		}
	}
	return opts, timeoutRaw, rest, nil
}

// setReadValueFlag stores the value of one of the string-valued flags.
func setReadValueFlag(opts *readFlags, timeoutRaw *string, target readFlagTarget, value string) {
	switch target {
	case readBackendValue:
		opts.backend = value
	case readPathValue:
		opts.kdbxPath = value
	case readFieldValue:
		opts.field = value
	case readTimeoutValue:
		*timeoutRaw = value
	}
}
