package cli

import (
	"fmt"
	"strings"
)

// MachineReadArgs reports whether args (os.Args[1:]) invoke the machine-facing
// read command. Flags may precede the command word in any order — the global
// --backend and --kdbx-path as well as read's own flags, so a mis-ordered
// `foostore --field Password read X` is still a read.
//
// The command word is the first argument that is neither a flag nor a flag's
// value. When it is "read", the returned argument vector is args with the
// command word removed, every flag and value kept in place (including empty
// values, which parseReadFlags then rejects instead of silently selecting a
// default).
//
// Two argument shapes are machine reads even without a usable command word: a
// value flag directly followed by the word "read" (an unset shell variable
// swallowed the command word), which is returned as isRead with a usage error,
// and any flag only the read command understands (--field, --timeout, --exact,
// --raw, --non-interactive), where a missing command word is inferred because
// the interactive CLI has no use for such a flag and would otherwise mishandle
// it. Deciding this before any interactive initialisation is what keeps a
// machine caller's typo from falling through into a prompt, a shell, or an
// interactive keepass unlock. After an explicit command word the flags are
// unambiguous, so `read --field read X` selects a field named "read".
func MachineReadArgs(args []string) (argv []string, isRead bool, err error) {
	sawReadOnlyFlag := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case readFlagSpecs[arg].target != readNoValue && i+1 < len(args) && args[i+1] == "read":
			return nil, true, errCommandWordSwallowed(arg)
		case readFlagSpecs[arg].target != readNoValue:
			sawReadOnlyFlag = sawReadOnlyFlag || readFlagSpecs[arg].readOnly
			i++ // skip the flag's value, whatever it is
		case strings.HasPrefix(arg, "-"):
			sawReadOnlyFlag = sawReadOnlyFlag || readFlagSpecs[arg].readOnly || isReadOnlyEqualsForm(arg)
		case arg == "read":
			argv = make([]string, 0, len(args)-1)
			argv = append(argv, args[:i]...)
			return append(argv, args[i+1:]...), true, nil
		default:
			return inferredRead(args, sawReadOnlyFlag)
		}
	}
	return inferredRead(args, sawReadOnlyFlag)
}

// errCommandWordSwallowed explains the argument shape an unquoted empty shell
// variable produces: `--kdbx-path $UNSET read ...` arrives as `--kdbx-path
// read ...`, so the flag ate the command word.
func errCommandWordSwallowed(flag string) error {
	return fmt.Errorf("%s is directly followed by %q, the command word — an unset shell variable? Quote the variable, put the flag after the command word, or spell a store literally named read as ./read", flag, "read")
}

// inferredRead returns a copy of args as a read invocation when a read-only
// flag was seen, and reports "not a read" otherwise.
func inferredRead(args []string, sawReadOnlyFlag bool) ([]string, bool, error) {
	if !sawReadOnlyFlag {
		return nil, false, nil
	}
	return append([]string(nil), args...), true, nil
}
