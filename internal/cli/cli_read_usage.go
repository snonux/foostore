package cli

// readUsage is the machine-facing read help text.
const readUsage = `usage: foostore read [--field NAME] [--kdbx-path PATH] [--backend keepass] [--timeout DURATION] [--exact] [--raw] [--non-interactive] REFERENCE

Reads exactly one secret and writes its raw bytes to stdout.
REFERENCE is the exact entry identity ("Group/Title"); an attachment is
selected by its reference form ("Group/Title/name"). Entry references require
--field NAME (e.g. --field Password); attachment references reject --field.
The reference must match the stored identity exactly (no normalisation);
use -- before a reference that starts with "-" (a reference literally
spelled "--help" or "-h" needs --). Sole --help prints this usage on
stdout with exit 0; sole -h is a usage error, not help.

Exit codes: 0 ok; 1 unexpected failure or timeout; 2 usage;
4 not found (the only suppressible code); 5 ambiguous identity;
6 locked or unusable credentials; 7 corrupt store; 8 store I/O.

Credentials resolve non-interactively: FOOSTORE_READ_PASSPHRASE_FD, then
kdbx_pass_file (regular file, owned by you, no group/world access). The
descriptor's writer must close its end (the passphrase is read to EOF); one
trailing line terminator is stripped. There is no $PIN or prompt fallback.
No shell, no fzf, no export, no git sync.`
