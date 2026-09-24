> **🚧 PRE-ALPHA SOFTWARE:** This project is in active early development, unstable, and intended for personal use. Expect bugs, breaking changes, missing safeguards, and possible data loss. Backward compatibility and upgrade paths are not guaranteed. Use at your own risk.

# foostore

This is an humble Go tool for text and binary document encryption. The default backend is a KeePass database (`.kdbx`, password plus optional key file). The original backend (`geheim`) stores AES-256-CBC encrypted `.index`/`.data` pairs in a Git repository, with the initialization vector generated from a user input PIN. Note that the legacy CBC format has no authentication tag, so it should not be used for new infrastructure secrets.

This is for my own use. So the documentation here may be lacking. But feel free to try out yourself or ask!

## Features

* Works on MacOS, Linux and on Android via Termux.
* Encrypts and stores any type of documents and files (text, binary, etc). Meant for smaller files, such as text, PDFs, etc.
* All documents are stored in a Git repository.
* All file names are encrypted as well and kept in encrypted indices in the same Git repository.
* The indices are searchable through `fzf`, the fuzzy finder.
* The Git repository can be synchronized with N remote Git repositories (e.g. to two separate VMs for geo-redundancy).
* Text entries are edited using Helix  (or any other `$EDITOR`)
* Clipboard support for MacOS and GNOME (Linux).
* Interactive `foostore` shell support.
* Can import and export documuments in batches.
* Can shred exported data again.

## Machine-Facing Read (`foostore read`)

For automation, foostore offers a separate read command that is exact, raw, and non-interactive. It is defined for the KeePass backend only (the legacy geheim CBC store is not supported for machine reads) and it never prompts, opens a shell, uses fzf, touches the clipboard, exports files, or syncs git:

```bash
foostore read --field Password --exact --raw --non-interactive Vault/api-token
foostore read Vault/Blob/blob.bin      # attachment references need no --field
foostore --kdbx-path /srv/gonf.kdbx read --timeout 10s --field Password Vault/api-token
```

The reference is the exact entry identity: the group names below the database's top-level group (whatever it is called), then the entry title (`Group/Title`; for foostore-written databases the same string `ls` shows). Unlike `ls` nothing is dropped or renamed — a sub-group that happens to be called `Root` stays part of the path, and entries with an empty title have no addressable identity. An attachment is selected by its reference form (`Group/Title/name`). It is compared byte for byte with no trimming or path cleaning. A relative structural respelling (`./Vault/x`, `Vault//x`) that Cleans onto a single stored identity is a usage error (exit `2`); the same Clean onto an ambiguous identity is exit `5` (`ErrAmbiguous`, same class as the canonical spelling). Absolute or still-traversing forms (`/Vault/x`, `../Vault/x`, bare `..` when absent) are also usage (exit `2`) via the absolute/traversal arm, whether or not something is stored under a cleaned spelling. An absent identity containing literal spaces or backslashes is not-found (exit `4`). Flags take non-empty values only (an empty value is usually an unset shell variable and never selects a default), and may precede the command word in any order (a flag directly followed by the word `read` is refused before the command word — an unquoted unset shell variable produces that shape — so put such flags after the command, e.g. `foostore read --field read Vault/x`). Use `--` before a reference that starts with `-` (a reference literally spelled `--help` needs `--`); sole `--help` prints usage on stdout with exit `0`; sole `-h` is a usage error (exit `2`, usage on stderr). Entry references require `--field NAME` (e.g. `--field Password`, `--field UserName`); attachment references reject `--field`. Stdout carries only the requested bytes — trailing newlines and binary content are preserved byte for byte. Ambiguous identities (duplicate titles in one group, duplicate attachment names, or an entry with two fields of the requested name) are rejected instead of guessed.

Exit codes: `0` ok; `1` unexpected failure, timeout or signal cancellation; `2` usage; `4` not found (the only code automation may suppress); `5` ambiguous identity; `6` locked or unusable credentials; `7` corrupt store; `8` store I/O error (including an unreadable or malformed `~/.config/foostore.json` — a machine read never falls back to default settings). `--timeout` (default `30s`) bounds the whole read — waiting for the credential source, the KDF and the final stdout write (a consumer that stops reading can leave a prefix of the bytes behind, which the non-zero exit code marks as not the requested value); SIGINT/SIGTERM cancel at any of those points; diagnostics never contain secret bytes.

Credentials resolve non-interactively, in priority order:

1. `FOOSTORE_READ_PASSPHRASE_FD` — an inherited file descriptor carrying the passphrase (preferred for unattended machines; the secret travels through a kernel pipe, not the environment). The writer must close its end — the passphrase is everything up to end-of-file, at most 1 MiB. Exactly one trailing line terminator is stripped. Descriptors 1 and 2, non-numeric or non-canonical numbers, and descriptors that are not an inherited pipe, socket or regular file (close-on-exec descriptors, which the process opened itself, are never read) are refused; the descriptor is consumed and closed.
2. `kdbx_pass_file` — an explicit local tradeoff that must be set in the config file itself (the built-in `~/.master.pass` default is never used for machine reads); machine reads require a regular file owned by the current user with no group or world permission bits (`0600` and the stricter `0400` both pass), checked on the very handle that is then read (at most 1 MiB). All trailing CR and LF characters are stripped, matching interactive unlock. A missing, lax, foreign-owned or empty file fails loudly. The same rules apply to `kdbx_key_file`, and an empty key file is refused rather than ignored.

The descriptor source and the ownership/permission checks are Unix mechanisms: on other platforms (Windows) `FOOSTORE_READ_PASSPHRASE_FD` is refused and `kdbx_pass_file` is used without the owner-only checks, which have no equivalent there.

There is deliberately no `$PIN` or prompt fallback for machine reads: environment variables leak to child processes and `/proc/<pid>/environ`, and a prompt would block automation. A truncated or damaged store is reported as corrupt (`7`), never as a crash, and a store with more than one top-level group is refused as corrupt rather than answering not-found for entries that exist. Attachments come back byte for byte in KDBX 3.1 and KDBX 4 stores (base64-looking content is not decoded, padding is not appended); a damaged attachment payload is an error, never partial bytes. Reads need a resolvable home directory for `~/.config/foostore.json` — there is no shared-temp-directory fallback. A consumer that closes stdout early gets exit `8`, not a SIGPIPE death.

Unknown backend names fail instead of silently falling through to the legacy backend.

## Fish Shell Integration

Tab completion and a `ge` shortcut wrapper are provided for the [fish shell](https://fishshell.com/).

### Install

Source the integration script once to activate it for the current session, or add the line to `~/.config/fish/config.fish` for permanent activation:

```fish
foostore fish | source
```

### Usage

```bash
# Tab-complete foostore subcommands
foostore <TAB>

# ge wrapper: no arguments → interactive shell
ge

# ge wrapper: bare term → treated as search
ge mypassword        # same as: foostore search mypassword

# ge wrapper: explicit commands pass through
ge cat mypassword
ge import file.txt backup/
```

Entry-name completion is gated on the `PIN` environment variable to avoid interactive PIN prompts during tab completion:

```fish
set -x PIN yourpin   # enable entry completion for this session
ge <TAB>
set -e PIN           # clear when done
```

## Interactive Picker UX

In interactive shell mode (`foostore` with no arguments), pressing `Enter` on an empty line opens an enhanced fuzzy picker.

- `Enter`: select entry (updates `last`)
- `Ctrl-T`: `cat` selected entry
- `Ctrl-Y`: `paste` selected entry
- `Ctrl-O`: `open` selected entry
- `Ctrl-E`: `edit` selected entry
- `Esc`: cancel picker

The preview is metadata-only (description/type/hash suffix). Decrypted secret content is not shown in the picker preview.

Optional picker customization:

```bash
# presets: bold (default), clean, neon, mono
export FOOSTORE_TUI_THEME=clean

# append raw extra fzf options
export FOOSTORE_FZF_OPTS="--cycle --no-mouse"
```

PIN entry uses masked feedback (`*`) and vi-style line editing.
