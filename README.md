> **🚧 PRE-ALPHA SOFTWARE:** This project is in active early development, unstable, and intended for personal use. Expect bugs, breaking changes, missing safeguards, and possible data loss. Backward compatibility and upgrade paths are not guaranteed. Use at your own risk.

# foostore

This is an humble Go tool for text and binary document encryption. It uses `AES-256-CBC` by default and the initialization vector is generated from an user input PIN.

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

## Fish Shell Integration

Tab completion and a `ge` shortcut wrapper are provided for the [fish shell](https://fishshell.com/).

### Install

```bash
./install-fish.sh
exec fish
```

This copies `completions/foostore.fish` to `~/.config/fish/completions/` and `completions/ge.fish` to `~/.config/fish/functions/`.

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

See `FISH_INTEGRATION.md` for more details.

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
