# Fish Shell Integration for foostore

## Installation

### Automatic Installation

```bash
cd /home/paul/git/foostore
./install-fish.sh
```

### Manual Installation

1. Copy the completion file for `foostore`:
```bash
cp completions/foostore.fish ~/.config/fish/completions/
```

2. Copy the wrapper function for `ge`:
```bash
cp completions/ge.fish ~/.config/fish/functions/
```

3. Reload fish shell:
```bash
exec fish
```

## Usage

### `foostore` command

The `foostore` command now has full tab completion:
- Tab complete all subcommands (ls, search, cat, paste, etc.)
- Tab complete file paths for `import`
- Tab complete the `force` flag for import

### `ge` wrapper

The `ge` wrapper provides shortcuts:

```bash
# Interactive mode (no arguments)
ge

# Search shortcut (if not a known command, treats as search)
ge mypassword
# Same as: foostore search mypassword

# Explicit commands still work
ge cat mypassword
ge import file.txt backup/
ge import file.txt backup/ force
```

In interactive mode, empty `Enter` opens the fuzzy picker with direct action keys:
- `Enter` select
- `Ctrl-T` cat
- `Ctrl-Y` paste
- `Ctrl-O` open
- `Ctrl-E` edit

The picker preview remains metadata-only for safety (no decrypted secret preview).

### Dynamic Entry Completion

For better security, entry completion only works when the `PIN` environment variable is set:

```bash
# Set PIN for session (entries will autocomplete)
set -x PIN yourpin

# Use foostore with autocomplete
ge <TAB>

# Unset PIN when done
set -e PIN
```

Without `PIN` set, commands will still autocomplete, but entry names won't (to avoid prompting for PIN during tab completion).

## Features

- ✓ Dynamic command completion (fetched from `foostore commands`)
- ✓ Smart search fallback in `ge` wrapper
- ✓ Entry name completion (when PIN is set)
- ✓ File path completion for import/export
- ✓ Force flag completion
- ✓ No hardcoded command lists (stays in sync with foostore updates)
