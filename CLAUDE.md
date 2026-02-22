# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`foostore` is a Go CLI for AES-256-CBC encryption of files and text. All secrets are stored in a Git repository with encrypted filenames (via SHA-256-hashed paths) and encrypted indices. The tool is designed for personal use on macOS, Linux, Android (Termux), and Windows.

## Building and running

```bash
mage          # build (produces ./bin/foostore)
mage install  # install to $GOPATH/bin (default ~/go/bin)
mage test     # run all tests
mage vet      # run go vet
```

Or run directly after building:

```bash
./bin/foostore [command] [args]
```

## Testing

```bash
go test ./...
```

Table-driven unit tests exist for all internal packages.

## Fish shell integration

```bash
./install-fish.sh          # installs completions/geheim.fish and completions/ge.fish
```

## Configuration

Config is read from `~/.config/foostore.json` at startup (merged over defaults). Key fields:
- `data_dir`: Git repo where encrypted `.index` / `.data` file pairs are stored (default: `~/git/geheimlager`)
- `key_file`: Path to the raw encryption key file (default: `~/.geheimlager.key`)
- `export_dir`: Temporary directory for decrypted exports (default: `~/.geheimlagerexport`)
- `edit_cmd`: Editor used by the `edit` command (default: `hx`)
- `sync_repos`: List of git remote names to push/pull when syncing

The PIN (entered at startup or via `$PIN` env var) is used to derive the AES IV; the actual key comes from `key_file`.

## Architecture

```
cmd/foostore/main.go   – thin entry point: -version flag, signal context, calls cli.Run
internal/version/      – Version constant
internal/config/       – load ~/.config/foostore.json, merge over defaults
internal/crypto/       – AES-256-CBC encrypt/decrypt (byte-identical to Ruby reference)
internal/git/          – git add/rm/commit/status/sync subprocess wrappers
internal/store/        – secret store: add/import/remove/search/export over .index+.data pairs
internal/clipboard/    – paste password field to OS clipboard (macOS/GNOME)
internal/shell/        – readline shell with vi mode, tab completion, history dedup
internal/cli/          – command dispatch, interactive shell loop
```

Data storage: every entry is a pair of files in `data_dir`:
- `<sha256(dir)>/<sha256(name)>.index` – encrypted human-readable description/filename
- `<sha256(dir)>/<sha256(name)>.data`  – encrypted file content

Search (`WalkIndexes`) decrypts every `.index` file and regex-matches against the description. `fzf` is used for interactive fuzzy selection.

## Key design constraints

- Encryption key and IV are initialised once per process from the key file and PIN (`internal/crypto.Cipher`).
- Commit messages are intentionally generic ("Changing stuff, not telling what in commit history") to avoid leaking metadata into git history.
- Binary vs text detection in `Index.IsBinary()` is extension-based; known text extensions (`.txt`, `.README`, `.conf`, `.csv`, `.md`) are whitelisted.
- The `shred` command (GNU coreutils) is used when available; falls back to `rm -Pfv`.
- AES-256-CBC implementation is byte-identical to the original Ruby `geheim.rb` so existing encrypted databases remain readable.
