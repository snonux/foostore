# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`geheim.rb` is a single-file Ruby CLI for AES-256-CBC encryption of files and text. All secrets are stored in a Git repository with encrypted filenames (via SHA-256-hashed paths) and encrypted indices. The tool is designed for personal use on macOS, Linux, Android (Termux), and Windows.

## Running

```bash
ruby geheim.rb [command] [args]
```

No build step. No gems beyond Ruby's standard library (openssl, readline, etc. are all stdlib). No Gemfile.

## Testing

There is no test suite. Manual testing is done by running the script directly.

## Fish shell integration

```bash
./install-fish.sh          # installs completions/geheim.fish and completions/ge.fish
```

## Configuration

Config is read from `~/.config/geheim.json` at startup (merged over defaults in `Config::DEFAULTS`). Key fields:
- `data_dir`: Git repo where encrypted `.index` / `.data` file pairs are stored (default: `~/git/geheimlager`)
- `key_file`: Path to the raw encryption key file (default: `~/.geheimlager.key`)
- `export_dir`: Temporary directory for decrypted exports (default: `~/.geheimlagerexport`)
- `edit_cmd`: Editor used by the `edit` command (default: `hx`)
- `sync_repos`: List of git remote names to push/pull when syncing

The PIN (entered at startup or via `$PIN` env var) is used to derive the AES IV; the actual key comes from `key_file`.

## Architecture

All code lives in `geheim.rb`. The class/module hierarchy:

```
Log (module)           – formatted output: log/warn/prompt/fatal
Git (module)           – git add/rm/commit/status/sync operations
Encryption (module)    – AES-256-CBC encrypt/decrypt; reads PIN once into @@key/@@iv
Clipboard (module)     – paste password field to OS clipboard (macOS/GNOME)
CommitFile             – writes a file and git-adds it
  GeheimData           – one encrypted secret; encrypt/decrypt/export/reimport
  Index                – encrypted filename index; maps description → .data file via SHA256 hash
Geheim                 – main logic: fzf picker, search/add/import/rm/shred/walk_indexes
CLI                    – parses argv, runs the interactive shell loop (readline, vi mode)
```

Data storage: every entry is a pair of files in `data_dir`:
- `<sha256(dir)>/<sha256(name)>.index` – encrypted human-readable description/filename
- `<sha256(dir)>/<sha256(name)>.data`  – encrypted file content

Search (`walk_indexes`) decrypts every `.index` file and regex-matches against the description. `fzf` is used for interactive fuzzy selection.

## Key design constraints

- Encryption key and IV are class-level (`@@key`, `@@iv`) — initialized once per process from the key file and PIN.
- Commit messages are intentionally generic ("Changing stuff, not telling what in commit history") to avoid leaking metadata into git history.
- Binary vs text detection in `Index#binary?` is extension-based; known text extensions (`.txt`, `.README`, `.conf`, `.csv`, `.md`) are whitelisted.
- The `shred` command (GNU coreutils) is used when available; falls back to `rm -Pfv`.
