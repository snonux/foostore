// Package cli — fish shell integration subcommand.
//
// This file implements the "fish" subcommand, which prints the complete fish
// shell integration script (tab completion for foostore + the ge wrapper
// function) to stdout so users can source it directly:
//
//	foostore fish | source
//
// The script is generated at runtime using the resolved binary path so that
// completion helpers call the correct executable even when foostore is installed
// under a non-default name or path.
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// cmdFish prints the fish shell integration script to stdout and returns an
// exit code.  The binary path is resolved from os.Executable() so that the
// generated script calls the correct foostore binary regardless of where it is
// installed.
func (c *CLI) cmdFish(stdout io.Writer) int {
	binaryPath, err := os.Executable()
	if err != nil {
		binaryPath = "foostore"
	}
	script := FishIntegrationScript(binaryPath)
	if _, err := io.WriteString(stdout, script); err != nil {
		return 1
	}
	return 0
}

// FishIntegrationScript returns the complete fish shell integration script for
// the given binary path.  The script combines the foostore completion rules and
// the ge wrapper function so users need only source a single output:
//
//	foostore fish | source
//
// The binary name is extracted from binaryPath (basename without path) and used
// wherever "foostore" appears in complete directives, making the script
// correct even when the binary is renamed.
//
// This function is exported so cmd/foostore/main.go can short-circuit the
// "fish" subcommand before constructing a CLI — the script is purely static
// and needs no backend, cipher, store, git, or shell initialisation.  Avoiding
// that init shaves ~1.8s (KeePass Argon2 KDF) off every interactive fish
// shell startup that sources `foostore fish`.
func FishIntegrationScript(binaryPath string) string {
	bin := filepath.Base(binaryPath)
	var b strings.Builder

	writeFishHeader(&b, bin)
	writeFishCompletionFunctions(&b, bin, binaryPath)
	writeFishCompleteDirectives(&b, bin)
	writeFishGeFunction(&b, binaryPath)
	writeFishGeCompleteDirectives(&b)

	return b.String()
}

// writeFishHeader writes the preamble comment explaining how to source the script.
func writeFishHeader(b *strings.Builder, bin string) {
	fmt.Fprintf(b, "# Fish shell integration for %s\n", bin)
	fmt.Fprintf(b, "# Source with: %s fish | source\n", bin)
	fmt.Fprintf(b, "# Or add to ~/.config/fish/config.fish:\n")
	fmt.Fprintf(b, "#   %s fish | source\n\n", bin)
}

// writeFishCompletionFunctions writes the helper functions used by complete directives
// for dynamic command and entry completion.
func writeFishCompletionFunctions(b *strings.Builder, bin, binaryPath string) {
	// Dynamic command list helper — calls foostore commands at completion time.
	fmt.Fprintf(b, "# Dynamically load commands from %s\n", bin)
	fmt.Fprintf(b, "function __fish_%s_commands\n", bin)
	fmt.Fprintf(b, "    %s commands 2>/dev/null\n", binaryPath)
	fmt.Fprintf(b, "end\n\n")

	// Entry list helper — only runs when $PIN is set to avoid interactive prompts.
	fmt.Fprintf(b, "# Get list of entries for completion (only when PIN is set)\n")
	fmt.Fprintf(b, "function __fish_%s_entries\n", bin)
	fmt.Fprintf(b, "    if set -q PIN\n")
	fmt.Fprintf(b, "        %s ls 2>/dev/null | string replace -r ';.*$' '' | string trim\n", binaryPath)
	fmt.Fprintf(b, "    end\n")
	fmt.Fprintf(b, "end\n\n")
}

// writeFishCompleteDirectives writes the complete directives for the foostore command.
func writeFishCompleteDirectives(b *strings.Builder, bin string) {
	fmt.Fprintf(b, "# Complete subcommands for %s\n", bin)
	fmt.Fprintf(b, "complete -c %s -f -n '__fish_use_subcommand' -a '(__fish_%s_commands)'\n\n", bin, bin)

	fmt.Fprintf(b, "# Complete entry names for commands that accept a search term\n")
	fmt.Fprintf(b, "complete -c %s -f -n '__fish_seen_subcommand_from search cat paste export pathexport open edit rm' -a '(__fish_%s_entries)'\n\n", bin, bin)

	fmt.Fprintf(b, "# Complete file paths for import and attach\n")
	fmt.Fprintf(b, "complete -c %s -n '__fish_seen_subcommand_from import attach' -F\n\n", bin)

	fmt.Fprintf(b, "# Complete entry names as attach parent (third token)\n")
	fmt.Fprintf(b, "complete -c %s -f -n '__fish_seen_subcommand_from attach; and __fish_is_nth_token 3' -a '(__fish_%s_entries)'\n\n", bin, bin)

	fmt.Fprintf(b, "# Complete force flag for attach (fifth token)\n")
	fmt.Fprintf(b, "complete -c %s -n '__fish_seen_subcommand_from attach; and __fish_is_nth_token 5' -f -a 'force'\n\n", bin)

	fmt.Fprintf(b, "# Complete directory paths for import destination (third token)\n")
	fmt.Fprintf(b, "complete -c %s -n '__fish_seen_subcommand_from import; and __fish_is_nth_token 3' -F -a '(__fish_complete_directories)'\n\n", bin)

	fmt.Fprintf(b, "# Complete force flag for import (fourth token)\n")
	fmt.Fprintf(b, "complete -c %s -n '__fish_seen_subcommand_from import; and __fish_is_nth_token 4' -f -a 'force'\n\n", bin)

	fmt.Fprintf(b, "# Complete directory paths for import_r\n")
	fmt.Fprintf(b, "complete -c %s -n '__fish_seen_subcommand_from import_r' -F -a '(__fish_complete_directories)'\n\n", bin)
}

// writeFishGeFunction writes the ge wrapper function definition.
// The ge function provides shortcuts:
//   - No arguments → interactive shell mode
//   - First argument is a known command → pass through to foostore
//   - First argument is not a command → treat as search term
func writeFishGeFunction(b *strings.Builder, binaryPath string) {
	b.WriteString("# ge — foostore wrapper with shortcuts\n")
	b.WriteString("# Usage:\n")
	b.WriteString("#   ge             → interactive shell mode\n")
	b.WriteString("#   ge mypassword  → same as: foostore search mypassword\n")
	b.WriteString("#   ge cat mypass  → passes through to foostore\n")
	b.WriteString("function ge --description 'foostore wrapper with shortcuts'\n")
	b.WriteString("    # No arguments: enter interactive shell mode\n")
	b.WriteString("    if test (count $argv) -eq 0\n")
	fmt.Fprintf(b, "        %s shell\n", binaryPath)
	b.WriteString("        return $status\n")
	b.WriteString("    end\n\n")
	b.WriteString("    set -l cmd $argv[1]\n\n")
	b.WriteString("    # If first argument is a known foostore command, pass through\n")
	fmt.Fprintf(b, "    if contains $cmd (%s commands 2>/dev/null)\n", binaryPath)
	fmt.Fprintf(b, "        %s $argv\n", binaryPath)
	b.WriteString("    else\n")
	b.WriteString("        # Not a command: treat as a search term\n")
	fmt.Fprintf(b, "        %s search $argv\n", binaryPath)
	b.WriteString("    end\n")
	b.WriteString("end\n\n")
}

// writeFishGeCompleteDirectives writes completion directives for the ge wrapper.
// These mirror the foostore directives but apply to the "ge" command name.
func writeFishGeCompleteDirectives(b *strings.Builder) {
	b.WriteString("# ge completion: subcommands and bare search terms\n")
	b.WriteString("complete -c ge -f -n '__fish_use_subcommand' -a '(__fish_foostore_commands)'\n")
	b.WriteString("complete -c ge -f -n '__fish_use_subcommand' -a '(__fish_foostore_entries)'\n\n")

	b.WriteString("# ge completion: entry names for search-type commands\n")
	b.WriteString("complete -c ge -f -n '__fish_seen_subcommand_from search cat paste export pathexport open edit rm' -a '(__fish_foostore_entries)'\n\n")

	b.WriteString("# ge completion: file paths for import and attach\n")
	b.WriteString("complete -c ge -n '__fish_seen_subcommand_from import attach' -F\n\n")

	b.WriteString("# ge completion: entry names as attach parent (third token)\n")
	b.WriteString("complete -c ge -f -n '__fish_seen_subcommand_from attach; and __fish_is_nth_token 3' -a '(__fish_foostore_entries)'\n\n")

	b.WriteString("# ge completion: force flag for attach (fifth token)\n")
	b.WriteString("complete -c ge -n '__fish_seen_subcommand_from attach; and __fish_is_nth_token 5' -f -a 'force'\n\n")

	b.WriteString("# ge completion: directory paths for import destination (third token)\n")
	b.WriteString("complete -c ge -n '__fish_seen_subcommand_from import; and __fish_is_nth_token 3' -F -a '(__fish_complete_directories)'\n\n")

	b.WriteString("# ge completion: force flag for import (fourth token)\n")
	b.WriteString("complete -c ge -n '__fish_seen_subcommand_from import; and __fish_is_nth_token 4' -f -a 'force'\n\n")

	b.WriteString("# ge completion: directory paths for import_r\n")
	b.WriteString("complete -c ge -n '__fish_seen_subcommand_from import_r' -F -a '(__fish_complete_directories)'\n")
}
