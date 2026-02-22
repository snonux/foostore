# Fish completion for foostore
# Install to ~/.config/fish/completions/foostore.fish

# Dynamically load commands from foostore
function __fish_foostore_commands
    foostore commands 2>/dev/null
end

# Get list of entries for completion
function __fish_foostore_entries
    # Only run if PIN is set to avoid interactive prompt
    if set -q PIN
        foostore ls 2>/dev/null | string replace -r ';.*$' '' | string trim
    end
end

# Complete subcommands
complete -c foostore -f -n "__fish_use_subcommand" -a "(__fish_foostore_commands)"

# Complete search terms for commands that need them
complete -c foostore -f -n "__fish_seen_subcommand_from search cat paste export pathexport open edit rm" -a "(__fish_foostore_entries)"

# Complete file paths for import
complete -c foostore -n "__fish_seen_subcommand_from import" -F

# Complete directory paths for import destination
complete -c foostore -n "__fish_seen_subcommand_from import; and __fish_is_nth_token 3" -F -a "(__fish_complete_directories)"

# Force flag for import
complete -c foostore -n "__fish_seen_subcommand_from import; and __fish_is_nth_token 4" -f -a "force"

# Complete directory paths for import_r
complete -c foostore -n "__fish_seen_subcommand_from import_r" -F -a "(__fish_complete_directories)"
