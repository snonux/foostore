# Fish wrapper and completion for ge (foostore shortcut)
# Install to ~/.config/fish/functions/ge.fish

function ge --description 'foostore wrapper with shortcuts'
    # If no arguments, run interactive mode
    if test (count $argv) -eq 0
        foostore shell
        return $status
    end

    set -l cmd $argv[1]

    # Check if first argument is a known command
    if contains $cmd (foostore commands 2>/dev/null)
        # It's a command, pass through to foostore
        foostore $argv
    else
        # Not a command, treat as search term
        foostore search $argv
    end
end

# Dynamically load commands from foostore
function __fish_ge_commands
    foostore commands 2>/dev/null
end

# Get list of entries for completion
function __fish_ge_entries
    # Only run if PIN is set to avoid interactive prompt
    if set -q PIN
        foostore ls 2>/dev/null | string replace -r ';.*$' '' | string trim
    end
end

# Complete subcommands or search terms
complete -c ge -f -n "__fish_use_subcommand" -a "(__fish_ge_commands)"
complete -c ge -f -n "__fish_use_subcommand" -a "(__fish_ge_entries)"

# Complete search terms for commands that need them
complete -c ge -f -n "__fish_seen_subcommand_from search cat paste export pathexport open edit rm" -a "(__fish_ge_entries)"

# Complete file paths for import
complete -c ge -n "__fish_seen_subcommand_from import" -F

# Complete directory paths for import destination
complete -c ge -n "__fish_seen_subcommand_from import; and __fish_is_nth_token 3" -F -a "(__fish_complete_directories)"

# Force flag for import
complete -c ge -n "__fish_seen_subcommand_from import; and __fish_is_nth_token 4" -f -a "force"

# Complete directory paths for import_r
complete -c ge -n "__fish_seen_subcommand_from import_r" -F -a "(__fish_complete_directories)"
