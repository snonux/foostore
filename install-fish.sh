#!/usr/bin/env bash

set -e

echo "Installing foostore fish shell integration..."

# Create directories if they don't exist
mkdir -p ~/.config/fish/completions
mkdir -p ~/.config/fish/functions

# Copy completion files
echo "Installing foostore completion..."
cp completions/foostore.fish ~/.config/fish/completions/

echo "Installing ge wrapper function..."
cp completions/ge.fish ~/.config/fish/functions/

echo ""
echo "✓ Fish integration installed successfully!"
echo ""
echo "Reload your fish shell with: exec fish"
echo ""
echo "See FISH_INTEGRATION.md for usage instructions."
