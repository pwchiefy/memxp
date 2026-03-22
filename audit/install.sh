#!/bin/bash
# memxp-audit installer
# Sets up directories, copies prompts, installs the CLI command,
# and creates a config file from the template.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${HOME}/.local/share/memxp-audit"
CONFIG_DIR="${HOME}/.config/memxp-audit"
BIN_DIR="${HOME}/.local/bin"

echo "Installing memxp-audit..."

# Create directories
mkdir -p "$INSTALL_DIR/prompts" "$INSTALL_DIR/reports" "$INSTALL_DIR/checks"
mkdir -p "$CONFIG_DIR"
mkdir -p "$BIN_DIR"

# Copy prompt files (skip if source and dest are the same)
if [ -d "$SCRIPT_DIR/prompts" ]; then
    if [ "$(cd "$SCRIPT_DIR/prompts" && pwd)" != "$(cd "$INSTALL_DIR/prompts" 2>/dev/null && pwd)" ]; then
        cp "$SCRIPT_DIR/prompts/"*.md "$INSTALL_DIR/prompts/"
    fi
    echo "  Prompts installed to $INSTALL_DIR/prompts/"
else
    echo "ERROR: prompts/ directory not found in $SCRIPT_DIR"
    exit 1
fi

# Install the main script (skip if same file)
if [ "$(cd "$SCRIPT_DIR" && pwd)/memxp-audit.sh" != "$BIN_DIR/memxp-audit" ]; then
    cp "$SCRIPT_DIR/memxp-audit.sh" "$BIN_DIR/memxp-audit"
fi
chmod +x "$BIN_DIR/memxp-audit"
echo "  CLI installed to $BIN_DIR/memxp-audit"

# Create config from template if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.env" ]; then
    if [ -f "$SCRIPT_DIR/config.example.env" ]; then
        cp "$SCRIPT_DIR/config.example.env" "$CONFIG_DIR/config.env"
        echo "  Config created at $CONFIG_DIR/config.env"
        echo ""
        echo "  IMPORTANT: Edit $CONFIG_DIR/config.env with your settings:"
        echo "    - MEMORY_FILE: path to your MEMORY.md"
        echo "    - MEDITATION_FILE: path to your Meditation.md"
        echo "    - SSH_TARGETS (optional): your SSH hosts"
        echo "    - GH_OWNER (optional): your GitHub username/org"
    else
        echo "WARNING: config.example.env not found — create $CONFIG_DIR/config.env manually"
    fi
else
    echo "  Config already exists at $CONFIG_DIR/config.env (not overwritten)"
fi

echo ""
echo "Installation complete. Run 'memxp-audit' to generate your first report."
echo "Run 'memxp-audit --force' to re-generate even if today's report exists."
