#!/bin/bash

# Dry run version of install-tools.sh for testing
# This script will show what would be installed without actually installing anything

echo "=== DRY RUN MODE - No actual installations will be performed ==="
echo ""

# Source the main script but override installation functions
DRY_RUN=true

# Override installation functions for dry run
install_go() {
    echo "[DRY RUN] Would install Go package: $1"
}

install_pipx() {
    echo "[DRY RUN] Would install Python package: $1"
}

install_rust() {
    echo "[DRY RUN] Would install Rust package: $1"
}

install_gem() {
    echo "[DRY RUN] Would install Ruby gem: $1"
}

git_clone_tool() {
    echo "[DRY RUN] Would clone $1 to $2"
}

install_snap() {
    echo "[DRY RUN] Would install snap package: $1"
}

# Override system commands for dry run
command_exists() {
    case "$1" in
        "git"|"curl"|"wget"|"go"|"cargo"|"pipx"|"gem") return 0 ;;
        *) return 1 ;;
    esac
}

sudo() {
    echo "[DRY RUN] Would execute with sudo: $*"
}

mkdir() {
    echo "[DRY RUN] Would create directory: $*"
}

echo "Dry run completed. Run the actual install-tools.sh script to perform installations."
