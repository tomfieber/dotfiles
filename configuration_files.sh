#!/bin/bash
export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.pdtm/go/bin:$HOME/.cargo/bin:$HOME/.cargo/env:$PATH"

# Define logging function
log_info() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

log_debug() {
    echo -e "\033[0;33m[DEBUG]\033[0m $1"
}

# Get absolute script directory
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
log_info "Using script directory: $SCRIPT_DIR"

# Check if necessary files exist
check_file() {
    if [ ! -f "$1" ] && [ ! -d "$1" ]; then
        log_error "File or directory not found: $1"
        return 1
    fi
    return 0
}

# Copy a file with verbose output
copy_file() {
    local src="$1"
    local dest="$2"
    local msg="$3"
    
    if check_file "$src"; then
        log_info "Copying $msg"
        cp -rv "$src" "$dest" || log_error "Failed to copy $msg"
    fi
}

# Copy cheats directory
log_info "Copying cheats to home directory"
copy_file "$SCRIPT_DIR/cheats" "$HOME/.cheats" "cheats directory"
copy_file "$SCRIPT_DIR/opt/*" "/opt/" "opt files"

if [ "$SHELL" = "$(which zsh)" ]; then
    log_info "Detected ZSH shell, copying zsh configuration files"
    copy_file "$SCRIPT_DIR/zshrc" "$HOME/.zshrc" "zshrc"
    copy_file "$SCRIPT_DIR/zsh_shortcuts" "$HOME/.zsh_shortcuts" "zsh_shortcuts"
    copy_file "$SCRIPT_DIR/zsh_aliases" "$HOME/.zsh_aliases" "zsh_aliases"
    copy_file "$SCRIPT_DIR/zsh_createdir" "$HOME/.zsh_createdir" "createdir script"
    
    # Only copy theme if oh-my-zsh is installed
    if [ -d "$HOME/.oh-my-zsh" ]; then
        copy_file "$SCRIPT_DIR/th0m12.zsh-theme" "$HOME/.oh-my-zsh/themes/th0m12.zsh-theme" "theme"
    else
        log_error "Oh My Zsh not found - skipping theme installation. Run initial_setup.sh first."
    fi
    
    copy_file "$SCRIPT_DIR/tmux" "$HOME/.tmux.conf" "tmux.conf"
else
    log_info "Detected non-ZSH shell, copying bash configuration files"
    log_debug "Current shell is: $SHELL"
    copy_file "$SCRIPT_DIR/zsh_shortcuts" "$HOME/.bash_shortcuts" "bash_shortcuts"
    copy_file "$SCRIPT_DIR/zsh_aliases" "$HOME/.bash_aliases" "bash_aliases"
    copy_file "$SCRIPT_DIR/tmux" "$HOME/.tmux.conf" "tmux.conf"
    copy_file "$SCRIPT_DIR/bashrc" "$HOME/.bashrc" "bashrc" 
fi

log_info "Installing npm packages globally"
sudo npm install -g pp-finder

log_info "Installing pdtm"
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -ia