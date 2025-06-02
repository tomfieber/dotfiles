#!/bin/bash

# Define logging function
log_info() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
# Fix shell comparison
log_info "Copying cheats to home directory"
cp -r "$SCRIPT_DIR/cheats" "$HOME/.cheats" || log_error "Failed to copy cheats directory"

if [ "$SHELL" = "$(which zsh)" ]; then
    log_info "Copying zsh configuration files"
    cp -r "$SCRIPT_DIR/zshrc" "$HOME/.zshrc" || log_error "Failed to copy zshrc"
    cp -r "$SCRIPT_DIR/zsh_shortcuts" "$HOME/.zsh_shortcuts" || log_error "Failed to copy zsh_shortcuts"
    cp -r "$SCRIPT_DIR/zsh_aliases" "$HOME/.zsh_aliases" || log_error "Failed to copy zsh_aliases"
    cp -r "$SCRIPT_DIR/th0m12.zsh-theme" "$HOME/.oh-my-zsh/themes/th0m12.zsh-theme" || log_error "Failed to copy theme"
    cp -r "$SCRIPT_DIR/tmux.conf" "$HOME/.tmux.conf" || log_error "Failed to copy tmux.conf"
else
    log_info "Copying bash configuration files"
    cp -r "$SCRIPT_DIR/zsh_shortcuts" "$HOME/.bash_shortcuts" || log_error "Failed to copy bash_shortcuts"
    cp -r "$SCRIPT_DIR/zsh_aliases" "$HOME/.bash_aliases" || log_error "Failed to copy bash_aliases"
fi

log_info "Installing zsh plugins"
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

log_info "Setting up asdf and node"
asdf plugin add nodejs
asdf install nodejs latest
npm install -g pp-finder

log_info "Installing pdtm"
pdtm -ia