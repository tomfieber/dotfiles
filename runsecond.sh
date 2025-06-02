#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
# Fix shell comparison
cp -r $SCRIPT_DIR/cheats $HOME/.cheats
if [ "$SHELL" = "$(which zsh)" ]; then
    log_info "Copying zsh configuration files"
    cp -r $SCRIPT_DIR/zshrc $HOME/.zshrc
    cp -r $SCRIPT_DIR/zsh_shortcuts $HOME/.zsh_shortcuts
    cp -r $SCRIPT_DIR/zsh_aliases $HOME/.zsh_aliases
    cp -r $SCRIPT_DIR/th0m12.zsh-theme $HOME/.oh-my-zsh/themes/th0m12.zsh-theme
    cp -r $SCRIPT_DIR/tmux.conf $HOME/.tmux.conf
else
    log_info "Copying bash configuration files"
    cp -r $SCRIPT_DIR/zsh_shortcuts $HOME/.bash_shortcuts
    cp -r $SCRIPT_DIR/zsh_aliases $HOME/.bash_aliases 
fi

git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

asdf plugin add nodejs
asdf install nodejs latest
npm install -g pp-finder

pdtm -ia
