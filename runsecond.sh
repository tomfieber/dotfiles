#!/bin/bash

pipx install git+https://github.com/Pennyw0rth/NetExec

cp th0m12.zsh-theme ~/.oh-my-zsh/themes/

git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

pdtm -ia

cp zshrc ~/.zshrc
