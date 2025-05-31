#!/bin/bash

cp th0m12.zsh-theme ~/.oh-my-zsh/themes/

git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

asdf plugin add nodejs
asdf install nodejs latest
npm install -g pp-finder

pdtm -ia

cp zshrc ~/.zshrc
