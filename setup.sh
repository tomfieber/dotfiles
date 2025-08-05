#!/usr/bin/env bash

# This script sets up the environment for the project. It is assumed that the following tools are installed:
# - zsh
# - oh-my-zsh
# - tmux
# - vim or mvim
# - git
# - pipx
# - go
# - ruby
# - rust
# - python

# Install additional tools from individual tool lists

# Copy configuration files to the home directory
cp -r ./tmux/tmux.conf ~/.tmux.conf
cp -r ./zsh/zshrc ~/.zshrc
cp -r ./zsh/zsh_aliases ~/.zsh_aliases
cp -r ./zsh/zsh_shortcuts ~/.zsh_shortcuts
cp -r ./zsh/zsh_createdir ~/.zsh_createdir
cp -r ./cheats/ ~/.cheats

# Update system and install necessary packages
sudo apt update
xargs -I {} sh -c 'sudo apt install -y {}' < ./tools/apt-tools.txt

# Install tmux plugins
if [ -d ~/.tmux/plugins/tpm ]; then
  echo "tmux plugin manager already installed."
else
  git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
fi

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Promp the user to restart the system
echo "Setup complete. Please restart your terminal or system to apply the changes."
# If you are using a Mac, you might want to run the following command to apply changes:
# source ~/.zshrc
# If you are using a Linux system, you might want to run the following command to apply changes:
# source ~/.bashrc
# Note: If you are using a different shell, please adjust the source command accordingly.
# If you are using tmux, you might want to reload the tmux configuration:
# tmux source-file ~/.tmux.conf