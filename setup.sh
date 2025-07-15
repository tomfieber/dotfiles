#!/bin/bash

# Exit on any error, undefined variables, and pipe failures
set -euo pipefail

# Update the system and install tools
xargs -a requirements.txt sudo apt-get install -y

# Change permissions on /opt to make this a bit easier
sudo chown -R $USER:$USER /opt

# Link the cheats directory
ln -s `pwd`/cheats/ "$HOME/.cheats"

# Link the zsh directory to .config/zsh
ln -s `pwd`/zsh/ "$HOME/.config/zsh"

# Link nvim directory
ln -s `pwd`/nvim/ "$HOME/.config/nvim"

# Link tmux directory
ln -s `pwd`/tmux/ "$HOME/.config/tmux"
