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

# Install oh-my-zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# Install tmux plugins
if [ -d ~/.tmux/plugins/tpm ]; then
  echo "tmux plugin manager already installed."
else
  git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
fi

echo "Installing zsh plugins..."
while IFS= read -r plugin_url; do
    # Skip empty lines
    if [ -z "$plugin_url" ]; then
        continue
    fi

    repo_name=$(basename "$plugin_url")
    dest_dir="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins/$repo_name"

    if [ -d "$dest_dir" ]; then
        echo "Plugin '$repo_name' already exists. Skipping."
    else
        git clone "$plugin_url" "$dest_dir"
    fi
done < ./tools/zsh-plugins.txt
echo "Zsh plugins installation complete."

# Moving the theme file to the custom themes directory
if [ -d "$ZSH_CUSTOM/themes" ]; then
    cp ./zsh/th0m12.zsh-theme "$ZSH_CUSTOM/themes/th0m12.zsh-theme"
else
    echo "Creating themes directory at $ZSH_CUSTOM/themes"
    mkdir -p "$ZSH_CUSTOM/themes"
    cp ./zsh/th0m12.zsh-theme "$ZSH_CUSTOM/themes/th0m12.zsh-theme"
fi

# Promp the user to restart the system
echo "Setup complete. Please restart your terminal or system to apply the changes."
# If you are using a Mac, you might want to run the following command to apply changes:
# source ~/.zshrc
# If you are using a Linux system, you might want to run the following command to apply changes:
# source ~/.bashrc
# Note: If you are using a different shell, please adjust the source command accordingly.
# If you are using tmux, you might want to reload the tmux configuration:
# tmux source-file ~/.tmux.conf