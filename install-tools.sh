#!/usr/bin/env bash

# This script installs the necessary tools for the project. It is assumed that the following tools are installed:
# - zsh
# - oh-my-zsh
# - tmux
# - vim or mvim
# - git

# Install additional tools from individual tool lists

# Install Go tools
echo "Installing Go tools..."
xargs -I {} sh -c 'go install {}' < ./tools/go-tools.txt
echo "Go tools installation complete."

# Install Ruby tools
echo "Installing Ruby tools..."
xargs -I {} sh -c 'gem install {}' < ./tools/ruby-tools.txt
echo "Ruby tools installation complete."

# Install Rust tools
echo "Installing Rust tools..."
xargs -I {} sh -c 'cargo install {}' < ./tools/rust-tools.txt
echo "Rust tools installation complete."

# Install Python tools
echo "Installing Python tools..."
xargs -I {} sh -c 'uv tool install {}' < ./tools/python-tools.txt
echo "Python tools installation complete."


# Install complete
echo "All tools have been installed."