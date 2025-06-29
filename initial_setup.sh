#!/bin/bash

# Install required packages
xargs -a requirements.txt sudo apt-get install -y

mkdir -p ~/.local/logging 

# Setup error logging
LOG_FILE="$HOME/.local/logging/initial-setup-$(date +%Y%m%d%H%M%S).log"
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' EXIT
exec 1>>"$LOG_FILE" 2>&1

# Function for logging
log_error() {
    echo "[ERROR] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&2
}

log_info() {
    echo "[INFO] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&3
}

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Error handling function
handle_error() {
    log_error "An error occurred on line $1"
}

# Set trap for error handling
trap 'handle_error $LINENO' ERR

# Progress indicator function
show_progress() {
    local action="$1"
    local package="$2"
    echo -ne "${BLUE}[*] ${action} ${package}...${NC}\r"
}

# Success indicator function
show_success() {
    local package="$1"
    echo -e "${GREEN}[✓] Successfully installed ${package}${NC}"
}

# Create necessary directories
sudo mkdir -p /opt/tools

# Copy configuration files
sudo cp -r opt/* /opt/

# Set permissions for /opt
sudo chown -R $USER:$USER /opt

# Add user to docker and sudo groups
sudo usermod -aG docker $USER
sudo usermod -aG sudo $USER

# Install pyenv if not already installed
if ! command -v pyenv &> /dev/null; then
    show_progress "Installing" "pyenv"
    log_info "Installing pyenv"
    
    curl https://pyenv.run | bash 2>>$LOG_FILE
    if [ $? -ne 0 ]; then
        log_error "Failed to install pyenv"
        echo -e "${RED}[✗] Failed to install pyenv${NC}"
    else
        export PATH="$HOME/.pyenv/bin:$PATH"
        eval "$(pyenv init --path)"
        eval "$(pyenv init -)"
        eval "$(pyenv virtualenv-init -)"
        show_success "pyenv"
    fi
else
    log_info "pyenv is already installed"
fi

go install github.com/asdf-vm/asdf/cmd/asdf@latest

# Make arsenal work
echo 'dev.tty.legacy_tiocsti = 1' | sudo tee /etc/sysctl.d/legacy_tiocsti.conf > /dev/null