#!/bin/bash

# Install required packages
xargs sudo apt-get install -y < requirements.txt 

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

# Install required packages
REQUIRED_PACKAGES=(
    wfuzz tesseract-ocr ipcalc antiword docker.io docker-compose
    python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
    prips libkrb5-dev dirb mingw-w64-tools mingw-w64-common g++-mingw-w64
    gcc-mingw-w64 upx-ucl osslsigncode git direnv fzf pipx zsh cewl snapd make
    libpcap-dev python3-netifaces python-dev-is-python3 build-essential
    libbz2-dev libreadline-dev libsqlite3-dev curl zlib1g-dev libncursesw5-dev
    xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev direnv
    python3-quamash python3-pyfiglet python3-pandas python3-shodan patchelf python3-aioquic 
)
for package in "${REQUIRED_PACKAGES[@]}"; do
    show_progress "Installing" "$package"
    log_info "Installing $package"
    
    if ! sudo apt install -y "$package" 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
    else
        show_success "$package"
    fi
done
# Create necessary directories
sudo mkdir -p /opt/{tools/powershell,lists,rules}

# Set permissions for /opt
sudo chown -R $USER:$USER /opt

# Copy configuration files
sudo cp -r opt/* /opt/

# Add user to docker and sudo groups
sudo usermod -aG docker $USER
sudo usermod -aG sudo $USER

# Run user mods
/usr/sbin/usermod -aG docker thomas
/usr/sbin/usermod -aG sudo thomas

chown -R thomas:thomas /opt

cp -r opt/* /opt/ 

# Install rustup and set up Rust
if ! command -v rustup &> /dev/null; then
    show_progress "Installing" "Rust"
    log_info "Installing Rust"
    
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>>$LOG_FILE
    if [ $? -ne 0 ]; then
        log_error "Failed to install Rust"
        echo -e "${RED}[✗] Failed to install Rust${NC}"
    else
        source $HOME/.cargo/env
        show_success "Rust"
    fi
else
    log_info "Rust is already installed"
fi

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

# Install go if not already installed
if ! command -v go &> /dev/null; then
    show_progress "Installing" "Go"
    log_info "Installing Go"
    
    if $SYSARCH = "x86_64"; then
        SYSARCH="amd64"
    elif $SYSARCH = "aarch64"; then
        SYSARCH="arm64"
    else
        log_error "Unsupported architecture: $SYSARCH"
        echo -e "${RED}[✗] Unsupported architecture: $SYSARCH${NC}"
        exit 1
    fi
    LATEST_GO_VERSION=$(curl -s 'https://go.dev/dl/?mode=json' | jq '.[].version' | head -n 1 | tr -d '"')
    wget "https://go.dev/dl/$LATEST_GO_VERSION.linux-$SYSARCH.tar.gz" -O /tmp/go.tar.gz 2>>$LOG_FILE
    if [ $? -ne 0 ]; then
        log_error "Failed to download Go"
        echo -e "${RED}[✗] Failed to download Go${NC}"
    else
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz 2>>$LOG_FILE
        export PATH=$PATH:/usr/local/go/bin
        show_success "Go"
    fi
    rm -rf /usr/local/go && tar -C /usr/local -xzf $LATEST_GO_VERSION.linux-$SYSARCH.tar.gz
else
    log_info "Go is already installed"
fi

# Install oh-my-zsh if not already installed
if [ ! -d "$HOME/.oh-my-zsh" ]; then
    show_progress "Installing" "Oh My Zsh"
    log_info "Installing Oh My Zsh"
    
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" --unattended 2>>$LOG_FILE
    if [ $? -ne 0 ]; then
        log_error "Failed to install Oh My Zsh"
        echo -e "${RED}[✗] Failed to install Oh My Zsh${NC}"
    else
        show_success "Oh My Zsh"
    fi
else
    log_info "Oh My Zsh is already installed"
fi

