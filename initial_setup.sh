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

log_warning() {
    echo "[WARNING] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&2
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

# Copy configuration files
sudo cp -r opt/ /opt/

# Set permissions for /opt
sudo chown -R $USER:$USER /opt

# Add user to docker and sudo groups
sudo usermod -aG docker $USER
sudo usermod -aG sudo $USER

# Install Go if not already installed
if ! command -v go &> /dev/null; then
    show_progress "Installing" "Go"
    log_info "Installing Go (latest stable version)"
    
    # Get the latest Go version
    GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n1)
    if [ -z "$GO_VERSION" ]; then
        log_warning "Could not fetch latest Go version, using fallback"
        GO_VERSION="go1.21.5"
    fi
    
    # Determine architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) GO_ARCH="amd64" ;;
        aarch64|arm64) GO_ARCH="arm64" ;;
        armv7l) GO_ARCH="armv6l" ;;
        *) 
            log_error "Unsupported architecture: $ARCH"
            GO_ARCH="amd64"
            ;;
    esac
    
    # Download and install Go
    GO_TARBALL="${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TARBALL}"
    
    cd /tmp || exit 1
    if wget -q "$GO_URL" 2>>$LOG_FILE; then
        # Remove any existing Go installation
        sudo rm -rf /usr/local/go
        
        # Extract new Go installation
        if sudo tar -C /usr/local -xzf "$GO_TARBALL" 2>>$LOG_FILE; then
            # Update PATH for current session
            export PATH="/usr/local/go/bin:$PATH"
            
            # Verify installation
            if /usr/local/go/bin/go version >/dev/null 2>&1; then
                show_success "Go ($GO_VERSION)"
                log_info "Go installed successfully: $(/usr/local/go/bin/go version)"
            else
                log_error "Go installation verification failed"
                echo -e "${RED}[✗] Failed to verify Go installation${NC}"
            fi
        else
            log_error "Failed to extract Go tarball"
            echo -e "${RED}[✗] Failed to extract Go${NC}"
        fi
        
        # Cleanup
        rm -f "$GO_TARBALL"
    else
        log_error "Failed to download Go from $GO_URL"
        echo -e "${RED}[✗] Failed to download Go${NC}"
    fi
else
    log_info "Go is already installed: $(go version)"
fi

# Install Rustup and Rust if not already installed
if ! command -v rustup &> /dev/null; then
    show_progress "Installing" "Rustup and Rust"
    log_info "Installing Rustup and Rust (latest stable)"
    
    # Download and run rustup installer
    if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>>$LOG_FILE; then
        # Source the cargo environment
        if [ -f "$HOME/.cargo/env" ]; then
            source "$HOME/.cargo/env"
        fi
        
        # Update PATH for current session
        export PATH="$HOME/.cargo/bin:$PATH"
        
        # Verify installation
        if command -v rustc &> /dev/null && command -v cargo &> /dev/null; then
            show_success "Rustup and Rust"
            log_info "Rust installed successfully: $(rustc --version)"
            log_info "Cargo version: $(cargo --version)"
            
            # Update to latest stable (in case there was an update since installer)
            rustup update stable 2>>$LOG_FILE || log_warning "Failed to update Rust to latest stable"
        else
            log_error "Rust installation verification failed"
            echo -e "${RED}[✗] Failed to verify Rust installation${NC}"
        fi
    else
        log_error "Failed to install Rustup"
        echo -e "${RED}[✗] Failed to install Rustup${NC}"
    fi
else
    log_info "Rustup is already installed: $(rustup --version)"
    log_info "Current Rust version: $(rustc --version)"
    
    # Update to latest stable version
    show_progress "Updating" "Rust to latest stable"
    if rustup update stable 2>>$LOG_FILE; then
        log_info "Rust updated successfully"
        rustup default stable 2>>$LOG_FILE || log_warning "Failed to set stable as default"
    else
        log_warning "Failed to update Rust"
    fi
fi

# Install uv
if ! command -v uv > /dev/null; then
    show_progress "Installing" "uv"
    log_info "Installing uv"
    
    curl -LsSf https://astral.sh/uv/install.sh | sh 2>>$LOG_FILE
    if [ $? -ne 0 ]; then
        log_error "Failed to install uv"
        echo -e "${RED}[✗] Failed to install uv${NC}"
    else
        show_success "uv"
    fi
else
    log_info "uv is already installed"
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

# Install Oh My Zsh if using zsh shell
install_oh_my_zsh() {
    local current_shell
    current_shell="$(basename "$SHELL")"
    
    if [[ "$current_shell" != "zsh" ]]; then
        log_info "Not using ZSH shell, skipping Oh My Zsh installation"
        return 0
    fi
    
    if [[ -d "$HOME/.oh-my-zsh" ]]; then
        log_info "Oh My Zsh already installed"
        return 0
    fi
    
    show_progress "Installing" "Oh My Zsh"
    log_info "Installing Oh My Zsh"
    
    # Check internet connectivity with a simple ping
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_error "No internet connectivity for Oh My Zsh installation"
        echo -e "${RED}[✗] Failed to install Oh My Zsh - no internet${NC}"
        return 1
    fi
    
    # Download and install Oh My Zsh unattended
    if sh -c "$(curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended 2>>$LOG_FILE; then
        show_success "Oh My Zsh"
        log_info "Oh My Zsh installed successfully"
        
        # Backup the default .zshrc created by Oh My Zsh since we'll overwrite it later
        if [[ -f "$HOME/.zshrc" ]]; then
            cp "$HOME/.zshrc" "$HOME/.zshrc.omz-default.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
            log_info "Backed up Oh My Zsh default .zshrc"
        fi
    else
        log_error "Failed to install Oh My Zsh"
        echo -e "${RED}[✗] Failed to install Oh My Zsh${NC}"
        return 1
    fi
}

# Install zsh plugins if Oh My Zsh is available
install_zsh_plugins() {
    if [[ ! -d "$HOME/.oh-my-zsh" ]]; then
        log_info "Oh My Zsh not found - skipping zsh plugins"
        return 0
    fi
    
    local zsh_custom="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"
    
    show_progress "Installing" "zsh plugins"
    log_info "Installing zsh plugins"
    
    # zsh-autosuggestions
    if [[ ! -d "$zsh_custom/plugins/zsh-autosuggestions" ]]; then
        log_info "Installing zsh-autosuggestions plugin"
        if git clone --depth 1 https://github.com/zsh-users/zsh-autosuggestions "$zsh_custom/plugins/zsh-autosuggestions" 2>>$LOG_FILE; then
            log_info "zsh-autosuggestions installed successfully"
        else
            log_error "Failed to install zsh-autosuggestions"
        fi
    else
        log_info "zsh-autosuggestions plugin already installed"
    fi
    
    # zsh-syntax-highlighting  
    if [[ ! -d "$zsh_custom/plugins/zsh-syntax-highlighting" ]]; then
        log_info "Installing zsh-syntax-highlighting plugin"
        if git clone --depth 1 https://github.com/zsh-users/zsh-syntax-highlighting.git "$zsh_custom/plugins/zsh-syntax-highlighting" 2>>$LOG_FILE; then
            log_info "zsh-syntax-highlighting installed successfully"
        else
            log_error "Failed to install zsh-syntax-highlighting"
        fi
    else
        log_info "zsh-syntax-highlighting plugin already installed"
    fi
    
    if [[ -d "$zsh_custom/plugins/zsh-autosuggestions" && -d "$zsh_custom/plugins/zsh-syntax-highlighting" ]]; then
        show_success "zsh plugins"
    fi
}

# Call the installation functions
install_oh_my_zsh
install_zsh_plugins

# Install Go tools
if command -v go &> /dev/null; then
    show_progress "Installing" "Go tools"
    log_info "Installing Go-based tools"
    
    # Ensure GOPATH and GOBIN are set
    if [ -z "$GOPATH" ]; then
        export GOPATH="$HOME/go"
        mkdir -p "$GOPATH/bin"
    fi
    
    # Add Go binary paths to current session PATH
    export PATH="/usr/local/go/bin:$GOPATH/bin:$PATH"


# Set up Rust environment and install default stable toolchain
if command -v rustup &> /dev/null; then
    log_info "Setting up Rust environment"
    
    # Ensure Rust stable is default and up to date
    rustup default stable 2>>$LOG_FILE || log_warning "Failed to set Rust stable as default"
    
    # Source cargo environment for current session
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    
    # Add commonly useful Rust components
    show_progress "Installing" "Rust components"
    rustup component add clippy rustfmt 2>>$LOG_FILE || log_warning "Failed to install some Rust components"
    
    log_info "Rust environment setup complete"
else
    log_warning "Rustup not found, skipping Rust environment setup"
fi

# Make arsenal work
echo 'dev.tty.legacy_tiocsti = 1' | sudo tee /etc/sysctl.d/legacy_tiocsti.conf > /dev/null

# Update environment variables for future sessions
log_info "Setting up environment variables for future sessions"

# Create or update shell profile for Go and Rust
PROFILE_ADDITIONS=""

# Add Go to PATH if installed
if [ -d "/usr/local/go/bin" ]; then
    PROFILE_ADDITIONS+='export PATH="/usr/local/go/bin:$PATH"'$'\n'
    PROFILE_ADDITIONS+='export GOPATH="$HOME/go"'$'\n'
    PROFILE_ADDITIONS+='export PATH="$GOPATH/bin:$PATH"'$'\n'
fi

# Add Rust/Cargo to PATH if installed
if [ -d "$HOME/.cargo/bin" ]; then
    PROFILE_ADDITIONS+='export PATH="$HOME/.cargo/bin:$PATH"'$'\n'
    PROFILE_ADDITIONS+='source "$HOME/.cargo/env"'$'\n'
fi

# Add pyenv to PATH if installed
if [ -d "$HOME/.pyenv/bin" ]; then
    PROFILE_ADDITIONS+='export PATH="$HOME/.pyenv/bin:$PATH"'$'\n'
    PROFILE_ADDITIONS+='eval "$(pyenv init --path)"'$'\n'
    PROFILE_ADDITIONS+='eval "$(pyenv init -)"'$'\n'
    PROFILE_ADDITIONS+='eval "$(pyenv virtualenv-init -)"'$'\n'
fi

# Add other common paths
PROFILE_ADDITIONS+='export PATH="$HOME/.local/bin:$PATH"'$'\n'

# Determine which shell profile to update
if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ]; then
    PROFILE_FILE="$HOME/.zshrc"
    SHELL_NAME="zsh"
else
    PROFILE_FILE="$HOME/.bashrc"
    SHELL_NAME="bash"
fi

# Check if additions are already in the profile
if [ -f "$PROFILE_FILE" ] && grep -q "# Development tools PATH" "$PROFILE_FILE"; then
    log_info "Environment variables already configured in $PROFILE_FILE"
else
    log_info "Adding environment variables to $PROFILE_FILE"
    {
        echo ""
        echo "# Development tools PATH - Added by initial_setup.sh"
        echo "$PROFILE_ADDITIONS"
    } >> "$PROFILE_FILE"
    
    log_info "Environment variables added to $PROFILE_FILE"
fi

# Final summary
echo ""
echo "=========================================="
echo "         INSTALLATION COMPLETE"
echo "=========================================="
echo "✅ System packages installed"
echo "✅ Directories and permissions configured"
echo "✅ User groups updated"
if command -v go &> /dev/null; then
    echo "✅ Go installed: $(go version | cut -d' ' -f3)"
else
    echo "❌ Go installation failed"
fi
if command -v rustc &> /dev/null; then
    echo "✅ Rust installed: $(rustc --version | cut -d' ' -f2)"
else
    echo "❌ Rust installation failed"
fi
if command -v pyenv &> /dev/null; then
    echo "✅ pyenv installed"
else
    echo "❌ pyenv installation failed"
fi
if [[ -d "$HOME/.oh-my-zsh" ]]; then
    echo "✅ Oh My Zsh installed"
    if [[ -d "$HOME/.oh-my-zsh/custom/plugins/zsh-autosuggestions" && -d "$HOME/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting" ]]; then
        echo "✅ Zsh plugins installed"
    else
        echo "⚠️  Zsh plugins partially installed"
    fi
else
    echo "❌ Oh My Zsh installation failed or skipped"
fi
echo "✅ System configuration applied"
echo ""
echo "NEXT STEPS:"
echo "1. Restart your shell or run: source $PROFILE_FILE"
echo "2. Log out and back in for group changes to take effect"
echo "3. Run './configuration_files.sh' to deploy configuration files"
echo "4. Run './install-tools.sh' to install additional tools"
echo ""
echo "Log file: $LOG_FILE"
echo "=========================================="