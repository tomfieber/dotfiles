#!/bin/bash

# Unified Setup Script - Combines initial_setup.sh and configuration_files.sh
# This script handles system setup, package installation, and configuration file deployment

set -euo pipefail

# Ensure non-interactive mode for all operations
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$HOME/.local/logging"
LOG_FILE="$LOG_DIR/setup-$(date +%Y%m%d%H%M%S).log"

# Tracking arrays
FAILED_OPERATIONS=()
SUCCESSFUL_OPERATIONS=()
SKIPPED_OPERATIONS=()

# Parse command line arguments
SKIP_PACKAGES=false
SKIP_CONFIG=false
FORCE_OVERWRITE=false

for arg in "$@"; do
    case $arg in
        --skip-packages)
            SKIP_PACKAGES=true
            shift
            ;;
        --skip-config)
            SKIP_CONFIG=true
            shift
            ;;
        --force)
            FORCE_OVERWRITE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --skip-packages   Skip system package installation"
            echo "  --skip-config     Skip configuration file copying"
            echo "  --force           Overwrite existing configuration files"
            echo "  --help, -h        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Setup logging
mkdir -p "$LOG_DIR"

# Signal handling for graceful shutdown
cleanup() {
    local exit_code=$?
    echo ""
    echo "Script interrupted. Cleaning up..."
    # Kill any background processes if they exist
    jobs -p | xargs -r kill 2>/dev/null || true
    exit $exit_code
}

trap cleanup SIGINT SIGTERM

# Setup logging with better output handling
# We'll use tee for logging while still showing output to user
exec 3>&1 4>&2
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_error() {
    echo -e "${RED}[ERROR] $(date +"%Y-%m-%d %H:%M:%S") - $1${NC}" >&2
}

log_info() {
    echo "[INFO] $(date +"%Y-%m-%d %H:%M:%S") - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $(date +"%Y-%m-%d %H:%M:%S") - $1${NC}"
}

# Progress indicators
show_progress() {
    local action="$1"
    local item="$2"
    echo -e "${BLUE}[*] ${action} ${item}...${NC}"
}

show_success() {
    local item="$1"
    echo -e "${GREEN}[✓] Successfully processed ${item}${NC}"
}

show_error() {
    local item="$1"
    echo -e "${RED}[✗] Failed to process ${item}${NC}"
}

# Add a function to check if we can reach the internet
check_internet() {
    if ! curl -sSf --connect-timeout 5 --max-time 10 http://www.google.com >/dev/null 2>&1; then
        log_warning "Internet connectivity check failed. Some operations may fail."
        return 1
    fi
    return 0
}

# Utility functions
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_file_exists() {
    if [[ ! -f "$1" && ! -d "$1" ]]; then
        log_warning "File or directory not found: $1"
        return 1
    fi
    return 0
}

# Enhanced file copying with backup and validation
copy_with_backup() {
    local src="$1"
    local dest="$2"
    local description="$3"
    
    if ! check_file_exists "$src"; then
        FAILED_OPERATIONS+=("$description (source not found)")
        return 1
    fi
    
    # Create destination directory if needed
    local dest_dir
    dest_dir="$(dirname "$dest")"
    if [[ ! -d "$dest_dir" ]]; then
        mkdir -p "$dest_dir" || {
            log_error "Failed to create directory: $dest_dir"
            FAILED_OPERATIONS+=("$description (mkdir failed)")
            return 1
        }
    fi
    
    # Handle existing files
    if [[ -f "$dest" || -d "$dest" ]]; then
        if [[ "$FORCE_OVERWRITE" != true ]]; then
            log_info "$description already exists, creating backup"
            cp -r "$dest" "${dest}.backup.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
        fi
    fi
    
    # Copy the file/directory
    if timeout 30 cp -r "$src" "$dest" 2>/dev/null; then
        log_info "Successfully copied $description"
        SUCCESSFUL_OPERATIONS+=("$description")
        return 0
    else
        log_error "Failed to copy $description (operation timed out or failed)"
        FAILED_OPERATIONS+=("$description (copy failed)")
        return 1
    fi
}

# System package installation
install_system_packages() {
    if [[ "$SKIP_PACKAGES" == true ]]; then
        log_info "Skipping system package installation (--skip-packages)"
        SKIPPED_OPERATIONS+=("System packages")
        return 0
    fi
    
    local requirements_file="$SCRIPT_DIR/requirements.txt"
    
    if ! check_file_exists "$requirements_file"; then
        log_warning "requirements.txt not found, skipping package installation"
        SKIPPED_OPERATIONS+=("System packages (no requirements.txt)")
        return 0
    fi
    
    log_info "Installing system packages from requirements.txt"
    show_progress "Installing" "system packages"
    
    # Check internet connectivity first
    if ! check_internet; then
        log_error "No internet connectivity for package installation"
        FAILED_OPERATIONS+=("System packages (no internet)")
        return 1
    fi
    
    # Update package lists first with timeout
    if ! timeout 60 sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>>"$LOG_FILE"; then
        log_warning "Package list update failed or timed out"
    fi
    
    if timeout 300 xargs -a "$requirements_file" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq 2>>"$LOG_FILE"; then
        show_success "system packages"
        SUCCESSFUL_OPERATIONS+=("System packages")
    else
        show_error "system packages"
        FAILED_OPERATIONS+=("System packages")
        return 1
    fi
}

# Directory and permission setup
setup_directories() {
    log_info "Setting up directories and permissions"
    
    # Create necessary directories
    local dirs=("/opt/tools" "$HOME/.local/bin" "$HOME/.cheats")
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            if [[ "$dir" == /opt/* ]]; then
                sudo mkdir -p "$dir"
                sudo chown -R "$USER:$USER" "$dir"
            else
                mkdir -p "$dir"
            fi
            log_info "Created directory: $dir"
        fi
    done
    
    # Copy opt files if they exist
    if [[ -d "$SCRIPT_DIR/opt" ]]; then
        if copy_with_backup "$SCRIPT_DIR/opt/" "/opt/" "opt files"; then
            sudo chown -R "$USER:$USER" /opt
        fi
    fi
    
    SUCCESSFUL_OPERATIONS+=("Directory setup")
}

# User group management
setup_user_groups() {
    log_info "Setting up user groups"
    
    # Add user to docker and sudo groups if they exist
    if getent group docker >/dev/null 2>&1; then
        sudo usermod -aG docker "$USER" 2>/dev/null || log_warning "Failed to add user to docker group"
    else
        log_warning "Docker group not found"
    fi
    
    if getent group sudo >/dev/null 2>&1; then
        sudo usermod -aG sudo "$USER" 2>/dev/null || log_warning "Failed to add user to sudo group"
    else
        log_warning "Sudo group not found"
    fi
    
    SUCCESSFUL_OPERATIONS+=("User groups")
}

# Python environment setup
setup_python_env() {
    if command_exists pyenv; then
        log_info "pyenv already installed"
        SKIPPED_OPERATIONS+=("pyenv (already installed)")
        return 0
    fi
    
    show_progress "Installing" "pyenv"
    log_info "Installing pyenv"
    
    # Check internet connectivity
    if ! check_internet; then
        log_error "No internet connectivity for pyenv installation"
        FAILED_OPERATIONS+=("pyenv (no internet)")
        return 1
    fi
    
    if curl -sSfL --connect-timeout 10 --max-time 60 https://pyenv.run | PYENV_INSTALLER_BATCH=1 bash 2>>"$LOG_FILE"; then
        # Update PATH and initialize pyenv
        export PATH="$HOME/.pyenv/bin:$PATH"
        if [[ -f "$HOME/.pyenv/bin/pyenv" ]]; then
            eval "$($HOME/.pyenv/bin/pyenv init --path)"
            eval "$($HOME/.pyenv/bin/pyenv init -)"
            eval "$($HOME/.pyenv/bin/pyenv virtualenv-init -)"
        fi
        show_success "pyenv"
        SUCCESSFUL_OPERATIONS+=("pyenv")
    else
        show_error "pyenv"
        FAILED_OPERATIONS+=("pyenv")
        return 1
    fi
}

# Go installation
setup_go() {
    if command_exists go; then
        local current_version
        current_version="$(go version | awk '{print $3}' | sed 's/go//')"
        log_info "Go already installed (version $current_version)"
        SKIPPED_OPERATIONS+=("Go (already installed - $current_version)")
        return 0
    fi
    
    show_progress "Installing" "Go (latest version)"
    log_info "Installing Go"
    
    # Check internet connectivity
    if ! check_internet; then
        log_error "No internet connectivity for Go installation"
        FAILED_OPERATIONS+=("Go (no internet)")
        return 1
    fi
    
    # Detect architecture
    local arch
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv6l) arch="armv6l" ;;
        armv7l) arch="armv7l" ;;
        i386) arch="386" ;;
        *) 
            log_error "Unsupported architecture: $(uname -m)"
            FAILED_OPERATIONS+=("Go (unsupported architecture)")
            return 1
            ;;
    esac
    
    # Detect OS
    local os
    case "$(uname -s)" in
        Linux) os="linux" ;;
        Darwin) os="darwin" ;;
        *) 
            log_error "Unsupported OS: $(uname -s)"
            FAILED_OPERATIONS+=("Go (unsupported OS)")
            return 1
            ;;
    esac
    
    # Get latest Go version
    local latest_version
    if ! latest_version="$(curl -sSfL --connect-timeout 10 --max-time 30 'https://go.dev/VERSION?m=text' 2>>"$LOG_FILE")"; then
        log_error "Failed to fetch latest Go version"
        FAILED_OPERATIONS+=("Go (version fetch failed)")
        return 1
    fi
    
    local download_url="https://go.dev/dl/${latest_version}.${os}-${arch}.tar.gz"
    local temp_dir="/tmp/go-install"
    
    # Create temporary directory
    mkdir -p "$temp_dir"
    
    # Download Go
    log_info "Downloading Go $latest_version for $os-$arch"
    if ! curl -sSfL --connect-timeout 10 --max-time 300 "$download_url" -o "$temp_dir/go.tar.gz" 2>>"$LOG_FILE"; then
        log_error "Failed to download Go"
        FAILED_OPERATIONS+=("Go (download failed)")
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Remove existing Go installation
    if [[ -d "/usr/local/go" ]]; then
        log_info "Removing existing Go installation"
        sudo rm -rf /usr/local/go
    fi
    
    # Extract and install Go
    log_info "Installing Go to /usr/local/go"
    if sudo tar -C /usr/local -xzf "$temp_dir/go.tar.gz" 2>>"$LOG_FILE"; then
        # Update shell profile
        local shell_profile=""
        case "$(basename "$SHELL")" in
            "zsh") shell_profile="$HOME/.zshrc" ;;
            "bash") shell_profile="$HOME/.bashrc" ;;
            *) shell_profile="$HOME/.profile" ;;
        esac
        
        # Add Go to PATH in shell profile
        if [[ -f "$shell_profile" ]] && ! grep -q "/usr/local/go/bin" "$shell_profile"; then
            echo "" >> "$shell_profile"
            echo "# Go installation" >> "$shell_profile"
            echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$shell_profile"
            echo 'export GOPATH="$HOME/go"' >> "$shell_profile"
            echo 'export PATH="$GOPATH/bin:$PATH"' >> "$shell_profile"
            log_info "Added Go to PATH in $shell_profile"
        fi
        
        # Update PATH for current session
        export PATH="/usr/local/go/bin:$PATH"
        export GOPATH="$HOME/go"
        export PATH="$GOPATH/bin:$PATH"
        
        # Create GOPATH directory
        mkdir -p "$GOPATH/bin"
        
        show_success "Go ($latest_version)"
        SUCCESSFUL_OPERATIONS+=("Go ($latest_version)")
    else
        show_error "Go"
        FAILED_OPERATIONS+=("Go (extraction failed)")
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
}

# Rust/Rustup installation and setup
setup_rust() {
    if command_exists rustc && command_exists cargo; then
        local current_version
        current_version="$(rustc --version | awk '{print $2}')"
        log_info "Rust already installed (version $current_version)"
        SKIPPED_OPERATIONS+=("Rust (already installed - $current_version)")
        return 0
    fi
    
    show_progress "Installing" "Rust (latest stable)"
    log_info "Installing Rust via rustup"
    
    # Check internet connectivity
    if ! check_internet; then
        log_error "No internet connectivity for Rust installation"
        FAILED_OPERATIONS+=("Rust (no internet)")
        return 1
    fi
    
    # Download and run rustup installer
    if curl --proto '=https' --tlsv1.2 -sSf --connect-timeout 10 --max-time 300 https://sh.rustup.rs | RUSTUP_INIT_SKIP_PATH_CHECK=yes sh -s -- -y --default-toolchain stable --no-modify-path 2>>"$LOG_FILE"; then
        # Source cargo environment
        if [[ -f "$HOME/.cargo/env" ]]; then
            source "$HOME/.cargo/env"
        fi
        
        # Update shell profile
        local shell_profile=""
        case "$(basename "$SHELL")" in
            "zsh") shell_profile="$HOME/.zshrc" ;;
            "bash") shell_profile="$HOME/.bashrc" ;;
            *) shell_profile="$HOME/.profile" ;;
        esac
        
        # Add Rust to PATH in shell profile
        if [[ -f "$shell_profile" ]] && ! grep -q "\.cargo/env" "$shell_profile"; then
            echo "" >> "$shell_profile"
            echo "# Rust installation" >> "$shell_profile"
            echo 'source "$HOME/.cargo/env"' >> "$shell_profile"
            log_info "Added Rust to PATH in $shell_profile"
        fi
        
        # Update PATH for current session
        export PATH="$HOME/.cargo/bin:$PATH"
        
        # Install additional components
        log_info "Installing Rust components"
        if command_exists rustup; then
            rustup component add clippy rustfmt 2>>"$LOG_FILE" || log_warning "Failed to install some Rust components"
            
            # Update to latest stable
            rustup update stable 2>>"$LOG_FILE" || log_warning "Failed to update Rust"
        fi
        
        local rust_version
        if command_exists rustc; then
            rust_version="$(rustc --version | awk '{print $2}')"
            show_success "Rust ($rust_version)"
            SUCCESSFUL_OPERATIONS+=("Rust ($rust_version)")
        else
            show_success "Rust"
            SUCCESSFUL_OPERATIONS+=("Rust")
        fi
    else
        show_error "Rust"
        FAILED_OPERATIONS+=("Rust")
        return 1
    fi
}

# Go tools installation
setup_go_tools() {
    if ! command_exists go; then
        log_warning "Go not found, skipping Go tools installation"
        SKIPPED_OPERATIONS+=("Go tools (Go not installed)")
        return 0
    fi
    
    log_info "Installing Go tools"
    
    # Install asdf
    if ! command_exists asdf; then
        go install github.com/asdf-vm/asdf/cmd/asdf@latest 2>>"$LOG_FILE" && \
        SUCCESSFUL_OPERATIONS+=("asdf") || FAILED_OPERATIONS+=("asdf")
    else
        SKIPPED_OPERATIONS+=("asdf (already installed)")
    fi
    
    # Install pdtm
    if ! command_exists pdtm; then
        if go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest 2>>"$LOG_FILE"; then
            "$HOME/go/bin/pdtm" -ia 2>>"$LOG_FILE" || log_warning "pdtm initialization failed"
            SUCCESSFUL_OPERATIONS+=("pdtm")
        else
            FAILED_OPERATIONS+=("pdtm")
        fi
    else
        SKIPPED_OPERATIONS+=("pdtm (already installed)")
    fi
}

# Node.js and npm setup
setup_nodejs() {
    log_info "Setting up Node.js environment"
    
    # Install nodejs via asdf if available
    if command_exists asdf; then
        # Add nodejs plugin (ignore errors if already exists)
        asdf plugin add nodejs 2>/dev/null || true
        
        # Set environment for non-interactive installation
        export NODEJS_CHECK_SIGNATURES=no
        
        if asdf install nodejs latest 2>>"$LOG_FILE"; then
            asdf global nodejs latest 2>>"$LOG_FILE"
            SUCCESSFUL_OPERATIONS+=("Node.js via asdf")
        else
            FAILED_OPERATIONS+=("Node.js via asdf")
            return 1
        fi
    else
        log_warning "asdf not available, skipping Node.js installation"
        SKIPPED_OPERATIONS+=("Node.js (asdf not available)")
        return 0
    fi
    
    # Install npm packages
    if command_exists npm; then
        log_info "Installing npm packages globally"
        if sudo npm install -g pp-finder --silent 2>>"$LOG_FILE"; then
            SUCCESSFUL_OPERATIONS+=("npm packages")
        else
            FAILED_OPERATIONS+=("npm packages")
        fi
    else
        SKIPPED_OPERATIONS+=("npm packages (npm not available)")
    fi
}

# Configuration files deployment
deploy_configuration() {
    if [[ "$SKIP_CONFIG" == true ]]; then
        log_info "Skipping configuration file deployment (--skip-config)"
        SKIPPED_OPERATIONS+=("Configuration files")
        return 0
    fi
    
    log_info "Deploying configuration files"
    
    # Copy cheats directory
    copy_with_backup "$SCRIPT_DIR/cheats" "$HOME/.cheats" "cheats directory"
    
    # Detect shell and copy appropriate configuration
    local current_shell
    current_shell="$(basename "$SHELL")"
    
    case "$current_shell" in
        "zsh")
            log_info "Detected ZSH shell, deploying ZSH configuration"
            copy_with_backup "$SCRIPT_DIR/zshrc" "$HOME/.zshrc" "zshrc"
            copy_with_backup "$SCRIPT_DIR/zsh_shortcuts" "$HOME/.zsh_shortcuts" "zsh_shortcuts"
            copy_with_backup "$SCRIPT_DIR/zsh_aliases" "$HOME/.zsh_aliases" "zsh_aliases"
            
            # Oh My Zsh theme (create directory if needed)
            local theme_dir="$HOME/.oh-my-zsh/themes"
            if [[ -d "$HOME/.oh-my-zsh" ]]; then
                mkdir -p "$theme_dir"
                copy_with_backup "$SCRIPT_DIR/th0m12.zsh-theme" "$theme_dir/th0m12.zsh-theme" "ZSH theme"
            else
                log_warning "Oh My Zsh not found, this shouldn't happen if setup ran correctly"
                SKIPPED_OPERATIONS+=("ZSH theme (Oh My Zsh not found)")
            fi
            ;;
        "bash")
            log_info "Detected Bash shell, deploying Bash configuration"
            copy_with_backup "$SCRIPT_DIR/zsh_shortcuts" "$HOME/.bash_shortcuts" "bash_shortcuts"
            copy_with_backup "$SCRIPT_DIR/zsh_aliases" "$HOME/.bash_aliases" "bash_aliases"
            copy_with_backup "$SCRIPT_DIR/bashrc" "$HOME/.bashrc" "bashrc"
            ;;
        *)
            log_warning "Unknown shell: $current_shell, using Bash configuration"
            copy_with_backup "$SCRIPT_DIR/zsh_shortcuts" "$HOME/.bash_shortcuts" "bash_shortcuts"
            copy_with_backup "$SCRIPT_DIR/zsh_aliases" "$HOME/.bash_aliases" "bash_aliases"
            ;;
    esac
    
    # Copy tmux configuration
    copy_with_backup "$SCRIPT_DIR/tmux" "$HOME/.tmux.conf" "tmux configuration"
}

# System configuration
setup_system_config() {
    log_info "Applying system configuration"
    
    # Arsenal compatibility (legacy tiocsti)
    local sysctl_config="/etc/sysctl.d/legacy_tiocsti.conf"
    if [[ ! -f "$sysctl_config" ]]; then
        if echo 'dev.tty.legacy_tiocsti = 1' | sudo DEBIAN_FRONTEND=noninteractive tee "$sysctl_config" >/dev/null 2>>"$LOG_FILE"; then
            log_info "Applied legacy_tiocsti configuration for arsenal compatibility"
            SUCCESSFUL_OPERATIONS+=("System configuration")
        else
            log_error "Failed to apply system configuration"
            FAILED_OPERATIONS+=("System configuration")
        fi
    else
        log_info "System configuration already applied"
        SKIPPED_OPERATIONS+=("System configuration (already applied)")
    fi
}

# Update PATH for current session
update_path() {
    log_info "Updating PATH for current session"
    
    local new_paths=(
        "$HOME/.local/bin"
        "$HOME/go/bin"
        "$HOME/.pdtm/go/bin"
        "$HOME/.asdf/bin"
        "$HOME/.pyenv/bin"
        "$HOME/.cargo/bin"
    )
    
    for path in "${new_paths[@]}"; do
        if [[ -d "$path" && ":$PATH:" != *":$path:"* ]]; then
            export PATH="$path:$PATH"
            log_info "Added $path to PATH"
        fi
    done
    
    SUCCESSFUL_OPERATIONS+=("PATH update")
}

# Oh My Zsh installation
setup_oh_my_zsh() {
    # Only install if using zsh shell
    local current_shell
    current_shell="$(basename "$SHELL")"
    
    if [[ "$current_shell" != "zsh" ]]; then
        log_info "Not using ZSH shell, skipping Oh My Zsh installation"
        SKIPPED_OPERATIONS+=("Oh My Zsh (not using ZSH)")
        return 0
    fi
    
    # Check if Oh My Zsh is already installed
    if [[ -d "$HOME/.oh-my-zsh" ]]; then
        log_info "Oh My Zsh already installed"
        SKIPPED_OPERATIONS+=("Oh My Zsh (already installed)")
        return 0
    fi
    
    show_progress "Installing" "Oh My Zsh"
    log_info "Installing Oh My Zsh"
    
    # Check internet connectivity
    if ! check_internet; then
        log_error "No internet connectivity for Oh My Zsh installation"
        FAILED_OPERATIONS+=("Oh My Zsh (no internet)")
        return 1
    fi
    
    # Download and install Oh My Zsh
    # Use unattended installation to avoid interactive prompts
    if sh -c "$(curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended 2>>"$LOG_FILE"; then
        show_success "Oh My Zsh"
        SUCCESSFUL_OPERATIONS+=("Oh My Zsh")
        
        # Backup the default .zshrc created by Oh My Zsh since we'll overwrite it
        if [[ -f "$HOME/.zshrc" ]]; then
            cp "$HOME/.zshrc" "$HOME/.zshrc.omz-default.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
            log_info "Backed up Oh My Zsh default .zshrc"
        fi
    else
        show_error "Oh My Zsh"
        FAILED_OPERATIONS+=("Oh My Zsh")
        return 1
    fi
}

# Main execution
main() {
    echo "=========================================="
    echo "    Starting Unified Setup Process"
    echo "=========================================="
    echo "Log file: $LOG_FILE"
    echo "Press Ctrl+C to cancel at any time"
    echo ""
    
    # Ensure completely non-interactive environment
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1
    export UCF_FORCE_CONFFNEW=1
    export PYENV_INSTALLER_BATCH=1
    export RUSTUP_INIT_SKIP_PATH_CHECK=yes
    
    log_info "Starting unified setup process"
    log_info "Script directory: $SCRIPT_DIR"
    log_info "Configuration: packages=$([ "$SKIP_PACKAGES" = true ] && echo "skip" || echo "install"), config=$([ "$SKIP_CONFIG" = true ] && echo "skip" || echo "deploy"), force=$FORCE_OVERWRITE"
    
    # Execute setup phases
    install_system_packages
    setup_directories
    setup_user_groups
    setup_python_env
    setup_go
    setup_rust
    setup_go_tools
    setup_nodejs
    setup_oh_my_zsh
    deploy_configuration
    setup_system_config
    update_path
    
    # Print summary
    print_summary
}

# Summary function
print_summary() {
    echo ""
    echo "=========================================="
    echo "           SETUP SUMMARY"
    echo "=========================================="
    
    echo "Configuration:"
    echo "  System packages: $([ "$SKIP_PACKAGES" = true ] && echo "❌ Skipped" || echo "✅ Processed")"
    echo "  Configuration files: $([ "$SKIP_CONFIG" = true ] && echo "❌ Skipped" || echo "✅ Processed")"
    echo "  Force overwrite: $([ "$FORCE_OVERWRITE" = true ] && echo "✅ Enabled" || echo "❌ Disabled")"
    echo ""
    
    if [[ ${#SUCCESSFUL_OPERATIONS[@]} -gt 0 ]]; then
        echo -e "${GREEN}Successfully completed (${#SUCCESSFUL_OPERATIONS[@]}):${NC}"
        printf '%s\n' "${SUCCESSFUL_OPERATIONS[@]}" | sort
        echo ""
    fi
    
    if [[ ${#SKIPPED_OPERATIONS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Skipped (${#SKIPPED_OPERATIONS[@]}):${NC}"
        printf '%s\n' "${SKIPPED_OPERATIONS[@]}" | sort
        echo ""
    fi
    
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        echo -e "${RED}Failed operations (${#FAILED_OPERATIONS[@]}):${NC}"
        printf '%s\n' "${FAILED_OPERATIONS[@]}" | sort
        echo ""
        echo -e "${RED}Check the log file for details: $LOG_FILE${NC}"
        
        # Provide recovery suggestions
        echo ""
        echo "Recovery suggestions:"
        echo "  • Re-run with --force to overwrite existing files"
        echo "  • Check file permissions and disk space"
        echo "  • Ensure all dependencies are installed"
    else
        echo -e "${GREEN}All operations completed successfully!${NC}"
    fi
    
    echo ""
    echo "Next steps:"
    echo "  • Restart your shell or run: source ~/.$(basename "$SHELL")rc"
    echo "  • Log out and back in for group changes to take effect"
    echo "  • Run the install-tools.sh script to install additional tools"
    echo ""
    echo "=========================================="
    echo "Full log available at: $LOG_FILE"
}

# Execute main function
main "$@"
