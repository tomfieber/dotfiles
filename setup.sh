#!/bin/bash

# Unified Setup Script - Combines initial_setup.sh and configuration_files.sh
# This script handles system setup, package installation, and configuration file deployment

set -euo pipefail

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
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' EXIT
exec 1>>"$LOG_FILE" 2>&1

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_error() {
    echo "[ERROR] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&2
}

log_info() {
    echo "[INFO] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&3
}

log_warning() {
    echo "[WARNING] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&3
}

# Progress indicators
show_progress() {
    local action="$1"
    local item="$2"
    echo -ne "${BLUE}[*] ${action} ${item}...${NC}\r"
}

show_success() {
    local item="$1"
    echo -e "${GREEN}[✓] Successfully processed ${item}${NC}"
}

show_error() {
    local item="$1"
    echo -e "${RED}[✗] Failed to process ${item}${NC}"
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
    if cp -r "$src" "$dest" 2>/dev/null; then
        log_info "Successfully copied $description"
        SUCCESSFUL_OPERATIONS+=("$description")
        return 0
    else
        log_error "Failed to copy $description"
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
    
    if xargs -a "$requirements_file" sudo apt-get install -y 2>>"$LOG_FILE"; then
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
        if copy_with_backup "$SCRIPT_DIR/opt/"* "/opt/" "opt files"; then
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
    
    if curl -sSfL https://pyenv.run | bash 2>>"$LOG_FILE"; then
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
        if sudo npm install -g pp-finder 2>>"$LOG_FILE"; then
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
                log_warning "Oh My Zsh not found, skipping theme installation"
                SKIPPED_OPERATIONS+=("ZSH theme (Oh My Zsh not installed)")
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
        if echo 'dev.tty.legacy_tiocsti = 1' | sudo tee "$sysctl_config" >/dev/null 2>>"$LOG_FILE"; then
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
    )
    
    for path in "${new_paths[@]}"; do
        if [[ -d "$path" && ":$PATH:" != *":$path:"* ]]; then
            export PATH="$path:$PATH"
            log_info "Added $path to PATH"
        fi
    done
    
    SUCCESSFUL_OPERATIONS+=("PATH update")
}

# Main execution
main() {
    log_info "Starting unified setup process"
    log_info "Script directory: $SCRIPT_DIR"
    log_info "Configuration: packages=$([ "$SKIP_PACKAGES" = true ] && echo "skip" || echo "install"), config=$([ "$SKIP_CONFIG" = true ] && echo "skip" || echo "deploy"), force=$FORCE_OVERWRITE"
    
    # Execute setup phases
    install_system_packages
    setup_directories
    setup_user_groups
    setup_python_env
    setup_go_tools
    setup_nodejs
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
