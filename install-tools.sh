#!/bin/bash

# Exit on any error, undefined variables, and pipe failures
set -euo pipefail

# Parse command line arguments
INSTALL_GITHUB_TOOLS=false

for arg in "$@"; do
    case $arg in
        --github-tools)
            INSTALL_GITHUB_TOOLS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --github-tools    Install GitHub-based tools (git clones to /opt/tools)"
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

# Setup error logging
if [ ! -d "$HOME/.local/logging" ]; then
    mkdir -p "$HOME/.local/logging"
fi
LOG_FILE="$HOME/.local/logging/install-tools-$(date +%Y%m%d%H%M%S).log"
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' EXIT
exec 1>>"$LOG_FILE" 2>&1

# Global variables for tracking
FAILED_INSTALLS=()
SKIPPED_INSTALLS=()
SUCCESSFUL_INSTALLS=()

# Function for logging
log_error() {
    echo "[ERROR] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&2
}

log_info() {
    echo "[INFO] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&3
}

log_warning() {
    echo "[WARNING] $(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE" >&3
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a package is already installed
is_installed() {
    local package="$1"
    local check_type="$2"
    
    case "$check_type" in
        "go")
            [ -f "$HOME/go/bin/$(basename "$package")" ] || command_exists "$(basename "$package")"
            ;;
        "pipx")
            pipx list | grep -q "$(basename "$package" .git)" 2>/dev/null
            ;;
        "cargo")
            cargo install --list | grep -q "$(echo "$package" | cut -d' ' -f1)" 2>/dev/null
            ;;
        "gem")
            gem list | grep -q "^$package " 2>/dev/null
            ;;
        "git")
            [ -d "$2" ]
            ;;
        "snap")
            snap list | grep -q "^$package " 2>/dev/null
            ;;
        *)
            command_exists "$package"
            ;;
    esac
}

# Function to validate prerequisites
check_prerequisites() {
    local missing_deps=()
    
    # Check for essential tools
    if ! command_exists git; then missing_deps+=("git"); fi
    if ! command_exists curl; then missing_deps+=("curl"); fi
    if ! command_exists wget; then missing_deps+=("wget"); fi
    
    # Check for language-specific package managers
    if ! command_exists go; then log_warning "Go not found - Go tools will be skipped"; fi
    if ! command_exists cargo; then log_warning "Rust/Cargo not found - Rust tools will be skipped"; fi
    if ! command_exists pipx; then log_warning "pipx not found - Python tools will be skipped"; fi
    if ! command_exists gem; then log_warning "Ruby/gem not found - Ruby tools will be skipped"; fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing essential dependencies: ${missing_deps[*]}"
        echo "Please install missing dependencies first:"
        printf '%s\n' "${missing_deps[@]}"
        exit 1
    fi
}

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Error handling function
handle_error() {
    log_error "An error occurred on line $1. Script will continue with next installation."
    return 0  # Don't exit, just continue
}

# Set trap for error handling - but don't exit on error
trap 'handle_error $LINENO' ERR
set +e  # Disable exit on error for individual commands

# Determine system architecture and OS
SYSARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
log_info "Detected system: $OS $SYSARCH"

# Architecture mapping for downloads
case "$SYSARCH" in
    "x86_64"|"amd64") ARCH="amd64" ;;
    "aarch64"|"arm64") ARCH="arm64" ;;
    "armv7l") ARCH="arm" ;;
    *) 
        log_warning "Unknown architecture: $SYSARCH. Using amd64 as fallback."
        ARCH="amd64"
        ;;
esac

# Check prerequisites before starting
check_prerequisites

# Create necessary directories with better error handling
create_directories() {
    local dirs=("/opt/tools/powershell")
    
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            if sudo mkdir -p "$dir" && sudo chmod 755 "$dir"; then
                log_info "Created directory: $dir"
            else
                log_error "Failed to create directory: $dir"
                return 1
            fi
        else
            log_info "Directory already exists: $dir"
        fi
    done
}

create_directories

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

# Install from snap with error handling and progress indicator
install_snap() {
    local package="$1"
    local options="${2:-}"
    
    if ! command_exists snap; then
        log_warning "snap not available - skipping $package"
        SKIPPED_INSTALLS+=("$package (snap not available)")
        return 1
    fi
    
    if is_installed "$package" "snap"; then
        log_info "$package already installed via snap"
        SKIPPED_INSTALLS+=("$package (already installed)")
        return 0
    fi
    
    show_progress "Installing" "$package via snap"
    log_info "Installing $package via snap"
    
    if sudo snap install "$package" $options 2>>"$LOG_FILE"; then
        show_success "$package"
        SUCCESSFUL_INSTALLS+=("$package")
        return 0
    else
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        FAILED_INSTALLS+=("$package")
        return 1
    fi
}

install_go() {
    local package="$1"
    local binary_name=$(basename "$package" | cut -d'@' -f1)
    
    if ! command_exists go; then
        log_warning "Go not available - skipping $package"
        SKIPPED_INSTALLS+=("$package (go not available)")
        return 1
    fi
    
    if is_installed "$binary_name" "go"; then
        log_info "$package already installed"
        SKIPPED_INSTALLS+=("$package (already installed)")
        return 0
    fi
    
    show_progress "Installing" "$package via go"
    log_info "Installing $package via go install"
    
    if go install "$package" 2>>"$LOG_FILE"; then
        show_success "$package"
        SUCCESSFUL_INSTALLS+=("$package")
        return 0
    else
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        FAILED_INSTALLS+=("$package")
        return 1
    fi
}

install_pipx() {
    local package="$1"
    local package_name=$(basename "$package" .git)
    
    if ! command_exists pipx; then
        log_warning "pipx not available - skipping $package"
        SKIPPED_INSTALLS+=("$package (pipx not available)")
        return 1
    fi
    
    if is_installed "$package_name" "pipx"; then
        log_info "$package already installed via pipx"
        SKIPPED_INSTALLS+=("$package (already installed)")
        return 0
    fi
    
    show_progress "Installing" "$package via pipx"
    log_info "Installing $package via pipx"
    
    if pipx install "$package" 2>>"$LOG_FILE"; then
        show_success "$package"
        SUCCESSFUL_INSTALLS+=("$package")
        return 0
    else
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        FAILED_INSTALLS+=("$package")
        return 1
    fi
}

install_rust() {
    local package="$1"
    
    if ! command_exists cargo; then
        log_warning "Cargo not available - skipping $package"
        SKIPPED_INSTALLS+=("$package (cargo not available)")
        return 1
    fi
    
    if is_installed "$package" "cargo"; then
        log_info "$package already installed via cargo"
        SKIPPED_INSTALLS+=("$package (already installed)")
        return 0
    fi
    
    show_progress "Installing" "$package via cargo"
    log_info "Installing $package via cargo install"
    
    if cargo install "$package" 2>>"$LOG_FILE"; then
        show_success "$package"
        SUCCESSFUL_INSTALLS+=("$package")
        return 0
    else
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        FAILED_INSTALLS+=("$package")
        return 1
    fi
}

install_gem() {
    local package="$1"
    
    if ! command_exists gem; then
        log_warning "gem not available - skipping $package"
        SKIPPED_INSTALLS+=("$package (gem not available)")
        return 1
    fi
    
    if is_installed "$package" "gem"; then
        log_info "$package already installed via gem"
        SKIPPED_INSTALLS+=("$package (already installed)")
        return 0
    fi
    
    show_progress "Installing" "$package via gem"
    log_info "Installing $package via gem"
    
    if sudo gem install "$package" 2>>"$LOG_FILE"; then
        show_success "$package"
        SUCCESSFUL_INSTALLS+=("$package")
        return 0
    else
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        FAILED_INSTALLS+=("$package")
        return 1
    fi
}

# Git clone with progress indicator and skip if exists
git_clone_tool() {
    local repo="$1"
    local destination="$2"
    local name=$(basename "$destination")
    
    if [ -d "$destination" ]; then
        log_info "$name already exists at $destination"
        SKIPPED_INSTALLS+=("$name (already exists)")
        return 0
    fi
    
    show_progress "Cloning" "$name"
    log_info "Cloning $repo to $destination"
    
    if git clone --depth 1 "$repo" "$destination" 2>>"$LOG_FILE"; then
        show_success "$name"
        SUCCESSFUL_INSTALLS+=("$name")
        return 0
    else
        log_error "Failed to clone $name repository"
        echo -e "${RED}[✗] Failed to clone $name repository${NC}"
        FAILED_INSTALLS+=("$name")
        return 1
    fi
}

# Initialize tools if available
if command_exists rustup; then
    if ! rustup default stable 2>>"$LOG_FILE"; then
        log_error "Failed to set rustup default to stable"
        echo -e "${RED}Failed to set rustup default to stable${NC}"
    fi
else
    log_warning "rustup not found - skipping Rust setup"
fi

if command_exists msfdb; then
    if ! msfdb init 2>>"$LOG_FILE"; then
        log_error "Failed to initialize msfdb"
        echo -e "${RED}Failed to initialize msfdb${NC}"
    fi
else
    log_warning "msfdb not found - skipping Metasploit database initialization"
fi

# Install BloodHound Community Edition with architecture detection
install_bloodhound() {
    log_info "Installing BloodHound Community Edition"
    
    local bloodhound_url="https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-${OS}-${ARCH}.tar.gz"
    local temp_dir=$(mktemp -d)
    
    cd "$temp_dir" || { log_error "Failed to create temp directory"; return 1; }
    
    if wget "$bloodhound_url" 2>>"$LOG_FILE"; then
        if tar -xzf "bloodhound-cli-${OS}-${ARCH}.tar.gz" 2>>"$LOG_FILE"; then
            if ./bloodhound-cli install 2>>"$LOG_FILE"; then
                log_info "BloodHound CE installed successfully"
                SUCCESSFUL_INSTALLS+=("BloodHound CE")
            else
                log_error "Failed to install BloodHound CE"
                FAILED_INSTALLS+=("BloodHound CE")
            fi
        else
            log_error "Failed to extract BloodHound CE"
            FAILED_INSTALLS+=("BloodHound CE")
        fi
    else
        log_error "Failed to download BloodHound CE"
        FAILED_INSTALLS+=("BloodHound CE")
    fi
    
    cd - >/dev/null
    rm -rf "$temp_dir"
}

install_bloodhound

# Improve massdns installation function
install_massdns() {
    if [ -d "/opt/tools/massdns" ]; then
        log_info "massdns already exists"
        SKIPPED_INSTALLS+=("massdns (already exists)")
        return 0
    fi
    
    if git_clone_tool https://github.com/blechschmidt/massdns.git /opt/tools/massdns; then
        cd /opt/tools/massdns/ || return 1
        if make 2>>"$LOG_FILE"; then
            if [ ! -f /usr/local/bin/massdns ]; then
                sudo ln -sf /opt/tools/massdns/bin/massdns /usr/local/bin/massdns
                log_info "massdns symlink created"
            fi
            SUCCESSFUL_INSTALLS+=("massdns (compiled)")
        else
            log_error "Failed to compile massdns"
            FAILED_INSTALLS+=("massdns (compilation failed)")
        fi
        cd - >/dev/null
    fi
}

# Install Rust tools
if command_exists cargo; then
    log_info "Installing Rust tools"
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    
    install_rust feroxbuster 
    install_rust rustscan    
else
    log_warning "Cargo not available - skipping Rust tools"
fi    

# Install evil-winrm
install_gem evil-winrm 

# Install XSpear
install_gem XSpear

# Install GitHub-based tools only if --github-tools flag is provided
if [ "$INSTALL_GITHUB_TOOLS" = true ]; then
    log_info "Installing GitHub-based tools (--github-tools flag detected)"
    log_info "Cloning various tools into /opt/tools"
    
    # git_clone_tool https://github.com/openwall/john.git /opt/tools/john
    # cd /opt/tools/john/src
    # ./configure && make -j$(nproc)
    # sudo make install
    
    git_clone_tool https://github.com/dolevf/graphql-cop.git /opt/tools/graphql-cop
    git_clone_tool https://github.com/dirkjanm/krbrelayx.git /opt/tools/krbrelayx
    git_clone_tool https://github.com/micahvandeusen/gMSADumper.git /opt/tools/gMSADumper
    git_clone_tool https://github.com/zyn3rgy/LdapRelayScan.git /opt/tools/ldaprelayscan
    git_clone_tool https://github.com/bats3c/darkarmour.git /opt/tools/DarkAmour 
    git_clone_tool https://github.com/m0rtem/CloudFail.git /opt/tools/CloudFail
    git_clone_tool https://github.com/Ridter/noPac.git /opt/tools/noPac
    git_clone_tool https://github.com/evilmog/ntlmv1-multi.git /opt/tools/ntlmv1-multi
    git_clone_tool https://github.com/Greenwolf/ntlm_theft.git /opt/tools/ntlm_theft
    git_clone_tool https://github.com/shmilylty/OneForAll.git /opt/tools/OneForAll
    git_clone_tool https://github.com/AlmondOffSec/PassTheCert.git /opt/tools/PassTheCert
    git_clone_tool https://github.com/topotam/PetitPotam.git /opt/tools/PetitPotam
    git_clone_tool https://github.com/dirkjanm/PKINITtools.git /opt/tools/PKINITtools
    git_clone_tool https://github.com/Wh1t3Fox/polenum.git /opt/tools/polenum
    git_clone_tool https://github.com/Hackndo/pyGPOAbuse.git /opt/tools/pyGPOAbuse
    git_clone_tool https://github.com/p0dalirius/pyLAPS.git /opt/tools/pyLAPS
    git_clone_tool https://github.com/GoSecure/pywsus.git /opt/tools/pywsus
    git_clone_tool https://github.com/lanmaster53/recon-ng.git /opt/tools/recon-ng
    git_clone_tool https://github.com/s0md3v/ReconDog.git /opt/tools/ReconDog
    git_clone_tool https://github.com/lgandx/Responder.git /opt/tools/Responder
    git_clone_tool https://github.com/xpn/sccmwtf.git /opt/tools/sccmwtf
    git_clone_tool https://github.com/synacktiv/SCCMSecrets.git /opt/tools/SCCMSecrets
    git_clone_tool https://github.com/pentestmonkey/smtp-user-enum.git /opt/tools/smtp-user-enum
    git_clone_tool https://github.com/defparam/smuggler.git /opt/tools/smuggler
    git_clone_tool https://github.com/smicallef/spiderfoot.git /opt/tools/spiderfoot
    git_clone_tool https://github.com/swisskyrepo/SSRFmap.git /opt/tools/SSRFmap
    git_clone_tool https://github.com/testssl/testssl.sh.git /opt/tools/testssl.sh
    git_clone_tool https://github.com/frohoff/ysoserial.git /opt/tools/ysoserial
    git_clone_tool https://github.com/SecuraBV/CVE-2020-1472.git /opt/tools/CVE-2020-1472-ZeroLogon
    git_clone_tool https://github.com/s0md3v/Photon.git /opt/tools/Photon
    git_clone_tool https://github.com/synacktiv/php_filter_chain_generator.git /opt/tools/php_filter_chain_generator
    install_massdns
    git_clone_tool https://github.com/tomfieber/hunter.git /opt/tools/hunter
else
    log_info "Skipping GitHub-based tools (use --github-tools flag to install them)"
    SKIPPED_INSTALLS+=("GitHub tools (--github-tools not specified)")
fi

# Install Go tools
if command_exists go; then
    log_info "Installing Go tools"
    
    install_go github.com/owasp-amass/amass/v4/...@master
    install_go github.com/ffuf/ffuf/v2@latest
    install_go github.com/ropnop/kerbrute@latest
    install_go github.com/sensepost/gowitness@latest
    install_go github.com/RedTeamPentesting/pretender@latest
    install_go github.com/EgeBalci/amber@latest
    install_go github.com/tomnomnom/anew@latest
    install_go github.com/asdf-vm/asdf/cmd/asdf@latest
    install_go github.com/tomnomnom/assetfinder@latest
    install_go github.com/lobuhi/byp4xx@latest
    install_go github.com/lc/gau/v2/cmd/gau@latest
    install_go github.com/hakluke/hakrawler@latest
    install_go github.com/hakluke/hakrevdns@latest
    install_go github.com/ipinfo/cli/ipinfo@latest
    install_go github.com/BishopFox/jsluice/cmd/jsluice@latest
    install_go github.com/tomnomnom/waybackurls@latest
    install_go github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    
    # Install trufflehog via script if Go binary doesn't exist
    if ! command_exists trufflehog; then
        log_info "Installing trufflehog via install script"
        if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>>"$LOG_FILE"; then
            SUCCESSFUL_INSTALLS+=("trufflehog")
        else
            FAILED_INSTALLS+=("trufflehog")
        fi
    fi
    
    # Fix gau binary name conflict
    if [ -f "$HOME/go/bin/gau" ] && [ ! -f "$HOME/go/bin/gau-cli" ]; then
        mv "$HOME/go/bin/gau" "$HOME/go/bin/gau-cli"
        log_info "Renamed gau to gau-cli to avoid conflicts"
    fi
else
    log_warning "Go not available - skipping Go tools"
fi 

# Installing pipx tools (removed duplicates)
if command_exists pipx; then
    log_info "Installing Python tools via pipx"
    
    # Security tools
    install_pipx git+https://github.com/fortra/impacket.git
    install_pipx git+https://github.com/ly4k/Certipy.git
    install_pipx git+https://github.com/dirkjanm/BloodHound.py.git
    install_pipx git+https://github.com/blacklanternsecurity/MANSPIDER
    install_pipx git+https://github.com/Pennyw0rth/NetExec
    install_pipx git+https://github.com/p0dalirius/Coercer.git
    install_pipx git+https://github.com/skelsec/pypykatz.git
    
    # Global install for mitm6
    if ! pipx list --include-deps | grep -q mitm6; then
        sudo pipx install --global git+https://github.com/dirkjanm/mitm6.git
    fi
    
    install_pipx git+https://github.com/Mazars-Tech/AD_Miner.git
    install_pipx git+https://github.com/zblurx/certsync.git
    install_pipx git+https://github.com/ImpostorKeanu/parsuite.git
    install_pipx git+https://github.com/AetherBlack/abuseACL.git
    install_pipx git+https://github.com/aas-n/aclpwn.py.git
    install_pipx git+https://github.com/dirkjanm/adidnsdump.git
    install_pipx git+https://github.com/androguard/androguard.git
    install_pipx git+https://github.com/angr/angr.git
    install_pipx git+https://github.com/s0md3v/Arjun.git
    install_pipx git+https://github.com/Orange-Cyberdefense/arsenal.git
    install_pipx git+https://github.com/CravateRouge/bloodyAD.git
    install_pipx git+https://github.com/chenjj/CORScanner.git
    install_pipx git+https://github.com/ihebski/DefaultCreds-cheat-sheet.git
    install_pipx git+https://github.com/maurosoria/dirsearch.git
    install_pipx git+https://github.com/login-securite/DonPAPI.git
    install_pipx git+https://github.com/zblurx/dploot.git
    install_pipx git+https://github.com/cddmp/enum4linux-ng.git
    install_pipx git+https://github.com/arthaud/git-dumper.git
    install_pipx git+https://github.com/Dramelac/GoldenCopy.git
    install_pipx git+https://github.com/khast3x/h8mail.git
    install_pipx git+https://github.com/almandin/krbjack.git
    install_pipx git+https://github.com/dirkjanm/ldapdomaindump.git
    install_pipx git+https://github.com/yaap7/ldapsearch-ad.git
    install_pipx git+https://github.com/bee-san/Name-That-Hash.git
    install_pipx git+https://github.com/codingo/NoSQLMap.git
    install_pipx git+https://github.com/i3visio/osrframework.git
    install_pipx git+https://github.com/aniqfakhrul/powerview.py.git
    install_pipx git+https://github.com/calebstewart/pwncat.git
    install_pipx git+https://github.com/Gallopsled/pwntools.git
    install_pipx git+https://github.com/skelsec/pysnaffler.git
    install_pipx git+https://github.com/the-useless-one/pywerview.git
    install_pipx git+https://github.com/ShutdownRepo/pywhisker.git
    install_pipx git+https://github.com/dirkjanm/ROADtools.git
    install_pipx git+https://github.com/Tw1sm/RITM.git
    install_pipx git+https://github.com/threat9/routersploit.git
    install_pipx git+https://github.com/garrettfoster13/sccmhunter.git
    install_pipx git+https://github.com/nccgroup/ScoutSuite.git
    install_pipx git+https://github.com/EnableSecurity/sipvicious.git
    install_pipx git+https://github.com/p0dalirius/smbclient-ng.git
    install_pipx git+https://github.com/jtesta/ssh-audit.git
    install_pipx git+https://github.com/sshuttle/sshuttle.git
    install_pipx git+https://github.com/aboul3la/Sublist3r.git
    install_pipx git+https://github.com/blacklanternsecurity/TREVORspray.git
    install_pipx git+https://github.com/sc0tfree/updog.git
    install_pipx git+https://github.com/EnableSecurity/wafw00f.git
    install_pipx git+https://github.com/garrettfoster13/pre2k.git
else
    log_warning "pipx not available - skipping Python tools"
fi

# Install sliver with better error handling
install_sliver() {
    if command_exists sliver; then
        log_info "Sliver already installed"
        SKIPPED_INSTALLS+=("sliver (already installed)")
        return 0
    fi
    
    log_info "Installing Sliver"
    if curl -sSfL https://sliver.sh/install | sudo bash 2>>"$LOG_FILE"; then
        log_info "Sliver installed successfully"
        SUCCESSFUL_INSTALLS+=("sliver")
    else
        log_error "Failed to install Sliver"
        FAILED_INSTALLS+=("sliver")
    fi
}

install_sliver

echo "=========================================="
echo

# Install zsh plugins with better error handling
install_zsh_plugins() {
    if [ -z "${ZSH_CUSTOM:-}" ] && [ ! -d "$HOME/.oh-my-zsh" ]; then
        log_warning "Oh My Zsh not found - skipping zsh plugins. Run initial_setup.sh first to install Oh My Zsh."
        return 0
    fi
    
    local zsh_custom="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"
    
    # Check if plugins are already installed
    if [ -d "$zsh_custom/plugins/zsh-autosuggestions" ] && [ -d "$zsh_custom/plugins/zsh-syntax-highlighting" ]; then
        log_info "Zsh plugins already installed from initial setup"
        SKIPPED_INSTALLS+=("zsh-autosuggestions (already installed)")
        SKIPPED_INSTALLS+=("zsh-syntax-highlighting (already installed)")
        return 0
    fi
    
    # zsh-autosuggestions
    if [ ! -d "$zsh_custom/plugins/zsh-autosuggestions" ]; then
        log_info "Installing zsh-autosuggestions plugin"
        if git clone --depth 1 https://github.com/zsh-users/zsh-autosuggestions "$zsh_custom/plugins/zsh-autosuggestions" 2>>"$LOG_FILE"; then
            SUCCESSFUL_INSTALLS+=("zsh-autosuggestions")
        else
            FAILED_INSTALLS+=("zsh-autosuggestions")
        fi
    else
        log_info "zsh-autosuggestions plugin already installed"
        SKIPPED_INSTALLS+=("zsh-autosuggestions (already installed)")
    fi
    
    # zsh-syntax-highlighting  
    if [ ! -d "$zsh_custom/plugins/zsh-syntax-highlighting" ]; then
        log_info "Installing zsh-syntax-highlighting plugin"
        if git clone --depth 1 https://github.com/zsh-users/zsh-syntax-highlighting.git "$zsh_custom/plugins/zsh-syntax-highlighting" 2>>"$LOG_FILE"; then
            SUCCESSFUL_INSTALLS+=("zsh-syntax-highlighting")
        else
            FAILED_INSTALLS+=("zsh-syntax-highlighting")
        fi
    else
        log_info "zsh-syntax-highlighting plugin already installed"
        SKIPPED_INSTALLS+=("zsh-syntax-highlighting (already installed)")
    fi
}

install_zsh_plugins

# Print installation summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "         INSTALLATION SUMMARY"
    echo "=========================================="
    
    # Show configuration
    echo "Configuration:"
    echo "  GitHub tools: $([ "$INSTALL_GITHUB_TOOLS" = true ] && echo "✅ Enabled" || echo "❌ Disabled (use --github-tools to enable)")"
    echo ""
    
    if [ ${#SUCCESSFUL_INSTALLS[@]} -gt 0 ]; then
        echo -e "${GREEN}Successfully installed (${#SUCCESSFUL_INSTALLS[@]}):${NC}"
        printf '%s\n' "${SUCCESSFUL_INSTALLS[@]}" | sort
        echo ""
    fi
    
    if [ ${#SKIPPED_INSTALLS[@]} -gt 0 ]; then
        echo -e "${YELLOW}Skipped (${#SKIPPED_INSTALLS[@]}):${NC}"
        printf '%s\n' "${SKIPPED_INSTALLS[@]}" | sort
        echo ""
    fi
    
    if [ ${#FAILED_INSTALLS[@]} -gt 0 ]; then
        echo -e "${RED}Failed installations (${#FAILED_INSTALLS[@]}):${NC}"
        printf '%s\n' "${FAILED_INSTALLS[@]}" | sort
        echo ""
        echo -e "${RED}Check the log file for details: $LOG_FILE${NC}"
    else
        echo -e "${GREEN}All installations completed successfully!${NC}"
    fi
    
    echo "=========================================="
}

log_info "Installation completed"
print_summary
echo "Full log file available at: $LOG_FILE"