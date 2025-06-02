#!/bin/bash

# Setup error logging
if [ ! -d "$HOME/.local/logging" ]; then
    mkdir -p "$HOME/.local/logging"
fi
LOG_FILE="$HOME/.local/logging/install-tools-$(date +%Y%m%d%H%M%S).log"
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

# Determine system architecture
SYSARCH=$(uname -m)
log_info "Detected system architecture: $SYSARCH"

# Create necessary directories
if [ ! -d /opt/tools ]; then
    sudo mkdir -p /opt/tools
    sudo chmod 755 /opt/tools
fi

if [ ! -d /opt/rules ]; then
    sudo mkdir -p /opt/rules
    sudo chmod 755 /opt/rules
fi

if [ ! -d /opt/lists ]; then
    sudo mkdir -p /opt/lists
    sudo chmod 755 /opt/lists
fi

if [ ! -d /opt/tools/powershell ]; then
    sudo mkdir -p /opt/tools/powershell
    sudo chmod 755 /opt/tools/powershell
fi

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
    local options="$2"
    
    show_progress "Installing" "$package via snap"
    log_info "Installing $package via snap"
    
    if ! sudo snap install "$package" $options 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        return 1
    else
        show_success "$package"
        return 0
    fi
}

install_go() {
    local package="$1"
    
    show_progress "Installing" "$package via go"
    log_info "Installing $package via go install"
    
    if ! go install "$package" 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        return 1
    else
        show_success "$package"
        return 0
    fi
}

install_pipx() {
    local package=$1
    
    show_progress "Installing" "$package via pipx"
    log_info "Installing $package via pipx"
    
    if ! pipx install $package 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        return 1
    else
        show_success "$package"
        return 0
    fi
}

install_rust() {
    local package=$1
    
    show_progress "Installing" "$package via cargo"
    log_info "Installing $package via cargo install"
    
    if ! cargo install $package 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        return 1
    else
        show_success "$package"
        return 0
    fi
}

install_gem() {
    local package=$1
    
    show_progress "Installing" "$package via gem"
    log_info "Installing $package via gem"
    
    if ! sudo gem install $package 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}[✗] Failed to install $package${NC}"
        return 1
    else
        show_success "$package"
        return 0
    fi
}

# Git clone with progress indicator
git_clone_tool() {
    local repo=$1
    local destination=$2
    local name=$(basename "$destination")
    
    show_progress "Cloning" "$name"
    log_info "Cloning $repo to $destination"
    
    if ! git clone "$repo" "$destination" 2>>$LOG_FILE; then
        log_error "Failed to clone $name repository"
        echo -e "${RED}[✗] Failed to clone $name repository${NC}"
        return 1
    else
        show_success "$name"
        return 0
    fi
}

# # Update and upgrade system
# log_info "Updating and upgrading system"
# if ! sudo apt update && sudo apt full-upgrade -y 2>>$LOG_FILE; then
#     log_error "Failed to update and upgrade system"
#     echo -e "${RED}Failed to update and upgrade system${NC}"
#     exit 1
# fi


# # Install snap packages
# install_snap go --classic
# install_snap rustup --classic
# install_snap metasploit-framework --classic

if ! rustup default stable 2>>$LOG_FILE; then
    log_error "Failed to set rustup default to stable"
    echo -e "${RED}Failed to set rustup default to stable${NC}"
fi

if ! msfdb init 2>>$LOG_FILE; then
    log_error "Failed to initialize msfdb"
    echo -e "${RED}Failed to initialize msfdb${NC}"
fi

# Install AWS CLI with error handling
log_info "Installing AWS CLI"
if [ "$SYSARCH" == "x86_64" ]; then
    if ! curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o awscliv2.zip 2>>$LOG_FILE; then
        log_error "Failed to download AWS CLI for x86_64"
        echo -e "${RED}Failed to download AWS CLI${NC}"
    fi
elif [ "$SYSARCH" == "aarch64" ]; then
    if ! curl 'https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip' -o awscliv2.zip 2>>$LOG_FILE; then
        log_error "Failed to download AWS CLI for aarch64"
        echo -e "${RED}Failed to download AWS CLI${NC}"
    fi
else
    log_error "Unsupported architecture for AWS CLI: $SYSARCH"
    echo -e "${RED}Unsupported architecture for AWS CLI: $SYSARCH${NC}"
fi

# Only continue with AWS CLI install if the zip was downloaded
if [ -f awscliv2.zip ]; then
    unzip -o awscliv2.zip
    sudo ./aws/install
    rm -f awscliv2.zip
fi

# Install powershell (fix path issue)
log_info "Installing PowerShell"
if ! sudo wget -q https://github.com/PowerShell/PowerShell/releases/download/v7.4.10/powershell-7.4.10-linux-arm64.tar.gz -O /opt/tools/powershell.tar.gz 2>>$LOG_FILE; then
    log_error "Failed to download PowerShell"
    echo -e "${RED}Failed to download PowerShell${NC}"
fi
if [ -f /opt/tools/powershell.tar.gz ]; then
    if ! sudo tar -xzf /opt/tools/powershell.tar.gz -C /opt/tools/powershell 2>>$LOG_FILE; then
        log_error "Failed to extract PowerShell"
        echo -e "${RED}Failed to extract PowerShell${NC}"
    fi
fi

# Install Azure CLI
log_info "Installing Azure CLI"
if ! curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash 2>>$LOG_FILE; then
    log_error "Failed to install Azure CLI"
    echo -e "${RED}Failed to install Azure CLI${NC}"
fi

# Install BloodHound Community Edition
log_info "Installing BloodHound Community Edition"
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-arm64.tar.gz
tar -xvzf bloodhound-cli-linux-arm64.tar.gz
./bloodhound-cli install

# Install Rust tools
log_info "Installing Rust tools"
source $HOME/.cargo/env

# Install Rust tools
install_rust feroxbuster 
install_rust rustscan    

# Install evil-winrm
install_gem evil-winrm 

# Install XSpear
install_gem XSpear

# Install krbrelayx 
# log_info "Installing krbrelayx"
# git clone https://github.com/dirkjanm/krbrelayx.git /opt/tools/krbrelayx
# sudo ln -s /opt/tools/krbrelayx/krbrelayx.py /usr/local/bin/krbrelayx.py
# sudo ln -s /opt/tools/krbrelayx/addspn.py /usr/local/bin/addspn.py
# sudo ln -s /opt/tools/krbrelayx/printerbug.py /usr/local/bin/printerbug.py
# sudo ln -s /opt/tools/krbrelayx/dnstool.py /usr/local/bin/dnstool.py

# Drop a bunch of tools to /opt/tools
log_info "Cloning various tools into /opt/tools"
git_clone_tool https://github.com/openwall/john.git /opt/tools/john
cd /opt/tools/john/src
./configure && make -j$(nproc)
sudo make install
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
git_clone_tool https://github.com/blechschmidt/massdns.git /opt/tools/massdns
cd /opt/tools/massdns/
make
sudo ln -s /opt/tools/massdns/bin/massdns /usr/local/bin/massdns


# Install Go tools
install_go github.com/projectdiscovery/pdtm/cmd/pdtm@latest
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
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
install_go github.com/tomnomnom/waybackurls@latest

# Fix gau
mv $HOME/go/bin/gau $HOME/go/bin/gau-cli 

# Installing pipx tools
install_pipx git+https://github.com/fortra/impacket.git
install_pipx git+https://github.com/ly4k/Certipy.git
install_pipx git+https://github.com/dirkjanm/BloodHound.py.git
install_pipx git+https://github.com/blacklanternsecurity/MANSPIDER
install_pipx git+https://github.com/Pennyw0rth/NetExec
install_pipx git+https://github.com/p0dalirius/Coercer.git
install_pipx git+https://github.com/skelsec/pypykatz.git
sudo pipx install --global git+https://github.com/dirkjanm/mitm6.git
install_pipx git+https://github.com/Mazars-Tech/AD_Miner.git
install_pipx git+https://github.com/zblurx/certsync.git
install_pipx git+https://github.com/ImpostorKeanu/parsuite.git
install_pipx git+https://github.com/AetherBlack/abuseACL.git
install_pipx git+https://github.com/aas-n/aclpwn.py.git
install_pipx git+https://github.com/AD-Security/AD_Miner.git
install_pipx git+https://github.com/dirkjanm/adidnsdump.git
install_pipx git+https://github.com/androguard/androguard.git
install_pipx git+https://github.com/angr/angr.git
install_pipx git+https://github.com/s0md3v/Arjun.git
install_pipx git+https://github.com/Orange-Cyberdefense/arsenal.git
install_pipx git+https://github.com/dirkjanm/BloodHound.py.git
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

# Install sliver 
curl https://sliver.sh/install|sudo bash


# # Install pyenv
# log_info "Installing pyenv"
# if [ ! -d $HOME/.pyenv ]; then
#     curl https://pyenv.run | bash
# fi

echo -n "=========="
echo

# Install rule lists
log_info "Installing rule lists"
wget https://raw.githubusercontent.com/stealthsploit/OneRuleToRuleThemStill/refs/heads/main/OneRuleToRuleThemStill.rule -O /opt/rules/OneRuleToRuleThemStill.rule

# SecLists
git_clone_tool https://github.com/danielmiessler/SecLists.git /opt/lists/SecLists

# OneListForAll
wget https://github.com/six2dez/OneListForAll/archive/refs/tags/v2.4.1.1.tar.gz -O /opt/lists/OneListForAll.tar.gz
cd /opt/lists
tar -xvzf OneListForAll.tar.gz
rm -rf OneListForAll.tar.gz

# Get the directory where the script is located

# SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
# # Fix shell comparison
# if [ "$SHELL" = "$(which zsh)" ]; then
#     log_info "Copying zsh configuration files"
#     cp -r $SCRIPT_DIR/zshrc $HOME/.zshrc
#     cp -r $SCRIPT_DIR/zsh_shortcuts $HOME/.zsh_shortcuts
#     cp -r $SCRIPT_DIR/zsh_aliases $HOME/.zsh_aliases
#     cp -r $SCRIPT_DIR/th0m12.zsh-theme $HOME/.oh-my-zsh/themes/th0m12.zsh-theme
#     cp -r $SCRIPT_DIR/tmux.conf $HOME/.tmux.conf
# else
#     log_info "Copying bash configuration files"
#     cp -r $SCRIPT_DIR/zsh_shortcuts $HOME/.bash_shortcuts
#     cp -r $SCRIPT_DIR/zsh_aliases $HOME/.bash_aliases 
# fi

# Install zsh plugins
if [ ! -d "${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions" ]; then
    log_info "Installing zsh-autosuggestions plugin"
    git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
else
    log_info "zsh-autosuggestions plugin already installed"
fi
if [ ! -d "${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting" ]; then
    log_info "Installing zsh-syntax-highlighting plugin"
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
else
    log_info "zsh-syntax-highlighting plugin already installed"
fi

asdf plugin add nodejs
asdf install nodejs latest
npm install -g pp-finder

pdtm -ia

log_info "Installation completed"
echo "Log file available at: $LOG_FILE"