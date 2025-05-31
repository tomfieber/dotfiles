#!/bin/bash

# Setup error logging
LOG_FILE="/tmp/install-tools-$(date +%Y%m%d%H%M%S).log"
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
NC='\033[0m' # No Color

# Error handling function
handle_error() {
    log_error "An error occurred on line $1"
}

# Set trap for error handling
trap 'handle_error $LINENO' ERR

# Export path variables
export GOPATH=$HOME/go
export PATH=$HOME/.local/bin:$GOPATH/bin:$HOME/.cargo/env:/snap/bin:$PATH

SYSARCH=$(uname -m)
log_info "System Architecture: $SYSARCH"
echo -e "${GREEN}System Architecture:${NC} $SYSARCH"

# Create directories with error handling
if ! sudo chown -R $USER:$USER /opt 2>>$LOG_FILE; then
    log_error "Failed to set permissions on /opt directory"
    echo -e "${RED}Failed to set permissions on /opt directory${NC}"
fi

if ! mkdir -p /opt/{lists,tools,rules} 2>>$LOG_FILE; then
    log_error "Failed to create directories in /opt"
    echo -e "${RED}Failed to create directories in /opt${NC}" 
fi

# Get desktop environment
DESKTOP=$XDG_CURRENT_DESKTOP
log_info "$DESKTOP desktop environment detected"
echo "[+] $DESKTOP desktop environment detected"

# Autoremove
if ! sudo apt autoremove -y 2>>$LOG_FILE; then
    log_error "Failed to run apt autoremove"
    echo -e "${RED}Failed to run apt autoremove${NC}"
fi
echo "=========="
echo

# Enable snapd
if ! sudo systemctl enable --now snapd 2>>$LOG_FILE; then
    log_error "Failed to enable snapd"
    echo -e "${RED}Failed to enable snapd. Some tools may not install correctly.${NC}"
fi

# Install tools
log_info "Installing tools"
echo "[+] Installing tools"

# Install from snap with error handling
install_snap() {
    local package=$1
    local options=$2
    log_info "Installing $package via snap"
    if ! sudo snap install $package $options 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}Failed to install $package${NC}"
        return 1
    fi
    return 0
}

install_go() {
    local package=$1
    log_info "Installing $package via go install"
    if ! go install $package 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}Failed to install $package${NC}"
        return 1
    fi
}

install_pipx() {
    local package=$1
    log_info "Installing $package via pipx"
    if ! sudo pipx install --global $package 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}Failed to install $package${NC}"
        return 1
    fi
}

install_rust() {
    local package=$1
    log_info "Installing $package via cargo install"
    if ! cargo install $package 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}Failed to install $package${NC}"
        return 1
    fi
}

install_gem() {
    local package=$1
    log_info "Installing $package via gem"
    if ! sudo gem install $package 2>>$LOG_FILE; then
        log_error "Failed to install $package"
        echo -e "${RED}Failed to install $package${NC}"
        return 1
    fi
}

# Install snap packages
install_snap go --classic
install_snap rustup --classic
install_snap nmap
install_snap powershell --classic
install_snap metasploit-framework --classic

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
    if ! curl -O 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o awscliv2.zip 2>>$LOG_FILE; then
        log_error "Failed to download AWS CLI for x86_64"
        echo -e "${RED}Failed to download AWS CLI${NC}"
    fi
fi
if [ "$SYSARCH" == "aarch64" ]; then
    if ! curl -O 'https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip' -o awscliv2.zip 2>>$LOG_FILE; then
        log_error "Failed to download AWS CLI for aarch64"
        echo -e "${RED}Failed to download AWS CLI${NC}"
    fi
fi
unzip awscliv2.zip
sudo ./aws/install

# Install Azure CLI
log_info "Installing Azure CLI"
if ! curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash 2>>$LOG_FILE; then
    log_error "Failed to install Azure CLI"
    echo -e "${RED}Failed to install Azure CLI${NC}"
fi

# Install BloodHound Community Edition
log_info "Installing BloodHound Community Edition"
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-arm64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
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
log_info "Installing krbrelayx"
git clone https://github.com/dirkjanm/krbrelayx.git /opt/tools/krbrelayx
sudo ln -s /opt/tools/krbrelayx/krbrelayx.py /usr/local/bin/krbrelayx.py
sudo ln -s /opt/tools/krbrelayx/addspn.py /usr/local/bin/addspn.py
sudo ln -s /opt/tools/krbrelayx/printerbug.py /usr/local/bin/printerbug.py
sudo ln -s /opt/tools/krbrelayx/dnstool.py /usr/local/bin/dnstool.py

# Drop a bunch of tools to /opt/tools
log_info "Cloning various tools into /opt/tools"
git clone https://github.com/openwall/john.git /opt/tools/john
cd /opt/tools/john/src
./configure && make -j$(nproc)
sudo make install
git clone https://github.com/micahvandeusen/gMSADumper.git /opt/tools/gMSADumper
git clone https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_arm64.tar.gz /opt/tools/ligolo-ng
cd /opt/tools/ligolo-ng
tar -xvzf ligolo-ng_proxy_0.8.2_linux_arm64.tar.gz -C /opt/tools/ligolo-ng
rm -rf ligolo-ng_proxy_0.8.2_linux_arm64.tar.gz
sudo ln -s /opt/tools/ligolo-ng/ligolo-ng_proxy /usr/local/bin/ligolo-ng
git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/tools/ldaprelayscan
git clone https://github.com/bats3c/darkarmour.git /opt/tools/DarkAmour 
git clone https://github.com/m0rtem/CloudFail.git /opt/tools/CloudFail
git clone https://github.com/Ridter/noPac.git /opt/tools/noPac
git clone https://github.com/evilmog/ntlmv1-multi.git /opt/tools/ntlmv1-multi
git clone https://github.com/Greenwolf/ntlm_theft.git /opt/tools/ntlm_theft
git clone https://github.com/shmilylty/OneForAll.git /opt/tools/OneForAll
git clone https://github.com/AlmondOffSec/PassTheCert.git /opt/tools/PassTheCert
git clone https://github.com/topotam/PetitPotam.git /opt/tools/PetitPotam
git clone https://github.com/dirkjanm/PKINITtools.git /opt/tools/PKINITtools
git clone https://github.com/Wh1t3Fox/polenum.git /opt/tools/polenum
git clone https://github.com/Hackndo/pyGPOAbuse.git /opt/tools/pyGPOAbuse
git clone https://github.com/p0dalirius/pyLAPS.git /opt/tools/pyLAPS
git clone https://github.com/GoSecure/pywsus.git /opt/tools/pywsus
git clone https://github.com/lanmaster53/recon-ng.git /opt/tools/recon-ng
git clone https://github.com/s0md3v/ReconDog.git /opt/tools/ReconDog
git clone https://github.com/lgandx/Responder.git /opt/tools/Responder
sudo ln -s /opt/tools/Responder/responder.py /usr/local/bin/responder.py
git clone https://github.com/xpn/sccmwtf.git /opt/tools/sccmwtf
git clone https://github.com/synacktiv/SCCMSecrets.git /opt/tools/SCCMSecrets
git clone https://github.com/pentestmonkey/smtp-user-enum.git /opt/tools/smtp-user-enum
git clone https://github.com/defparam/smuggler.git /opt/tools/smuggler
git clone https://github.com/smicallef/spiderfoot.git /opt/tools/spiderfoot
git clone https://github.com/swisskyrepo/SSRFmap.git /opt/tools/SSRFmap
git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/tools/testssl.sh
sudo ln -s /opt/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
git clone https://github.com/frohoff/ysoserial.git /opt/tools/ysoserial
git clone https://github.com/SecuraBV/CVE-2020-1472.git /opt/tools/CVE-2020-1472-ZeroLogon
git clone https://github.com/s0md3v/Photon.git /opt/tools/Photon
git clone https://github.com/synacktiv/php_filter_chain_generator.git /opt/tools/php_filter_chain_generator
git clone https://github.com/blechschmidt/massdns.git /opt/tools/massdns
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
install_pipx git+https://github.com/ly4k/Certipy.git
install_pipx git+https://github.com/dirkjanm/BloodHound.py.git
install_pipx git+https://github.com/blacklanternsecurity/MANSPIDER
install_pipx git+https://github.com/Pennyw0rth/NetExec
install_pipx git+https://github.com/p0dalirius/Coercer.git
install_pipx git+https://github.com/skelsec/pypykatz.git
install_pipx git+https://github.com/dirkjanm/mitm6.git
install_pipx git+https://github.com/Mazars-Tech/AD_Miner.git
install_pipx git+https://github.com/fortra/impacket.git
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
install_pipx git+https://github.com/login-securite/conpass.git
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


# Install pyenv
log_info "Installing pyenv"
if [ ! -d $HOME/.pyenv ]; then
    curl https://pyenv.run | bash
fi

echo -n "=========="
echo

# Install rule lists
log_info "Installing rule lists"
wget https://raw.githubusercontent.com/stealthsploit/OneRuleToRuleThemStill/refs/heads/main/OneRuleToRuleThemStill.rule -O /opt/rules/OneRuleToRuleThemStill.rule

# SecLists
git clone https://github.com/danielmiessler/SecLists.git /opt/lists/SecLists

# OneListForAll
wget https://github.com/six2dez/OneListForAll/archive/refs/tags/v2.4.1.1.tar.gz -O /opt/lists/OneListForAll.tar.gz
cd /opt/lists
tar -xvzf OneListForAll.tar.gz
rm -rf OneListForAll.tar.gz


# Add zsh_shortcuts and zsh_aliases
log_info "Adding zsh shortcuts and aliases"
cp zshrc $HOME/.zshrc
cp zsh_aliases $HOME/.bash_aliases
cp zsh_shortcuts $HOME/.bash_shortcuts
cp tmux $HOME/.tmux.conf
echo

log_info "Installation completed"
echo "Log file available at: $LOG_FILE"