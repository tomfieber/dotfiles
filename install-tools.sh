#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'


export GOPATH=$HOME/go
export PATH=$HOME/.local/bin:$GOPATH/bin:$HOME/.cargo/env:/snap/bin:$PATH

SYSARCH=$(uname -m)
echo -e "${GREEN}System Architecture:${NC} $SYSARCH"

sudo chown -R $USER:$USER /opt 
mkdir -p /opt/{lists,tools,rules}

# Get desktop environment
DESKTOP=$XDG_CURRENT_DESKTOP
echo "[+] $DESKTOP desktop environment detected"

# Do an update
sudo apt update && sudo apt full-upgrade

# Install some basic necessities 
echo "[+] Installing some basic necessities"
sudo apt install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential prips libkrb5-dev dirb mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode git direnv fzf pipx zsh cewl snapd make libssl-dev libpcap-dev libffi-dev python3-netifaces python-dev-is-python3 build-essential libbz2-dev libreadline-dev libsqlite3-dev curl zlib1g-dev libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev direnv python3-quamash python3-pyfiglet python3-pandas python3-shodan patchelf

# Autoremove
sudo apt autoremove
echo "=========="
echo

sudo systemctl enable --now snapd

# Install from snap
sudo snap install go --classic
sudo snap install rustup --classic
sudo snap install nmap
sudo snap install powershell --classic 
sudo snap install metasploit-framework --classic
rustup default stable
msfdb init

# Install AWS CLI
echo "[+] Installing AWS CLI"
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install Azure CLI
echo "[+] Installing Azure CLI"
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Install BloodHound Community Edition
echo "[+] Installing BloodHound Community Edition"
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install

# Install Rust tools
echo "[+] Installing Rust tools"
if [ ! -d $HOME/.cargo ]; then
    curl https://sh.rustup.rs -sSf | sh -s -- -y
fi
source $HOME/.cargo/env

# Install Rust tools
cargo install feroxbuster 
cargo install rustscan    

# Install evil-winrm
sudo gem install evil-winrm 

# Install XSpear
sudo gem install XSpear

# Install krbrelayx 
git clone https://github.com/dirkjanm/krbrelayx.git /opt/tools/krbrelayx
sudo ln -s /opt/tools/krbrelayx/krbrelayx.py /usr/local/bin/krbrelayx.py
sudo ln -s /opt/tools/krbrelayx/addspn.py /usr/local/bin/addspn.py
sudo ln -s /opt/tools/krbrelayx/printerbug.py /usr/local/bin/printerbug.py
sudo ln -s /opt/tools/krbrelayx/dnstool.py /usr/local/bin/dnstool.py

# Install ldaprelayscan
git clone git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/tools/ldaprelayscan
cd /opt/tools/ldaprelayscan
virtualenv -p python3 venv
source venv/bin/activate
python3 -m pip install -r requirements_exact.txt

# Install ligolo-ng
git clone https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_arm64.tar.gz /opt/tools/ligolo-ng
cd /opt/tools/ligolo-ng
tar -xvzf ligolo-ng_proxy_0.8.2_linux_arm64.tar.gz -C /opt/tools/ligolo-ng
rm -rf ligolo-ng_proxy_0.8.2_linux_arm64.tar.gz
sudo ln -s /opt/tools/ligolo-ng/ligolo-ng_proxy /usr/local/bin/ligolo-ng

wget https://github.com/six2dez/OneListForAll/archive/refs/tags/v2.4.1.1.tar.gz -O /opt/lists/OneListForAll.tar.gz
cd /opt/lists
tar -xvzf OneListForAll.tar.gz
rm -rf OneListForAll.tar.gz


git clone https://github.com/micahvandeusen/gMSADumper.git /opt/tools/gMSADumper
git clone https://github.com/openwall/john.git /opt/tools/john
cd /opt/tools/john/src
./configure && make -j$(nproc)
sudo make install

git clone https://github.com/bats3c/darkarmour.git /opt/tools/DarkAmour 
git clone https://github.com/m0rtem/CloudFail.git /opt/tools/CloudFail
git clone https://github.com/Ridter/noPac.git /opt/tools/noPac
git clone https://github.com/evilmog/ntlmv1-multi.git /opt/tools/ntlmv1-multi
git clone https://github.com/Greenwolf/ntlm_theft.git /opt/tools/ntlm_theft
git clone git clone https://github.com/shmilylty/OneForAll.git /opt/tools/OneForAll
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
git clone https://github.com/danielmiessler/SecLists.git /opt/lists/SecLists
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
git clone https://github.com/m0rtem/CloudFail.git /opt/tools/CloudFail
echo "=========="
echo    


# Install Go tools
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install github.com/ffuf/ffuf/v2@latest
go install github.com/ropnop/kerbrute@latest
go install github.com/sensepost/gowitness@latest
go install -v github.com/RedTeamPentesting/pretender@latest
go install github.com/EgeBalci/amber@latest
go install -v github.com/tomnomnom/anew@latest
go install github.com/asdf-vm/asdf/cmd/asdf@latest
go install -u github.com/tomnomnom/assetfinder@latest
go install -v github.com/lobuhi/byp4xx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/hakluke/hakrevdns@latest
go install github.com/ipinfo/cli/ipinfo@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
go install github.com/tomnomnom/waybackurls@latest

echo "=========="
echo

# Fix gau
mv $HOME/go/bin/gau $HOME/go/bin/gau-cli 

# Install massdns
mkdir ~/Tools
cd ~/Tools
git clone https://github.com/blechschmidt/massdns.git /opt/tools/massdns
cd /opt/tools/massdns/
make
sudo ln -s /opt/tools/massdns/bin/massdns /usr/local/bin/massdns


# Installing pipx tools
echo "${GREEN}[+] Installing some tools from pipx${NC}"
sudo pipx install --global git+https://github.com/ly4k/Certipy.git
sudo pipx install --global git+https://github.com/dirkjanm/BloodHound.py.git
sudo pipx install --global git+https://github.com/blacklanternsecurity/MANSPIDER
sudo pipx install --global git+https://github.com/tldr-pages/tldr.git
sudo pipx install --global git+https://github.com/Pennyw0rth/NetExec
sudo pipx install --global git+https://github.com/p0dalirius/Coercer.git
sudo pipx install --global git+https://github.com/skelsec/pypykatz.git
sudo pipx install --global git+https://github.com/dirkjanm/mitm6.git
sudo pipx install --global git+https://github.com/Mazars-Tech/AD_Miner.git
sudo pipx install --global git+https://github.com/fortra/impacket.git
sudo pipx install --global git+https://github.com/zblurx/certsync.git
sudo pipx install --global git+https://github.com/ImpostorKeanu/parsuite.git
sudo pipx install --global git+https://github.com/AetherBlack/abuseACL.git
sudo pipx install --global git+https://github.com/aas-n/aclpwn.py.git
sudo pipx install --global git+https://github.com/AD-Security/AD_Miner.git
sudo pipx install --global git+https://github.com/dirkjanm/adidnsdump.git
sudo pipx install --global git+https://github.com/androguard/androguard.git
sudo pipx install --global git+https://github.com/angr/angr.git
sudo pipx install --global git+https://github.com/s0md3v/Arjun.git
sudo pipx install --global git+https://github.com/Orange-Cyberdefense/arsenal.git
sudo pipx install --global git+https://github.com/dirkjanm/BloodHound.py.git
sudo pipx install --global git+https://github.com/CravateRouge/bloodyAD.git
sudo pipx install --global git+https://github.com/login-securite/conpass.git
sudo pipx install --global git+https://github.com/chenjj/CORScanner.git
sudo pipx install --global git+https://github.com/ihebski/DefaultCreds-cheat-sheet.git
sudo pipx install --global git+https://github.com/maurosoria/dirsearch.git
sudo pipx install --global git+https://github.com/login-securite/DonPAPI.git
sudo pipx install --global git+https://github.com/zblurx/dploot.git
sudo pipx install --global git+https://github.com/cddmp/enum4linux-ng.git
sudo pipx install --global git+https://github.com/arthaud/git-dumper.git
sudo pipx install --global git+https://github.com/Dramelac/GoldenCopy.git
sudo pipx install --global git+https://github.com/khast3x/h8mail.git
sudo pipx install --global git+https://github.com/almandin/krbjack.git
sudo pipx install --global git+https://github.com/dirkjanm/ldapdomaindump.git
sudo pipx install --global git+https://github.com/yaap7/ldapsearch-ad.git
sudo pipx install --global git+https://github.com/bee-san/Name-That-Hash.git
sudo pipx install --global git+https://github.com/codingo/NoSQLMap.git
sudo pipx install --global git+https://github.com/i3visio/osrframework.git
sudo pipx install --global git+https://github.com/aniqfakhrul/powerview.py.git
sudo pipx install --global git+https://github.com/calebstewart/pwncat.git
sudo pipx install --global git+https://github.com/Gallopsled/pwntools.git
sudo pipx install --global git+https://github.com/skelsec/pysnaffler.git
sudo pipx install --global git+https://github.com/the-useless-one/pywerview.git
sudo pipx install --global git+https://github.com/ShutdownRepo/pywhisker.git
sudo pipx install --global git+https://github.com/dirkjanm/ROADtools.git
sudo pipx install --global git+https://github.com/Tw1sm/RITM.git
sudo pipx install --global git+https://github.com/threat9/routersploit.git
sudo pipx install --global git+https://github.com/garrettfoster13/sccmhunter.git
sudo pipx install --global git+https://github.com/nccgroup/ScoutSuite.git
sudo pipx install --global git+https://github.com/EnableSecurity/sipvicious.git
sudo pipx install --global git+https://github.com/p0dalirius/smbclient-ng.git
sudo pipx install --global git+https://github.com/jtesta/ssh-audit.git
sudo pipx install --global git+https://github.com/sshuttle/sshuttle.git
sudo pipx install --global git+https://github.com/aboul3la/Sublist3r.git
sudo pipx install --global git+https://github.com/blacklanternsecurity/TREVORspray.git
sudo pipx install --global git+https://github.com/sc0tfree/updog.git
sudo pipx install --global git+https://github.com/EnableSecurity/wafw00f.git
sudo pipx install --global git+https://github.com/xmendez/wfuzz.git
sudo pipx install --global git+https://github.com/garrettfoster13/pre2k.git
echo "=========="
echo

# Install sliver 
curl https://sliver.sh/install|sudo bash

# Install rule lists
echo "[+] Installing rule lists"
wget https://raw.githubusercontent.com/stealthsploit/OneRuleToRuleThemStill/refs/heads/main/OneRuleToRuleThemStill.rule -O /opt/rules/OneRuleToRuleThemStill.rule

# Install pyenv
echo "[+] Installing pyenv"
if [ ! -d $HOME/.pyenv ]; then
    curl https://pyenv.run | bash
fi
echo

# Add zsh_shortcuts and zsh_aliases
echo "[+] Installing dotfiles"
cp zsh_aliases $HOME/.bash_aliases
cp zsh_shortcuts $HOME/.bash_shortcuts
cp tmux $HOME/.tmux.conf
echo

echo -e "${green}Install complete.${NC}"

sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
