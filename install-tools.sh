#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'


export GOPATH=$HOME/go
export PATH=$HOME/.local/bin:$GOPATH/bin:$HOME/.cargo/env:/snap/bin:$PATH

SYSARCH=$(uname -m)
echo -e "${GREEN}System Architecture:${NC} $SYSARCH"

# Get desktop environment
DESKTOP=$XDG_CURRENT_DESKTOP
echo "[+] $DESKTOP desktop environment detected"

# Do an update
sudo apt update && sudo apt full-upgrade

# Install some basic necessities 
echo "[+] Installing some basic necessities"
sudo apt install -y git direnv pipx zsh snapd make libssl-dev libpcap-dev libffi-dev python3-netifaces python-dev-is-python3 build-essential libbz2-dev libreadline-dev libsqlite3-dev curl zlib1g-dev libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev direnv python3-quamash python3-pyfiglet python3-pandas python3-shodan patchelf

# Autoremove
sudo apt autoremove
echo "=========="
echo

sudo systemctl enable --now snapd

# Install from snap
sudo snap install go --classic
sudo snap install rustup --classic
sudo snap install nmap
sudo snap install metasploit-framework --classic
rustup default stable
msfdb init


# Install Go tools
echo "[+] Install pdtm"
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
echo "[+] Installing amass"
go install -v github.com/owasp-amass/amass/v4/...@master
echo "[+] Installing ffuf"
go install github.com/ffuf/ffuf/v2@latest
echo "[+] Installing kerbrute"
go install github.com/ropnop/kerbrute@latest
echo "[+] Installing gowitness"
go install github.com/sensepost/gowitness@latest
echo "[+] Installing pretender"
go install -v github.com/RedTeamPentesting/pretender@latest
echo "=========="
echo

mkdir ~/Tools
cd ~/Tools
git clone https://github.com/blechschmidt/massdns.git ~/Tools/massdns
cd ~/Tools/massdns/
make
sudo ln -s $(pwd)/bin/massdns /usr/local/bin/massdns


# Installing pipx tools
echo "${GREEN}[+] Installing some tools from pipx${NC}"
pipx install certipy-ad
pipx install bloodhound
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
pipx install tldr
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install coercer
pipx install pypykatz
pipx install mitm6
pipx install 'git+https://github.com/Mazars-Tech/AD_Miner.git'
pipx install 'git+https://github.com/fortra/impacket.git'
pipx install certsync
pipx install parsuite
echo "=========="
echo

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
