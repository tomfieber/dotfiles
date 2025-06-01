#!/bin/bash

#!/bin/bash

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    echo "Please try again using: su root and then run the script."
    exit 1
fi

apt udpate && apt full-upgrade -y
sudo apt install -y forensics-all wfuzz tesseract-ocr antiword docker.io docker-compose python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential prips libkrb5-dev dirb mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode git direnv fzf pipx zsh cewl snapd make libssl-dev libpcap-dev libffi-dev python3-netifaces python-dev-is-python3 build-essential libbz2-dev libreadline-dev libsqlite3-dev curl zlib1g-dev libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev direnv python3-quamash python3-pyfiglet python3-pandas python3-shodan patchelf

mkdir -p /opt/{tools/powershell,lists}

# Run user mods
/usr/sbin/usermod -aG docker thomas
/usr/sbin/usermod -aG sudo thomas