#!/bin/bash
# Mobile App Testing Tools Installation

echo "==================================================================="
echo "Installing Mobile App Testing Tools"
echo "==================================================================="

# Python packages
echo "[*] Installing Python packages..."
pip install -r requirements/requirements-mobile.txt

# Android tools
echo "[*] Installing Android tools..."
# apktool
if ! command -v apktool &> /dev/null; then
    echo "[*] Installing apktool..."
    wget https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool_2.9.3.jar -O ~/apktool.jar
    echo 'alias apktool="java -jar ~/apktool.jar"' >> ~/.bashrc
fi

# jadx
if ! command -v jadx &> /dev/null; then
    echo "[*] Installing jadx..."
    wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip -O /tmp/jadx.zip
    unzip /tmp/jadx.zip -d ~/jadx
    echo 'export PATH=$PATH:~/jadx/bin' >> ~/.bashrc
fi

# Frida server (for device)
echo "[*] Downloading Frida server..."
wget https://github.com/frida/frida/releases/download/16.5.9/frida-server-16.5.9-android-arm64.xz -O /tmp/frida-server.xz
unxz /tmp/frida-server.xz

echo ""
echo "[+] Mobile testing tools installed!"
echo ""
echo "Next steps:"
echo "1. Push frida-server to device: adb push /tmp/frida-server /data/local/tmp/"
echo "2. Run frida-server on device: adb shell '/data/local/tmp/frida-server &'"
echo "3. Test: frida-ps -U"
