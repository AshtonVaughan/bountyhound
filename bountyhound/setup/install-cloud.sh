#!/bin/bash
# Cloud Infrastructure Testing Tools Installation

echo "===================================================================="
echo "Installing Cloud Testing Tools"
echo "===================================================================="

# AWS CLI
echo "[*] Installing AWS CLI..."
pip install awscli boto3

# Azure CLI
echo "[*] Installing Azure CLI..."
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# GCP CLI
echo "[*] Installing GCP CLI..."
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get update && sudo apt-get install google-cloud-cli

# ScoutSuite
echo "[*] Installing ScoutSuite..."
pip install scoutsuite

# Prowler
echo "[*] Installing Prowler..."
pip install prowler

echo ""
echo "[+] Cloud testing tools installed!"
echo ""
echo "Configure credentials:"
echo "- AWS: aws configure"
echo "- Azure: az login"
echo "- GCP: gcloud auth login"
