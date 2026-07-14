#!/bin/bash
# This script installs the required Python libraries for Linux/macOS users.

echo "[*] Installing dependencies for SOC Threat Hunt Analyzer..."

# Use pip3 to install pandas (for data manipulation) and openpyxl (for reading .xlsx files)
pip3 install pandas openpyxl

echo "[+] Installation complete. You can now run: python3 soc_threat_hunt_analyzer.py"