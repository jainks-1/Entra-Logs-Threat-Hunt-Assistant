# Entra-Logs-Threat-Hunt-Asssitant

Authors/Contributors:
- Kaden Jain

This tool is designed to rapidly identify suspicious activity across Entra ID (Interactive and Non-Interactive) and Microsoft Purview audit logs. It utilizes a GUI to analyze CSV or Excel files for various threats including impossible travel, malicious user agents, legacy auth, mass file operations, and unauthorized mailbox access.

## Requirements
- Python 3.x installed on your system.
- Target log files (.csv or .xlsx) exported from Entra ID or Purview.

## Installation
Run the dependency script for your operating system to install the required Python libraries (`pandas` and `openpyxl`).
- **Windows:** Double-click `windows_install_dependencies.bat`
- **Linux/macOS:** Open a terminal and run `install_dependencies.sh`

## Usage
1. Open a terminal or command prompt and run the script:
   ```bash
   python ThreatHunt.py

OR

1. Double click ThreatHunt.py in file explorer
