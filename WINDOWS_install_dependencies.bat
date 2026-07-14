@echo off
:: This script installs the required Python libraries for Windows users.
echo [*] Installing dependencies for SOC Threat Hunt Analyzer...

:: Use pip to install pandas (for data manipulation) and openpyxl (for reading .xlsx files)
pip install pandas openpyxl

echo.
echo [+] Installation complete. You can now run soc_threat_hunt_analyzer.py.
pause