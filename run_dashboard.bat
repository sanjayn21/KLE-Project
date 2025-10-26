@echo off
cd /d "%~dp0"
streamlit run security_auditor\dashboard\live_dashboard.py
pause
