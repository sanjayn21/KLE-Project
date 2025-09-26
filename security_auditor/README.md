Unified AI-Powered Security Auditor (Skeleton)

Quick start

1. Create venv (Linux):
   python3 -m venv .venv && source .venv/bin/activate

2. Install deps:
   pip install -r requirements.txt

3. Configure:
   - Put API keys in environment or .env (see config/config.yaml keys)
   - Adjust paths in config/config.yaml

4. Run CLI:
   python -m security_auditor.main --mode audit

5. Run dashboard:
   streamlit run security_auditor/dashboard/security_dashboard.py

Notes

- Gmail API requires OAuth client credentials and consent. Place token files under a safe location and reference via config.
- VirusTotal API key is required for file lookups.
- NVD API key is optional but recommended for higher rate limits.

