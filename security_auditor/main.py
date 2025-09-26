#!/usr/bin/env python3
import sys
from pathlib import Path
from dotenv import load_dotenv
from scanners.config_scanner import ConfigScanner
from scanners.vulnerability_scanner import VulnerabilityScanner
from scanners.file_scanner import FileScanner
from scanners.email_scanner import EmailScanner
from ml_engine.risk_analyzer import RiskAnalyzer
from utils.report_generator import ReportGenerator
from utils.logger import setup_logger

class SecurityAuditor:
    def __init__(self):
        self.logger = setup_logger("SecurityAuditor")
        self.config_scanner = ConfigScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.file_scanner = FileScanner()
        self.email_scanner = EmailScanner()
        self.risk = RiskAnalyzer()
        self.report = ReportGenerator()

    def run(self):
        self.logger.info("Starting security audit...")
        self.logger.info("Running config scanner...")
        config_results = self.config_scanner.scan()
        self.logger.info("Running vulnerability scanner...")
        vuln_results = self.vuln_scanner.scan()
        self.logger.info("Running file scanner...")
        file_results = self.file_scanner.scan()
        self.logger.info("Running email scanner...")
        email_results = self.email_scanner.scan()
        results = {
            "config": config_results,
            "vulnerabilities": vuln_results,
            "files": file_results,
            "email": email_results
        }
        results["risk_analysis"] = self.risk.analyze(results)
        self.report.generate_report(results)
        score = results["risk_analysis"]["overall_score"]
        print(f"Audit done! Overall Risk Score: {score}/100")
        return results

import argparse
import os
import sys


def main() -> int:
    # Load environment variables from project root .env if present
    try:
        project_root = Path(__file__).resolve().parents[1]
        env_path = project_root / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="Unified Security Auditor")
    parser.add_argument("--mode", choices=["audit", "dashboard"], default="audit")
    args = parser.parse_args()

    if args.mode == "dashboard":
        os.system("streamlit run security_auditor/dashboard/security_dashboard.py")
        return 0

    auditor = SecurityAuditor()
    auditor.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

