#!/usr/bin/env python3
import numpy as np
from sklearn.ensemble import IsolationForest
from utils.logger import setup_logger

class RiskAnalyzer:
    def __init__(self):
        self.logger = setup_logger("RiskAnalyzer")
        self.model = IsolationForest(contamination=0.1)

    def analyze(self, results):
        config_score = len(results["config"].get("issues", [])) * 10
        vuln_score = len(results["vulnerabilities"].get("vulnerabilities", [])) * 2
        file_score = results["files"].get("files_scanned", 0) // 10
        email_score = results["email"].get("phishing_emails", 0) * 20
        overall_score = min(config_score + vuln_score + file_score + email_score, 100)
        return {
            "overall_score": overall_score,
            "risk_level": self.risk_label(overall_score),
            "component_scores": {
                "configuration": config_score,
                "vulnerabilities": vuln_score,
                "files": file_score,
                "email": email_score
            }
        }

    def risk_label(self, score):
        if score >= 71: return "HIGH"
        if score >= 31: return "MEDIUM"
        return "LOW"

