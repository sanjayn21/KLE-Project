#!/usr/bin/env python3
from utils.logger import setup_logger
from apis.gmail_client import GmailClient

class EmailScanner:
    def __init__(self):
        self.logger = setup_logger("EmailScanner")
        self.client = GmailClient()

    def scan(self):
        messages = self.client.search_messages("after:2025/08/20", 20)
        phishing_count = sum(1 for m in messages if self.is_phishing(m))
        return {"emails_scanned": len(messages), "phishing_emails": phishing_count}

    def is_phishing(self, msg):
        subject = next((h["value"] for h in msg.get("payload", {}).get("headers", []) if h["name"].lower() == "subject"), "").lower()
        return any(kw in subject for kw in ["urgent", "suspended", "verify"])

