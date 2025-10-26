#!/usr/bin/env python3
from utils.logger import setup_logger
from apis.gmail_client import GmailClient
from ml_engine.email_ml_trainer import EmailMLTrainer
import os

class EmailScanner:
    def __init__(self, use_ml=True):
        self.logger = setup_logger("EmailScanner")
        self.client = GmailClient()
        self.use_ml = use_ml
        self.ml_trainer = None
        
        # Initialize ML model if available
        if self.use_ml:
            try:
                self.ml_trainer = EmailMLTrainer()
                model_path = "security_auditor/ml_engine/models/email_phishing_detector.pkl"
                if os.path.exists(model_path):
                    self.ml_trainer.load_model("email_phishing_detector")
                    self.logger.info("ML model loaded successfully")
                else:
                    self.logger.warning("ML model not found, falling back to rule-based detection")
                    self.use_ml = False
            except Exception as e:
                self.logger.warning(f"Failed to load ML model: {str(e)}, using rule-based detection")
                self.use_ml = False

    def scan(self):
        messages = self.client.search_messages("after:2025/08/20", 20)
        phishing_count = sum(1 for m in messages if self.is_phishing(m))
        return {"emails_scanned": len(messages), "phishing_emails": phishing_count}

    def is_phishing(self, msg):
        """
        Detect phishing emails using ML model or rule-based approach
        """
        # Extract email content
        email_content = self._extract_email_content(msg)
        
        if self.use_ml and self.ml_trainer:
            try:
                # Use ML model for prediction
                prediction = self.ml_trainer.predict_phishing(email_content)
                self.logger.debug(f"ML prediction: {prediction}")
                return prediction['is_phishing']
            except Exception as e:
                self.logger.warning(f"ML prediction failed: {str(e)}, using rule-based detection")
        
        # Fallback to rule-based detection
        return self._rule_based_detection(email_content)
    
    def _extract_email_content(self, msg):
        """Extract email content from Gmail message"""
        try:
            # Get subject
            subject = next((h["value"] for h in msg.get("payload", {}).get("headers", []) 
                          if h["name"].lower() == "subject"), "")
            
            # Get body content
            body = ""
            payload = msg.get("payload", {})
            
            if "parts" in payload:
                # Multipart message
                for part in payload["parts"]:
                    if part.get("mimeType") == "text/plain":
                        data = part.get("body", {}).get("data", "")
                        if data:
                            import base64
                            body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            else:
                # Single part message
                data = payload.get("body", {}).get("data", "")
                if data:
                    import base64
                    body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            
            # Combine subject and body
            return f"{subject} {body}".strip()
            
        except Exception as e:
            self.logger.error(f"Error extracting email content: {str(e)}")
            return ""
    
    def _rule_based_detection(self, email_content):
        """Original rule-based phishing detection"""
        email_lower = email_content.lower()
        suspicious_keywords = ["urgent", "suspended", "verify", "click here", "act now", 
                             "limited time", "winner", "congratulations", "free money"]
        return any(kw in email_lower for kw in suspicious_keywords)

