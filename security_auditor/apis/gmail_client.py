#!/usr/bin/env python3
import json, os, base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from utils.logger import setup_logger

class GmailClient:
    def __init__(self):
        self.scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.token_path = "config/gmail_token.json"
        self.credentials_path = "config/gmail_credentials.json"
        self.logger = setup_logger("GmailClient")
        self.service = None  # Lazy auth to avoid failure when creds are missing

    def authenticate(self):
        if not os.path.exists(self.credentials_path):
            self.logger.warning("Gmail credentials not found at %s. Skipping email scan.", self.credentials_path)
            return None
        creds = None
        if os.path.exists(self.token_path):
            creds = Credentials.from_authorized_user_file(self.token_path, self.scopes)
        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(self.credentials_path, self.scopes)
            creds = flow.run_local_server(port=0)
            with open(self.token_path, 'w') as token_file:
                token_file.write(creds.to_json())
        return build('gmail', 'v1', credentials=creds)

    def search_messages(self, query, max_results=10):
        if self.service is None:
            self.service = self.authenticate()
        if self.service is None:
            return []
        results = self.service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
        messages = results.get('messages', [])
        details = []
        for msg in messages:
            details.append(self.service.users().messages().get(userId='me', id=msg['id']).execute())
        return details

