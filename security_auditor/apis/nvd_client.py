#!/usr/bin/env python3
import requests
from utils.logger import setup_logger

class NVDClient:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.logger = setup_logger("NVDClient")

    def search_cves_by_keyword(self, keyword, limit=5):
        params = {"keywordSearch": keyword, "resultsPerPage": limit}
        r = requests.get(self.base_url, params=params, timeout=30)
        if r.ok:
            data = r.json()
            return data.get('vulnerabilities', [])
        return []

