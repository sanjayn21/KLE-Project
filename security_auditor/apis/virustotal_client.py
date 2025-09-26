#!/usr/bin/env python3
import os
import time
import requests
from utils.logger import setup_logger


class VirusTotalClient:
    def __init__(self, api_key=None, fast_mode=True):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.api_key = api_key or os.environ.get("VT_API_KEY") or "YOUR_VIRUSTOTAL_API_KEY"
        self.logger = setup_logger("VTClient")
        self.simple_upload_limit_bytes = 32 * 1024 * 1024  # 32MB for free/simple upload
        # Fast mode shortens polling so we don't wait long for sandbox/behavior
        self.fast_mode = fast_mode

    def check_file_hash(self, file_hash):
        if not self.api_key or self.api_key == "YOUR_VIRUSTOTAL_API_KEY":
            # Skip network call when API key isn't configured to prevent hangs
            self.logger.info("VirusTotal API key not set. Skipping VT lookup.")
            return {"skipped": True, "reason": "no_api_key"}
        url = f"{self.base_url}/files/{file_hash}"
        headers = {"x-apikey": self.api_key}
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.ok:
                return {"found": True, "source": "hash", "data": r.json()}
            if r.status_code == 404:
                # Not found in VT database
                return {"found": False, "reason": "not_found"}
            self.logger.warning(f"VT lookup failed: {r.status_code} {r.text[:120]}")
            return {"found": False, "reason": f"http_{r.status_code}"}
        except Exception as exc:
            self.logger.warning(f"VT lookup error: {exc}")
            return {"found": False, "reason": "exception"}

    def _poll_analysis(self, analysis_id, timeout_seconds=None, interval_seconds=3):
        """Poll VT analysis until completed or timeout."""
        headers = {"x-apikey": self.api_key}
        url = f"{self.base_url}/analyses/{analysis_id}"
        if timeout_seconds is None:
            timeout_seconds = 20 if self.fast_mode else 60
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if not r.ok:
                    self.logger.warning(f"VT analysis poll failed: {r.status_code} {r.text[:120]}")
                    time.sleep(interval_seconds)
                    continue
                data = r.json()
                status = data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return data
            except Exception as exc:
                self.logger.warning(f"VT analysis poll error: {exc}")
            time.sleep(interval_seconds)
        return {"timeout": True}

    def upload_file_for_analysis(self, file_path, file_bytes):
        """Upload a file to VT for analysis and poll for the result."""
        if not self.api_key or self.api_key == "YOUR_VIRUSTOTAL_API_KEY":
            self.logger.info("VirusTotal API key not set. Skipping VT upload.")
            return {"skipped": True, "reason": "no_api_key"}
        headers = {"x-apikey": self.api_key}
        url = f"{self.base_url}/files"
        files = {"file": (os.path.basename(file_path) or "file.bin", file_bytes)}
        try:
            r = requests.post(url, headers=headers, files=files, timeout=30)
            if not r.ok:
                self.logger.warning(f"VT upload failed: {r.status_code} {r.text[:200]}")
                return {"uploaded": False, "reason": f"http_{r.status_code}", "response": r.text[:200]}
            analysis_id = r.json().get("data", {}).get("id")
            if not analysis_id:
                return {"uploaded": True, "polled": False, "reason": "no_analysis_id", "data": r.json()}
            analysis = self._poll_analysis(analysis_id)
            return {"uploaded": True, "polled": True, "data": analysis}
        except Exception as exc:
            self.logger.warning(f"VT upload error: {exc}")
            return {"uploaded": False, "reason": "exception", "error": str(exc)}

    def analyze_file_if_needed(self, file_hash, file_size_bytes, file_path, file_bytes, allow_upload=True):
        """
        First check by hash. If not found and within simple upload limit, upload and poll.
        Skips upload when file is larger than 32MB.
        """
        lookup = self.check_file_hash(file_hash)
        if lookup.get("found"):
            return lookup
        if not allow_upload:
            return {"found": False, "attempted_upload": False, "reason": "upload_not_allowed"}
        if file_size_bytes > self.simple_upload_limit_bytes:
            return {"skipped": True, "reason": "file_too_large", "limit_bytes": self.simple_upload_limit_bytes}
        upload = self.upload_file_for_analysis(file_path, file_bytes)
        result = {"found": False, "attempted_upload": True}
        result.update(upload)
        return result

