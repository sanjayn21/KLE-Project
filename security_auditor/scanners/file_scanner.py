#!/usr/bin/env python3
import os, hashlib
from pathlib import Path
from utils.logger import setup_logger
from apis.virustotal_client import VirusTotalClient

class FileScanner:
    def __init__(self):
        self.logger = setup_logger("FileScanner")
        self.virustotal = VirusTotalClient(fast_mode=True)
        self.scan_directories = ["/tmp", str(Path.home()/ "Downloads")]
        self.max_files = 50
        self.max_file_size_bytes = 10 * 1024 * 1024  # 10 MB (internal cap)
        self.vt_simple_limit_bytes = 32 * 1024 * 1024  # 32 MB VT upload limit
        self.max_uploads_per_directory = 3

    def scan(self):
        scanned = []
        total_seen = 0
        for directory in self.scan_directories:
            dirpath = Path(directory)
            if not dirpath.exists():
                continue
            uploads_used = 0
            for file_path in dirpath.rglob("*"):
                if not file_path.is_file():
                    continue
                # Cap workload
                if total_seen >= self.max_files:
                    break
                total_seen += 1
                try:
                    size = file_path.stat().st_size
                    if size > self.max_file_size_bytes:
                        self.logger.debug(f"Skipping large file: {file_path} ({size} bytes)")
                        continue
                    with open(file_path, "rb") as f:
                        content = f.read()
                    file_hash = hashlib.sha256(content).hexdigest()
                    # Upload only first N files per directory; hash-check for the rest
                    allow_upload = uploads_used < self.max_uploads_per_directory
                    if size > self.vt_simple_limit_bytes:
                        vt_result = {"skipped": True, "reason": "file_too_large", "limit_bytes": self.vt_simple_limit_bytes}
                    else:
                        vt_result = self.virustotal.analyze_file_if_needed(
                            file_hash=file_hash,
                            file_size_bytes=size,
                            file_path=str(file_path),
                            file_bytes=content,
                            allow_upload=allow_upload,
                        )
                        if allow_upload and vt_result.get("attempted_upload") and vt_result.get("uploaded"):
                            uploads_used += 1
                    scanned.append({"file": str(file_path), "size": size, "vt_result": vt_result})
                except Exception as exc:
                    self.logger.warning(f"Error scanning file {file_path}: {exc}")
                    continue
        return {'files_scanned': len(scanned), 'results': scanned}

