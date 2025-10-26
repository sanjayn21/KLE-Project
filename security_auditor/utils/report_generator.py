#!/usr/bin/env python3
import json
import os
from datetime import datetime
from utils.logger import setup_logger

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.logger = setup_logger("ReportGenerator")
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
        self.output_dir = output_dir

    def generate_report(self, results):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/security_audit_report_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)
        self.logger.info(f"Report saved: {filename}")

