#!/usr/bin/env python3
"""
NVD API Usage Monitor
Tracks and displays NVD API usage statistics and data retrieval
"""

import json
import os
from datetime import datetime
from utils.logger import setup_logger

class NVDAPIMonitor:
    def __init__(self):
        self.logger = setup_logger("NVDAPIMonitor")
        self.usage_stats = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'packages_scanned': 0,
            'vulnerabilities_found': 0,
            'api_key_used': False,
            'last_scan_time': None,
            'scan_history': []
        }
        
    def log_api_call(self, package_name, vulnerabilities_found, success=True, api_key_used=False):
        """Log an API call for monitoring"""
        self.usage_stats['total_calls'] += 1
        
        if success:
            self.usage_stats['successful_calls'] += 1
            self.usage_stats['vulnerabilities_found'] += vulnerabilities_found
        else:
            self.usage_stats['failed_calls'] += 1
        
        if api_key_used:
            self.usage_stats['api_key_used'] = True
        
        # Log the call
        call_info = {
            'timestamp': datetime.now().isoformat(),
            'package': package_name,
            'vulnerabilities_found': vulnerabilities_found,
            'success': success,
            'api_key_used': api_key_used
        }
        
        self.usage_stats['scan_history'].append(call_info)
        
        # Keep only last 100 calls
        if len(self.usage_stats['scan_history']) > 100:
            self.usage_stats['scan_history'] = self.usage_stats['scan_history'][-100:]
        
        self.logger.info(f"NVD API Call: {package_name} -> {vulnerabilities_found} vulnerabilities (Success: {success})")
    
    def log_scan_completion(self, total_packages):
        """Log completion of a full vulnerability scan"""
        self.usage_stats['packages_scanned'] += total_packages
        self.usage_stats['last_scan_time'] = datetime.now().isoformat()
        
        self.logger.info(f"Vulnerability scan completed: {total_packages} packages scanned")
    
    def get_usage_summary(self):
        """Get a summary of API usage"""
        success_rate = 0
        if self.usage_stats['total_calls'] > 0:
            success_rate = (self.usage_stats['successful_calls'] / self.usage_stats['total_calls']) * 100
        
        return {
            'total_api_calls': self.usage_stats['total_calls'],
            'successful_calls': self.usage_stats['successful_calls'],
            'failed_calls': self.usage_stats['failed_calls'],
            'success_rate': round(success_rate, 2),
            'packages_scanned': self.usage_stats['packages_scanned'],
            'total_vulnerabilities_found': self.usage_stats['vulnerabilities_found'],
            'api_key_configured': self.usage_stats['api_key_used'],
            'last_scan_time': self.usage_stats['last_scan_time'],
            'avg_vulnerabilities_per_package': self._calculate_avg_vulns_per_package()
        }
    
    def _calculate_avg_vulns_per_package(self):
        """Calculate average vulnerabilities per package"""
        if self.usage_stats['packages_scanned'] > 0:
            return round(self.usage_stats['vulnerabilities_found'] / self.usage_stats['packages_scanned'], 2)
        return 0
    
    def get_recent_activity(self, limit=10):
        """Get recent API activity"""
        return self.usage_stats['scan_history'][-limit:]
    
    def save_stats(self, file_path="logs/nvd_api_stats.json"):
        """Save usage statistics to file"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(self.usage_stats, f, indent=2)
            self.logger.info(f"API usage stats saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save stats: {e}")
    
    def load_stats(self, file_path="logs/nvd_api_stats.json"):
        """Load usage statistics from file"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    self.usage_stats = json.load(f)
                self.logger.info(f"API usage stats loaded from {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to load stats: {e}")
    
    def print_usage_report(self):
        """Print a detailed usage report"""
        summary = self.get_usage_summary()
        
        print("\n" + "="*60)
        print("NVD API USAGE REPORT")
        print("="*60)
        print(f"Total API Calls: {summary['total_api_calls']}")
        print(f"Successful Calls: {summary['successful_calls']}")
        print(f"Failed Calls: {summary['failed_calls']}")
        print(f"Success Rate: {summary['success_rate']}%")
        print(f"Packages Scanned: {summary['packages_scanned']}")
        print(f"Total Vulnerabilities Found: {summary['total_vulnerabilities_found']}")
        print(f"API Key Configured: {'Yes' if summary['api_key_configured'] else 'No'}")
        print(f"Last Scan: {summary['last_scan_time'] or 'Never'}")
        print(f"Avg Vulnerabilities per Package: {summary['avg_vulnerabilities_per_package']}")
        
        # Recent activity
        recent = self.get_recent_activity(5)
        if recent:
            print(f"\nRecent Activity (Last 5 calls):")
            for call in recent:
                status = "SUCCESS" if call['success'] else "FAILED"
                print(f"  {status} {call['package']} -> {call['vulnerabilities_found']} vulnerabilities")
        
        print("="*60)
    
    def check_api_health(self):
        """Check API health and provide recommendations"""
        summary = self.get_usage_summary()
        issues = []
        recommendations = []
        
        # Check success rate
        if summary['success_rate'] < 90:
            issues.append(f"Low success rate: {summary['success_rate']}%")
            recommendations.append("Check API key configuration and network connectivity")
        
        # Check if API key is configured
        if not summary['api_key_configured']:
            issues.append("No API key configured")
            recommendations.append("Configure NVD API key for higher rate limits")
        
        # Check for failed calls
        if summary['failed_calls'] > 0:
            issues.append(f"{summary['failed_calls']} failed API calls")
            recommendations.append("Review failed calls in logs for error patterns")
        
        return {
            'health_status': 'HEALTHY' if not issues else 'ISSUES_DETECTED',
            'issues': issues,
            'recommendations': recommendations,
            'summary': summary
        }
