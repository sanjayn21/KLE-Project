#!/usr/bin/env python3
import requests
import yaml
import os
from datetime import datetime
from utils.logger import setup_logger
from utils.nvd_api_monitor import NVDAPIMonitor

class NVDClient:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.logger = setup_logger("NVDClient")
        self.api_key = self._load_api_key()
        self.api_calls_made = 0
        self.api_calls_successful = 0
        self.monitor = NVDAPIMonitor()
        self.monitor.load_stats()  # Load existing stats
        
    def _load_api_key(self):
        """Load NVD API key from config"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.yaml')
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config.get('apis', {}).get('nvd', {}).get('api_key', '')
        except Exception as e:
            self.logger.warning(f"Could not load API key: {e}")
            return ""

    def search_cves_by_keyword(self, keyword, limit=5):
        """Enhanced CVE search with detailed vulnerability analysis"""
        params = {
            "keywordSearch": keyword, 
            "resultsPerPage": limit,
            "startIndex": 0
        }
        
        # Add API key if available
        if self.api_key:
            params["apiKey"] = self.api_key
            
        self.api_calls_made += 1
        self.logger.info(f"NVD API Call #{self.api_calls_made}: Searching for '{keyword}'")
        
        try:
            r = requests.get(self.base_url, params=params, timeout=30)
            if r.ok:
                self.api_calls_successful += 1
                data = r.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                # Enhanced processing of vulnerability data
                processed_vulns = []
                for vuln in vulnerabilities:
                    processed_vuln = self._process_vulnerability(vuln, keyword)
                    processed_vulns.append(processed_vuln)
                
                # Log successful API call to monitor
                self.monitor.log_api_call(keyword, len(processed_vulns), success=True, api_key_used=bool(self.api_key))
                
                self.logger.info(f"Found {len(processed_vulns)} vulnerabilities for '{keyword}'")
                return processed_vulns
            else:
                self.logger.error(f"NVD API call failed: {r.status_code} - {r.text}")
                # Log failed API call to monitor
                self.monitor.log_api_call(keyword, 0, success=False, api_key_used=bool(self.api_key))
                return []
        except Exception as e:
            self.logger.error(f"NVD API call exception: {e}")
            # Log failed API call to monitor
            self.monitor.log_api_call(keyword, 0, success=False, api_key_used=bool(self.api_key))
            return []

    def _process_vulnerability(self, vuln_data, package_name):
        """Process and extract detailed vulnerability information"""
        cve = vuln_data.get('cve', {})
        cve_id = cve.get('id', 'Unknown')
        
        # Extract CVSS scores
        cvss_scores = self._extract_cvss_scores(cve)
        
        # Extract severity levels
        severity_info = self._extract_severity_info(cve)
        
        # Extract descriptions
        descriptions = cve.get('descriptions', [])
        description = ""
        if descriptions:
            description = descriptions[0].get('value', '')
        
        # Extract references
        references = cve.get('references', [])
        
        # Calculate risk score based on CVSS and other factors
        risk_score = self._calculate_vulnerability_risk_score(cvss_scores, severity_info)
        
        return {
            'cve_id': cve_id,
            'package_name': package_name,
            'description': description[:200] + "..." if len(description) > 200 else description,
            'cvss_scores': cvss_scores,
            'severity_info': severity_info,
            'risk_score': risk_score,
            'references': len(references),
            'published_date': cve.get('published', ''),
            'last_modified': cve.get('lastModified', ''),
            'source_identifier': cve.get('sourceIdentifier', ''),
            'vuln_status': cve.get('vulnStatus', 'Unknown')
        }

    def _extract_cvss_scores(self, cve_data):
        """Extract CVSS scores from CVE data"""
        metrics = cve_data.get('metrics', {})
        cvss_scores = {}
        
        # CVSS v3.1 scores
        if 'cvssMetricV31' in metrics:
            cvss_v31 = metrics['cvssMetricV31'][0].get('cvssData', {})
            cvss_scores['v3_1'] = {
                'base_score': cvss_v31.get('baseScore', 0.0),
                'base_severity': cvss_v31.get('baseSeverity', 'Unknown'),
                'vector_string': cvss_v31.get('vectorString', ''),
                'attack_vector': cvss_v31.get('attackVector', 'Unknown'),
                'attack_complexity': cvss_v31.get('attackComplexity', 'Unknown'),
                'privileges_required': cvss_v31.get('privilegesRequired', 'Unknown'),
                'user_interaction': cvss_v31.get('userInteraction', 'Unknown'),
                'scope': cvss_v31.get('scope', 'Unknown'),
                'confidentiality_impact': cvss_v31.get('confidentialityImpact', 'Unknown'),
                'integrity_impact': cvss_v31.get('integrityImpact', 'Unknown'),
                'availability_impact': cvss_v31.get('availabilityImpact', 'Unknown')
            }
        
        # CVSS v3.0 scores
        if 'cvssMetricV30' in metrics:
            cvss_v30 = metrics['cvssMetricV30'][0].get('cvssData', {})
            cvss_scores['v3_0'] = {
                'base_score': cvss_v30.get('baseScore', 0.0),
                'base_severity': cvss_v30.get('baseSeverity', 'Unknown')
            }
        
        # CVSS v2 scores
        if 'cvssMetricV2' in metrics:
            cvss_v2 = metrics['cvssMetricV2'][0].get('cvssData', {})
            cvss_scores['v2'] = {
                'base_score': cvss_v2.get('baseScore', 0.0),
                'base_severity': cvss_v2.get('baseSeverity', 'Unknown')
            }
        
        return cvss_scores

    def _extract_severity_info(self, cve_data):
        """Extract severity information"""
        severity_info = {
            'highest_severity': 'Unknown',
            'severity_count': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        metrics = cve_data.get('metrics', {})
        
        # Count severities across all CVSS versions
        for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if metric_type in metrics:
                for metric in metrics[metric_type]:
                    cvss_data = metric.get('cvssData', {})
                    severity = cvss_data.get('baseSeverity', '').lower()
                    
                    if severity:
                        severity_info['severity_count'] += 1
                        if severity == 'critical':
                            severity_info['critical_count'] += 1
                        elif severity == 'high':
                            severity_info['high_count'] += 1
                        elif severity == 'medium':
                            severity_info['medium_count'] += 1
                        elif severity == 'low':
                            severity_info['low_count'] += 1
        
        # Determine highest severity
        if severity_info['critical_count'] > 0:
            severity_info['highest_severity'] = 'Critical'
        elif severity_info['high_count'] > 0:
            severity_info['highest_severity'] = 'High'
        elif severity_info['medium_count'] > 0:
            severity_info['highest_severity'] = 'Medium'
        elif severity_info['low_count'] > 0:
            severity_info['highest_severity'] = 'Low'
        
        return severity_info

    def _calculate_vulnerability_risk_score(self, cvss_scores, severity_info):
        """Calculate ML-based vulnerability risk score"""
        base_score = 0.0
        severity_multiplier = 1.0
        
        # Get the highest CVSS score available
        if 'v3_1' in cvss_scores and cvss_scores['v3_1']['base_score'] > 0:
            base_score = cvss_scores['v3_1']['base_score']
        elif 'v3_0' in cvss_scores and cvss_scores['v3_0']['base_score'] > 0:
            base_score = cvss_scores['v3_0']['base_score']
        elif 'v2' in cvss_scores and cvss_scores['v2']['base_score'] > 0:
            base_score = cvss_scores['v2']['base_score']
        
        # Apply severity multipliers
        highest_severity = severity_info['highest_severity'].lower()
        if highest_severity == 'critical':
            severity_multiplier = 2.0
        elif highest_severity == 'high':
            severity_multiplier = 1.5
        elif highest_severity == 'medium':
            severity_multiplier = 1.0
        elif highest_severity == 'low':
            severity_multiplier = 0.5
        
        # Calculate final risk score (0-100 scale)
        risk_score = min(base_score * severity_multiplier * 10, 100)
        
        return round(risk_score, 2)

    def get_api_usage_stats(self):
        """Get comprehensive API usage statistics"""
        # Save current stats
        self.monitor.save_stats()
        
        # Get monitor summary
        monitor_summary = self.monitor.get_usage_summary()
        
        # Combine with local stats
        return {
            'total_calls': self.api_calls_made,
            'successful_calls': self.api_calls_successful,
            'success_rate': (self.api_calls_successful / self.api_calls_made * 100) if self.api_calls_made > 0 else 0,
            'api_key_configured': bool(self.api_key),
            'last_call_time': datetime.now().isoformat(),
            'monitor_summary': monitor_summary,
            'api_health': self.monitor.check_api_health()
        }
    
    def print_api_report(self):
        """Print detailed API usage report"""
        self.monitor.print_usage_report()
    
    def get_monitor(self):
        """Get the API monitor instance"""
        return self.monitor

