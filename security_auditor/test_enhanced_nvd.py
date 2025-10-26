#!/usr/bin/env python3
"""
Test script to demonstrate enhanced NVD API usage and ML-based vulnerability scoring
"""

import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from apis.nvd_client import NVDClient
from ml_engine.vulnerability_risk_analyzer import VulnerabilityRiskAnalyzer
from scanners.vulnerability_scanner import VulnerabilityScanner
from utils.nvd_api_monitor import NVDAPIMonitor

def test_nvd_api():
    """Test NVD API functionality"""
    print("🔍 Testing NVD API Client...")
    
    client = NVDClient()
    
    # Test API call
    print("\n📡 Making test API call...")
    vulnerabilities = client.search_cves_by_keyword("openssl", limit=3)
    
    print(f"✅ Found {len(vulnerabilities)} vulnerabilities for 'openssl'")
    
    if vulnerabilities:
        print("\n📊 Sample vulnerability data:")
        vuln = vulnerabilities[0]
        print(f"  CVE ID: {vuln.get('cve_id', 'Unknown')}")
        print(f"  Description: {vuln.get('description', 'No description')[:100]}...")
        print(f"  CVSS Score: {vuln.get('cvss_scores', {}).get('v3_1', {}).get('base_score', 'N/A')}")
        print(f"  Severity: {vuln.get('severity_info', {}).get('highest_severity', 'Unknown')}")
        print(f"  Risk Score: {vuln.get('risk_score', 'N/A')}")
    
    # Print API usage report
    print("\n📈 API Usage Report:")
    client.print_api_report()
    
    return client

def test_ml_risk_analyzer():
    """Test ML-based vulnerability risk analyzer"""
    print("\n🤖 Testing ML Vulnerability Risk Analyzer...")
    
    analyzer = VulnerabilityRiskAnalyzer()
    
    # Test with sample vulnerability data
    sample_vuln = {
        'cve_id': 'CVE-2023-1234',
        'package_name': 'test-package',
        'description': 'Test vulnerability',
        'cvss_scores': {
            'v3_1': {
                'base_score': 8.5,
                'base_severity': 'High',
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Changed',
                'confidentiality_impact': 'High',
                'integrity_impact': 'High',
                'availability_impact': 'High'
            }
        },
        'severity_info': {
            'highest_severity': 'High',
            'critical_count': 0,
            'high_count': 1,
            'medium_count': 0,
            'low_count': 0
        },
        'published_date': '2023-01-01T00:00:00.000Z',
        'last_modified': '2023-01-01T00:00:00.000Z'
    }
    
    risk_score = analyzer.predict_vulnerability_risk(sample_vuln)
    print(f"✅ ML Risk Score for sample vulnerability: {risk_score}")
    
    model_info = analyzer.get_model_info()
    print(f"📊 Model Info: {model_info}")
    
    return analyzer

def test_vulnerability_scanner():
    """Test enhanced vulnerability scanner"""
    print("\n🔍 Testing Enhanced Vulnerability Scanner...")
    
    scanner = VulnerabilityScanner()
    
    # Run a limited scan
    print("📦 Running vulnerability scan...")
    results = scanner.scan()
    
    print(f"✅ Scan completed:")
    print(f"  Total packages: {results['total_packages']}")
    print(f"  Total vulnerabilities: {results['vulnerability_stats']['total_vulnerabilities']}")
    print(f"  Critical vulnerabilities: {results['vulnerability_stats']['critical_vulnerabilities']}")
    print(f"  High vulnerabilities: {results['vulnerability_stats']['high_vulnerabilities']}")
    print(f"  Overall risk score: {results['overall_risk_score']}")
    
    # Show top vulnerabilities
    if results['top_vulnerabilities']:
        print(f"\n🚨 Top 3 Most Risky Vulnerabilities:")
        for i, vuln in enumerate(results['top_vulnerabilities'][:3], 1):
            print(f"  {i}. {vuln.get('cve_id', 'Unknown')} - Risk: {vuln.get('ml_risk_score', 'N/A')}")
    
    return results

def test_api_monitor():
    """Test API monitoring functionality"""
    print("\n📊 Testing API Monitor...")
    
    monitor = NVDAPIMonitor()
    
    # Simulate some API calls
    monitor.log_api_call("test-package-1", 5, success=True, api_key_used=True)
    monitor.log_api_call("test-package-2", 0, success=False, api_key_used=True)
    monitor.log_api_call("test-package-3", 3, success=True, api_key_used=True)
    monitor.log_scan_completion(3)
    
    # Get usage summary
    summary = monitor.get_usage_summary()
    print(f"✅ Monitor Summary:")
    print(f"  Total API calls: {summary['total_api_calls']}")
    print(f"  Success rate: {summary['success_rate']}%")
    print(f"  Total vulnerabilities found: {summary['total_vulnerabilities_found']}")
    
    # Check API health
    health = monitor.check_api_health()
    print(f"🏥 API Health Status: {health['health_status']}")
    
    if health['issues']:
        print("⚠️  Issues detected:")
        for issue in health['issues']:
            print(f"    - {issue}")
    
    if health['recommendations']:
        print("💡 Recommendations:")
        for rec in health['recommendations']:
            print(f"    - {rec}")
    
    return monitor

def main():
    """Run all tests"""
    print("🛡️  Enhanced NVD API and ML Vulnerability Scoring Test")
    print("="*60)
    
    try:
        # Test individual components
        client = test_nvd_api()
        analyzer = test_ml_risk_analyzer()
        results = test_vulnerability_scanner()
        monitor = test_api_monitor()
        
        print("\n" + "="*60)
        print("✅ All tests completed successfully!")
        print("="*60)
        
        # Final summary
        print("\n📋 FINAL SUMMARY:")
        print(f"🔑 NVD API Key Configured: {'Yes' if client.api_key else 'No'}")
        print(f"🤖 ML Model Status: {'Loaded' if analyzer.model else 'Not Loaded'}")
        print(f"📊 Total Vulnerabilities Found: {results['vulnerability_stats']['total_vulnerabilities']}")
        print(f"🎯 Overall Risk Score: {results['overall_risk_score']}")
        print(f"📈 API Success Rate: {monitor.get_usage_summary()['success_rate']}%")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
