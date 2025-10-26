#!/usr/bin/env python3
import numpy as np
from sklearn.ensemble import IsolationForest
from utils.logger import setup_logger

class RiskAnalyzer:
    def __init__(self):
        self.logger = setup_logger("RiskAnalyzer")
        self.model = IsolationForest(contamination=0.1)

    def analyze(self, results):
        """Enhanced risk analysis using ML-based vulnerability scoring"""
        self.logger.info("Starting enhanced risk analysis...")
        
        # Configuration risks (unchanged)
        config_score = len(results["config"].get("issues", [])) * 10
        
        # Enhanced vulnerability scoring using ML data
        vuln_data = results["vulnerabilities"]
        vuln_score = self._calculate_enhanced_vulnerability_score(vuln_data)
        
        # File risks (unchanged)
        file_score = results["files"].get("files_scanned", 0) // 10
        
        # Email risks (unchanged)
        email_score = results["email"].get("phishing_emails", 0) * 20
        
        # Calculate weighted overall score using config weights
        weights = {
            'config': 0.25,
            'vulnerabilities': 0.35,
            'files': 0.30,
            'email': 0.10
        }
        
        overall_score = (
            config_score * weights['config'] +
            vuln_score * weights['vulnerabilities'] +
            file_score * weights['files'] +
            email_score * weights['email']
        )
        
        # Cap at 100
        overall_score = min(overall_score, 100)
        
        # Enhanced analysis with ML insights
        analysis_result = {
            "overall_score": round(overall_score, 2),
            "risk_level": self.risk_label(overall_score),
            "component_scores": {
                "configuration": round(config_score, 2),
                "vulnerabilities": round(vuln_score, 2),
                "files": round(file_score, 2),
                "email": round(email_score, 2)
            },
            "ml_insights": self._generate_ml_insights(results),
            "recommendations": self._generate_recommendations(results, overall_score),
            "risk_factors": self._identify_risk_factors(results)
        }
        
        self.logger.info(f"Risk analysis complete - Overall Score: {overall_score}/100 ({analysis_result['risk_level']})")
        return analysis_result

    def _calculate_enhanced_vulnerability_score(self, vuln_data):
        """Calculate vulnerability score using ML-based risk assessment"""
        if not vuln_data:
            return 0.0
        
        # Get ML-based overall risk score if available
        if 'overall_risk_score' in vuln_data:
            ml_score = vuln_data['overall_risk_score']
            self.logger.info(f"Using ML-based vulnerability score: {ml_score}")
            return ml_score
        
        # Fallback to traditional counting method
        vulnerabilities = vuln_data.get("vulnerabilities", [])
        vuln_score = len(vulnerabilities) * 2
        
        # Apply severity multipliers
        severity_multipliers = {
            'Critical': 4.0,
            'High': 3.0,
            'Medium': 2.0,
            'Low': 1.0
        }
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity_info', {}).get('highest_severity', 'Medium')
            multiplier = severity_multipliers.get(severity, 2.0)
            
            # Use ML risk score if available
            ml_risk = vuln.get('ml_risk_score', 50)  # Default to medium risk
            total_weighted_score += ml_risk * multiplier
            total_weight += multiplier
        
        if total_weight > 0:
            vuln_score = total_weighted_score / total_weight
        
        return min(vuln_score, 100)

    def _generate_ml_insights(self, results):
        """Generate ML-based insights from scan results"""
        insights = {
            'vulnerability_analysis': {},
            'risk_trends': {},
            'ml_model_performance': {}
        }
        
        # Vulnerability insights
        vuln_data = results.get("vulnerabilities", {})
        if vuln_data:
            vuln_stats = vuln_data.get('vulnerability_stats', {})
            insights['vulnerability_analysis'] = {
                'total_vulnerabilities': vuln_stats.get('total_vulnerabilities', 0),
                'critical_count': vuln_stats.get('critical_vulnerabilities', 0),
                'high_count': vuln_stats.get('high_vulnerabilities', 0),
                'medium_count': vuln_stats.get('medium_vulnerabilities', 0),
                'low_count': vuln_stats.get('low_vulnerabilities', 0),
                'packages_at_risk': vuln_stats.get('packages_with_vulnerabilities', 0),
                'avg_ml_risk_score': self._calculate_average_ml_score(vuln_stats.get('ml_risk_scores', []))
            }
            
            # API usage insights
            api_stats = vuln_stats.get('api_usage_stats', {})
            insights['ml_model_performance'] = {
                'nvd_api_calls': api_stats.get('total_calls', 0),
                'api_success_rate': api_stats.get('success_rate', 0),
                'api_key_configured': api_stats.get('api_key_configured', False)
            }
        
        return insights

    def _calculate_average_ml_score(self, ml_scores):
        """Calculate average ML risk score"""
        if not ml_scores:
            return 0.0
        return round(sum(ml_scores) / len(ml_scores), 2)

    def _generate_recommendations(self, results, overall_score):
        """Generate actionable recommendations based on scan results"""
        recommendations = []
        
        # Vulnerability recommendations
        vuln_data = results.get("vulnerabilities", {})
        if vuln_data:
            vuln_stats = vuln_data.get('vulnerability_stats', {})
            
            if vuln_stats.get('critical_vulnerabilities', 0) > 0:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'category': 'Vulnerabilities',
                    'message': f"Address {vuln_stats['critical_vulnerabilities']} critical vulnerabilities immediately",
                    'action': 'Update affected packages and apply security patches'
                })
            
            if vuln_stats.get('high_vulnerabilities', 0) > 5:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Vulnerabilities',
                    'message': f"High number of high-severity vulnerabilities ({vuln_stats['high_vulnerabilities']})",
                    'action': 'Prioritize patching high-severity vulnerabilities'
                })
        
        # Configuration recommendations
        config_issues = results.get("config", {}).get("issues", [])
        if config_issues:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Configuration',
                'message': f"Found {len(config_issues)} configuration issues",
                'action': 'Review and fix configuration security issues'
            })
        
        # Email recommendations
        phishing_count = results.get("email", {}).get("phishing_emails", 0)
        if phishing_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Email Security',
                'message': f"Detected {phishing_count} potential phishing emails",
                'action': 'Review email security policies and user training'
            })
        
        # Overall risk recommendations
        if overall_score >= 80:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Overall Security',
                'message': 'System has critical security risks',
                'action': 'Immediate comprehensive security review required'
            })
        elif overall_score >= 60:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Overall Security',
                'message': 'System has significant security risks',
                'action': 'Prioritize security improvements'
            })
        
        return recommendations

    def _identify_risk_factors(self, results):
        """Identify key risk factors"""
        risk_factors = []
        
        # Vulnerability risk factors
        vuln_data = results.get("vulnerabilities", {})
        if vuln_data:
            vuln_stats = vuln_data.get('vulnerability_stats', {})
            
            if vuln_stats.get('critical_vulnerabilities', 0) > 0:
                risk_factors.append('Critical vulnerabilities present')
            
            if vuln_stats.get('packages_with_vulnerabilities', 0) > 10:
                risk_factors.append('Many packages with known vulnerabilities')
            
            avg_ml_score = self._calculate_average_ml_score(vuln_stats.get('ml_risk_scores', []))
            if avg_ml_score > 70:
                risk_factors.append('High average ML risk score for vulnerabilities')
        
        # Configuration risk factors
        config_issues = results.get("config", {}).get("issues", [])
        if config_issues:
            risk_factors.append(f'{len(config_issues)} configuration security issues')
        
        # Email risk factors
        phishing_count = results.get("email", {}).get("phishing_emails", 0)
        if phishing_count > 0:
            risk_factors.append(f'{phishing_count} potential phishing emails detected')
        
        return risk_factors

    def risk_label(self, score):
        """Enhanced risk labeling with more granular levels"""
        if score >= 90:
            return "CRITICAL"
        elif score >= 71:
            return "HIGH"
        elif score >= 51:
            return "MEDIUM-HIGH"
        elif score >= 31:
            return "MEDIUM"
        elif score >= 11:
            return "LOW-MEDIUM"
        else:
            return "LOW"

