#!/usr/bin/env python3
"""
Live Security Dashboard with Real-time Scanning and Report Display
"""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import glob
from datetime import datetime
import pandas as pd
import sys
from pathlib import Path  
import time

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners.config_scanner import ConfigScanner
from scanners.vulnerability_scanner import VulnerabilityScanner
from scanners.file_scanner import FileScanner
from scanners.email_scanner import EmailScanner
from ml_engine.risk_analyzer import RiskAnalyzer
from utils.report_generator import ReportGenerator
from utils.logger import setup_logger

# Page configuration
st.set_page_config(
    page_title="🛡️ Security Auditor Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .scanning-status {
        padding: 1rem;
        background-color: #e3f2fd;
        border-radius: 0.5rem;
        border-left: 5px solid #2196f3;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def run_security_scan():
    """Run the complete security audit"""
    logger = setup_logger("SecurityAuditor")
    results = {}
    
    try:
        logger.info("Starting security audit...")
        
        # Initialize scanners
        config_scanner = ConfigScanner()
        vuln_scanner = VulnerabilityScanner()
        file_scanner = FileScanner()
        email_scanner = EmailScanner()
        risk_analyzer = RiskAnalyzer()
        report_generator = ReportGenerator()
        
        # Run scans
        logger.info("Running config scanner...")
        config_results = config_scanner.scan()
        
        logger.info("Running vulnerability scanner...")
        vuln_results = vuln_scanner.scan()
        
        logger.info("Running file scanner...")
        file_results = file_scanner.scan()
        
        logger.info("Running email scanner...")
        email_results = email_scanner.scan()
        
        # Combine results
        results = {
            "config": config_results,
            "vulnerabilities": vuln_results,
            "files": file_results,
            "email": email_results
        }
        
        # Generate risk analysis
        results["risk_analysis"] = risk_analyzer.analyze(results)
        
        # Save report
        report_generator.generate_report(results)
        
        logger.info("Security audit completed")
        return results
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return None

def load_latest_report():
    """Load the most recent security report"""
    reports_dirs = ["reports", "security_auditor/reports"]
    all_report_files = []
    
    for dir_path in reports_dirs:
        if os.path.exists(dir_path):
            # Support both old and new naming conventions
            report_files = glob.glob(os.path.join(dir_path, "security_report_*.json"))
            audit_files = glob.glob(os.path.join(dir_path, "security_audit_report_*.json"))
            all_report_files.extend(report_files)
            all_report_files.extend(audit_files)
    
    if not all_report_files:
        return None
    
    def get_timestamp_from_filename(filepath):
        filename = os.path.basename(filepath)
        try:
            # Support both old (security_report_) and new (security_audit_report_) naming
            if 'security_report_' in filename:
                parts = filename.replace('security_report_', '').replace('.json', '').split('_')
            elif 'security_audit_report_' in filename:
                parts = filename.replace('security_audit_report_', '').replace('.json', '').split('_')
            else:
                return '00000000_000000'
            
            if len(parts) == 2:
                return parts[0] + '_' + parts[1]
        except:
            pass
        return '00000000_000000'
    
    latest_report = max(all_report_files, key=get_timestamp_from_filename)
    
    try:
        with open(latest_report, 'r') as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading report: {e}")
        return None

def create_risk_gauge(score, title):
    """Create a gauge chart for risk score"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 20], 'color': "lightgreen"},
                {'range': [20, 50], 'color': "yellow"},
                {'range': [50, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(height=300)
    return fig

def create_component_chart(component_scores):
    """Create component risk scores chart"""
    df = pd.DataFrame(list(component_scores.items()), columns=['Component', 'Score'])
    df['Color'] = df['Score'].apply(lambda x: 'green' if x < 20 else 'orange' if x < 50 else 'red')
    
    fig = px.bar(
        df, 
        x='Component', 
        y='Score',
        color='Color',
        title="🔍 Component Risk Breakdown",
        color_discrete_map={'green': '#28a745', 'orange': '#ffc107', 'red': '#dc3545'},
        text='Score'
    )
    fig.update_traces(texttemplate='%{text}/100', textposition='outside')
    fig.update_layout(
        yaxis_title="Risk Score",
        xaxis_title="Security Components",
        showlegend=False,
        height=400
    )
    return fig

def create_file_type_chart(file_results):
    """Create file type distribution chart"""
    file_types = {}
    for result in file_results:
        file_path = result.get('file', '')
        if '.' in file_path:
            ext = file_path.split('.')[-1].lower()
            file_types[ext] = file_types.get(ext, 0) + 1
    
    if not file_types:
        return None
    
    df = pd.DataFrame(list(file_types.items()), columns=['File Type', 'Count'])
    df = df.sort_values('Count', ascending=False).head(10)
    
    fig = px.pie(df, values='Count', names='File Type', title="📁 File Types Scanned")
    return fig

# Main Dashboard
st.markdown('<h1 class="main-header">🛡️ Security Auditor Dashboard</h1>', unsafe_allow_html=True)

# Sidebar Controls
st.sidebar.title("⚙️ Control Panel")

# Check if we need to run a new scan or show existing report
run_new_scan = st.sidebar.button("🔄 Run New Security Scan", type="primary")

if run_new_scan:
    st.markdown('<div class="scanning-status">', unsafe_allow_html=True)
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    steps = [
        ("🔍 Scanning Configuration", 20),
        ("🔍 Analyzing Vulnerabilities", 40),
        ("📁 Scanning Files", 60),
        ("📧 Checking Emails", 80),
        ("📊 Generating Report", 100)
    ]
    
    try:
        for step_name, progress in steps:
            status_text.text(step_name)
            progress_bar.progress(progress / 100)
            time.sleep(0.3)  # Small delay for visual feedback
        
        # Run actual scan
        status_text.text("⏳ Running complete security audit...")
        
        results = run_security_scan()
        
        if results:
            progress_bar.progress(100)
            status_text.text("✅ Scan completed successfully!")
            time.sleep(1)
            
            # Clear the cache to show new data
            st.cache_data.clear()
            
            # Reload page to show results
            st.rerun()
        else:
            status_text.text("❌ Scan failed. Please check logs.")
    except Exception as e:
        st.error(f"Error during scan: {str(e)}")
        status_text.text(f"❌ Error: {str(e)}")
    finally:
        st.markdown('</div>', unsafe_allow_html=True)

# Load and display data
data = load_latest_report()

if data is None:
    st.warning("⚠️ No security reports found.")
    st.info("💡 Click **'🔄 Run New Security Scan'** in the sidebar to start a security audit.")
    
    # Show instructions
    with st.expander("📖 How to Use", expanded=False):
        st.markdown("""
        ### Steps to Run Security Audit:
        
        1. **Click the "🔄 Run New Security Scan" button** in the sidebar
        2. Wait for the scan to complete (typically 1-3 minutes)
        3. Results will automatically display in the dashboard
        
        ### What Gets Scanned:
        - 🔍 **Configuration** - Firewall, SSH, network services
        - 🔍 **Vulnerabilities** - System packages and security updates
        - 📁 **Files** - Suspicious files and VirusTotal analysis
        - 📧 **Email** - Phishing detection and email security
        
        ### Report Features:
        - Real-time risk scoring
        - Visual charts and graphs
        - Detailed vulnerability listings
        - File security analysis
        - Email phishing detection
        """)
else:
    # Sidebar report info
    st.sidebar.title("📊 Report Info")
    
    all_reports = []
    for dir_path in ["reports", "security_auditor/reports"]:
        if os.path.exists(dir_path):
            # Support both old and new naming
            report_files = glob.glob(os.path.join(dir_path, "security_report_*.json"))
            audit_files = glob.glob(os.path.join(dir_path, "security_audit_report_*.json"))
            all_reports.extend(report_files)
            all_reports.extend(audit_files)
    
    if all_reports:
        def get_timestamp_from_filename(filepath):
            filename = os.path.basename(filepath)
            try:
                # Support both old and new naming
                if 'security_report_' in filename:
                    parts = filename.replace('security_report_', '').replace('.json', '').split('_')
                elif 'security_audit_report_' in filename:
                    parts = filename.replace('security_audit_report_', '').replace('.json', '').split('_')
                else:
                    return '00000000_000000'
                
                if len(parts) == 2:
                    return parts[0] + '_' + parts[1]
            except:
                pass
            return '00000000_000000'
        
        latest_report_path = max(all_reports, key=get_timestamp_from_filename)
        current_report = os.path.basename(latest_report_path)
        
        st.sidebar.success(f"📌 Latest Report:\n**{current_report}**")
        
        # Report selection
        report_names = [os.path.basename(f) for f in all_reports]
        if len(report_names) > 1:
            selected_report = st.sidebar.selectbox("View Different Report", report_names, index=0)
            if selected_report and selected_report != current_report:
                try:
                    full_path = None
                    for dir_path in ["reports", "security_auditor/reports"]:
                        potential_path = os.path.join(dir_path, selected_report)
                        if os.path.exists(potential_path):
                            full_path = potential_path
                            break
                    
                    if full_path:
                        with open(full_path, 'r') as f:
                            data = json.load(f)
                except Exception as e:
                    st.error(f"Error loading report: {e}")
    
    # Extract data
    risk_analysis = data.get('risk_analysis', {})
    config = data.get('config', {})
    vulnerabilities = data.get('vulnerabilities', {})
    files = data.get('files', {})
    email = data.get('email', {})
    
    # Main metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        overall_score = risk_analysis.get('overall_score', 0)
        risk_level = risk_analysis.get('risk_level', 'UNKNOWN')
        risk_icon = "🟢" if overall_score < 20 else "🟡" if overall_score < 50 else "🔴"
        st.metric("🎯 Overall Risk Score", f"{overall_score}/100", delta=f"{risk_icon} {risk_level}")
    
    with col2:
        files_scanned = files.get('files_scanned', 0)
        st.metric("📁 Files Scanned", files_scanned)
    
    with col3:
        vuln_count = len(vulnerabilities.get('vulnerabilities', []))
        st.metric("🔍 Vulnerabilities", vuln_count)
    
    with col4:
        emails_scanned = email.get('emails_scanned', 0)
        st.metric("📧 Emails Scanned", emails_scanned)
    
    # NVD API Usage and ML Scoring Display
    st.subheader("🔍 NVD API & ML Analysis")
    
    # Get vulnerability data for NVD API info
    vuln_stats = vulnerabilities.get('vulnerability_stats', {})
    api_stats = vuln_stats.get('api_usage_stats', {})
    ml_model_info = vulnerabilities.get('ml_model_info', {})
    
    # Create columns for NVD API info
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # NVD API Calls
        total_calls = api_stats.get('total_calls', 0)
        success_calls = api_stats.get('successful_calls', 0)
        success_rate = api_stats.get('success_rate', 0)
        
        if total_calls > 0:
            st.metric(
                "📡 NVD API Calls", 
                f"{total_calls}",
                delta=f"✅ {success_rate:.1f}% success"
            )
        else:
            st.metric("📡 NVD API Calls", "0", delta="No calls made")
    
    with col2:
        # Vulnerabilities Found
        total_vulns = vuln_stats.get('total_vulnerabilities', 0)
        critical_vulns = vuln_stats.get('critical_vulnerabilities', 0)
        high_vulns = vuln_stats.get('high_vulnerabilities', 0)
        
        if total_vulns > 0:
            st.metric(
                "🔍 Vulnerabilities Found", 
                f"{total_vulns}",
                delta=f"🚨 {critical_vulns} Critical, {high_vulns} High"
            )
        else:
            st.metric("🔍 Vulnerabilities Found", "0", delta="✅ No vulnerabilities")
    
    with col3:
        # ML Model Status
        model_saved = ml_model_info.get('model_saved', False)
        model_type = ml_model_info.get('model_type', 'Unknown')
        
        if model_saved:
            st.metric(
                "🤖 ML Model Status", 
                "✅ Active",
                delta=f"{model_type}"
            )
        else:
            st.metric("🤖 ML Model Status", "❌ Not Loaded", delta="Fallback mode")
    
    with col4:
        # Overall ML Risk Score
        overall_risk_score = vulnerabilities.get('overall_risk_score', 0)
        
        if overall_risk_score > 0:
            risk_color = "🔴" if overall_risk_score > 70 else "🟡" if overall_risk_score > 40 else "🟢"
            st.metric(
                "🎯 ML Risk Score", 
                f"{overall_risk_score:.1f}/100",
                delta=f"{risk_color} ML-based"
            )
        else:
            st.metric("🎯 ML Risk Score", "0/100", delta="✅ No risks detected")
    
    # Detailed NVD API Information
    if api_stats:
        with st.expander("📊 Detailed NVD API Information", expanded=False):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 📡 API Usage Statistics")
                st.write(f"**Total API Calls:** {api_stats.get('total_calls', 0)}")
                st.write(f"**Successful Calls:** {api_stats.get('successful_calls', 0)}")
                st.write(f"**Failed Calls:** {api_stats.get('failed_calls', 0)}")
                st.write(f"**Success Rate:** {api_stats.get('success_rate', 0):.1f}%")
                st.write(f"**API Key Configured:** {'✅ Yes' if api_stats.get('api_key_configured', False) else '❌ No'}")
            
            with col2:
                st.markdown("### 🔍 Vulnerability Analysis")
                st.write(f"**Packages Scanned:** {vuln_stats.get('total_packages_scanned', 0)}")
                st.write(f"**Packages with Vulnerabilities:** {vuln_stats.get('packages_with_vulnerabilities', 0)}")
                st.write(f"**Critical Vulnerabilities:** {vuln_stats.get('critical_vulnerabilities', 0)}")
                st.write(f"**High Vulnerabilities:** {vuln_stats.get('high_vulnerabilities', 0)}")
                st.write(f"**Medium Vulnerabilities:** {vuln_stats.get('medium_vulnerabilities', 0)}")
                st.write(f"**Low Vulnerabilities:** {vuln_stats.get('low_vulnerabilities', 0)}")
            
            # ML Model Information
            if ml_model_info:
                st.markdown("### 🤖 ML Model Information")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Model Type:** {ml_model_info.get('model_type', 'Unknown')}")
                    st.write(f"**Model Saved:** {'✅ Yes' if ml_model_info.get('model_saved', False) else '❌ No'}")
                    st.write(f"**Scaler Saved:** {'✅ Yes' if ml_model_info.get('scaler_saved', False) else '❌ No'}")
                
                with col2:
                    st.write(f"**Encoders Saved:** {'✅ Yes' if ml_model_info.get('encoders_saved', False) else '❌ No'}")
                    features = ml_model_info.get('features', [])
                    if features:
                        st.write(f"**Features Used:** {len(features)}")
                        with st.expander("View Features"):
                            for feature in features:
                                st.write(f"• {feature}")
    
    # Risk Gauge
    st.subheader("🎯 Risk Assessment")
    col1, col2 = st.columns([1, 1])
    
    with col1:
        gauge_fig = create_risk_gauge(overall_score, "Overall Risk")
        st.plotly_chart(gauge_fig, use_container_width=True)
    
    with col2:
        component_scores = risk_analysis.get('component_scores', {})
        if component_scores:
            comp_fig = create_component_chart(component_scores)
            st.plotly_chart(comp_fig, use_container_width=True)
    
    # Detailed sections
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🛡️ Configuration", "🔍 Vulnerabilities", "📁 Files", "📧 Email", "📊 Network"])
    
    with tab1:
        st.subheader("🛡️ System Configuration")
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Firewall Status:**")
            firewall_status = config.get('firewall_status', {}).get('status', 'Unknown')
            st.success(f"✅ {firewall_status.title()}")
            
            st.write("**SSH Configuration:**")
            ssh_issues = len(config.get('ssh_config', {}).get('issues', []))
            if ssh_issues == 0:
                st.success("✅ No SSH issues found")
            else:
                st.error(f"❌ {ssh_issues} SSH issues found")
        
        with col2:
            st.write("**Network Services:**")
            ports = config.get('network_services', {}).get('listening_ports', [])
            st.info(f"📡 {len(ports)} listening ports detected")
            
            if ports:
                st.write("**Open Ports:**")
                for port in ports[:10]:
                    st.code(port)
                if len(ports) > 10:
                    st.write(f"... and {len(ports) - 10} more ports")
    
    with tab2:
        st.subheader("🔍 Vulnerability Scan")
        total_packages = vulnerabilities.get('total_packages', 0)
        vuln_list = vulnerabilities.get('vulnerabilities', [])
        vuln_stats = vulnerabilities.get('vulnerability_stats', {})
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("📦 Packages Scanned", total_packages)
        with col2:
            st.metric("🔍 Total Vulnerabilities", len(vuln_list))
        with col3:
            st.metric("🚨 Critical", vuln_stats.get('critical_vulnerabilities', 0))
        with col4:
            st.metric("⚠️ High", vuln_stats.get('high_vulnerabilities', 0))
        
        # ML Risk Score Display
        overall_risk_score = vulnerabilities.get('overall_risk_score', 0)
        if overall_risk_score > 0:
            st.info(f"🤖 **ML-Based Overall Risk Score:** {overall_risk_score:.1f}/100")
        
        # Top Vulnerabilities by ML Risk Score
        top_vulns = vulnerabilities.get('top_vulnerabilities', [])
        if top_vulns:
            st.subheader("🚨 Top Vulnerabilities (by ML Risk Score)")
            
            # Create a DataFrame for better display
            vuln_data = []
            for vuln in top_vulns[:10]:  # Show top 10
                vuln_data.append({
                    'CVE ID': vuln.get('cve_id', 'Unknown'),
                    'Package': vuln.get('package_name', 'Unknown'),
                    'Severity': vuln.get('severity_info', {}).get('highest_severity', 'Unknown'),
                    'ML Risk Score': f"{vuln.get('ml_risk_score', 0):.1f}",
                    'CVSS Score': vuln.get('cvss_scores', {}).get('v3_1', {}).get('base_score', 'N/A'),
                    'Description': vuln.get('description', 'No description')[:100] + '...' if len(vuln.get('description', '')) > 100 else vuln.get('description', 'No description')
                })
            
            if vuln_data:
                df = pd.DataFrame(vuln_data)
                st.dataframe(df, use_container_width=True)
        
        # Detailed vulnerability list
        if vuln_list:
            st.subheader("📋 All Vulnerabilities")
            
            # Group by severity
            severity_groups = {
                'Critical': [],
                'High': [],
                'Medium': [],
                'Low': []
            }
            
            for vuln in vuln_list:
                severity = vuln.get('severity_info', {}).get('highest_severity', 'Unknown')
                if severity in severity_groups:
                    severity_groups[severity].append(vuln)
            
            # Display by severity
            for severity, vulns in severity_groups.items():
                if vulns:
                    with st.expander(f"🚨 {severity} Severity ({len(vulns)} vulnerabilities)", expanded=(severity == 'Critical')):
                        for vuln in vulns:
                            col1, col2 = st.columns([3, 1])
                            
                            with col1:
                                st.write(f"**{vuln.get('cve_id', 'Unknown')}** - {vuln.get('package_name', 'Unknown')}")
                                st.write(f"*{vuln.get('description', 'No description')[:200]}...*")
                                
                                # CVSS details
                                cvss_scores = vuln.get('cvss_scores', {})
                                if cvss_scores:
                                    if 'v3_1' in cvss_scores:
                                        cvss = cvss_scores['v3_1']
                                        st.write(f"**CVSS v3.1:** {cvss.get('base_score', 'N/A')} ({cvss.get('base_severity', 'Unknown')})")
                                    elif 'v3_0' in cvss_scores:
                                        cvss = cvss_scores['v3_0']
                                        st.write(f"**CVSS v3.0:** {cvss.get('base_score', 'N/A')} ({cvss.get('base_severity', 'Unknown')})")
                            
                            with col2:
                                ml_score = vuln.get('ml_risk_score', 0)
                                if ml_score > 0:
                                    risk_color = "🔴" if ml_score > 70 else "🟡" if ml_score > 40 else "🟢"
                                    st.metric("ML Risk", f"{ml_score:.1f}", delta=f"{risk_color}")
                                
                                # Published date
                                pub_date = vuln.get('published_date', '')
                                if pub_date:
                                    try:
                                        from datetime import datetime
                                        pub_dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                                        st.write(f"**Published:** {pub_dt.strftime('%Y-%m-%d')}")
                                    except:
                                        st.write(f"**Published:** {pub_date[:10]}")
                            
                            st.divider()
        else:
            st.success("✅ No vulnerabilities found!")
            
            # Show NVD API status even when no vulnerabilities
            api_stats = vuln_stats.get('api_usage_stats', {})
            if api_stats:
                st.info(f"📡 **NVD API Status:** {api_stats.get('total_calls', 0)} calls made, {api_stats.get('success_rate', 0):.1f}% success rate")
    
    with tab3:
        st.subheader("📁 File Security Scan")
        files_scanned = files.get('files_scanned', 0)
        file_results = files.get('results', [])
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Files Scanned", files_scanned)
            st.metric("Files Analyzed", len(file_results))
        
        with col2:
            if file_results:
                file_chart = create_file_type_chart(file_results)
                if file_chart:
                    st.plotly_chart(file_chart, use_container_width=True)
        
        if file_results:
            st.write("**File Scan Results:**")
            for i, result in enumerate(file_results[:20]):
                file_path = result.get('file', 'Unknown')
                file_name = os.path.basename(file_path)
                vt_result = result.get('vt_result', {})
                
                if vt_result.get('found'):
                    vt_data = vt_result.get('data', {}).get('data', {})
                    last_analysis = vt_data.get('last_analysis_stats', {})
                    malicious = last_analysis.get('malicious', 0)
                    
                    if malicious > 0:
                        st.error(f"🚨 {file_name} - {malicious} engines detected as malicious")
                    else:
                        st.success(f"✅ {file_name} - Clean")
                else:
                    st.info(f"ℹ️ {file_name} - Not found in VirusTotal")
            
            if len(file_results) > 20:
                st.write(f"... and {len(file_results) - 20} more files")
    
    with tab4:
        st.subheader("📧 Email Security")
        emails_scanned = email.get('emails_scanned', 0)
        phishing_emails = email.get('phishing_emails', 0)
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Emails Scanned", emails_scanned)
        with col2:
            st.metric("Phishing Emails", phishing_emails)
        
        if emails_scanned == 0:
            st.warning("⚠️ No emails scanned. Gmail API not configured.")
        else:
            if phishing_emails == 0:
                st.success("✅ No phishing emails detected!")
            else:
                st.error(f"❌ {phishing_emails} phishing emails found!")
    
    with tab5:
        st.subheader("📊 Network Analysis")
        ports = config.get('network_services', {}).get('listening_ports', [])
        
        if ports:
            port_data = []
            for port in ports:
                if 'TCP' in port:
                    try:
                        port_num = port.split(':')[1].split()[0]
                        port_data.append(int(port_num))
                    except:
                        continue
            
            if port_data:
                df_ports = pd.DataFrame({'Port': port_data})
                fig = px.histogram(df_ports, x='Port', title="📡 Network Port Distribution")
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("ℹ️ No network ports detected")

# Footer
st.markdown("---")
st.markdown("🛡️ **Security Auditor Dashboard** - Real-time security monitoring and analysis")

