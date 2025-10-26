import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import glob
from datetime import datetime
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="🛡️ Security Auditor Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #1f77b4;
    }
    .risk-low { color: #28a745; }
    .risk-medium { color: #ffc107; }
    .risk-high { color: #dc3545; }
</style>
""", unsafe_allow_html=True)

def load_latest_report():
    """Load the most recent security report"""
    # Check both root reports and security_auditor/reports directories
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
    
    # Parse timestamp from filename and sort to get the most recent
    # Filename format: security_audit_report_YYYYMMDD_HHMMSS.json
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
                return parts[0] + '_' + parts[1]  # YYYYMMDD_HHMMSS
        except:
            pass
        return '00000000_000000'  # Fallback for invalid filenames
    
    # Sort by timestamp (filename-based) to get the most recent
    latest_report = max(all_report_files, key=get_timestamp_from_filename)
    
    try:
        with open(latest_report, 'r') as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading report: {e}")
        return None

def get_risk_color(score):
    """Get color based on risk score"""
    if score < 20:
        return "🟢"
    elif score < 50:
        return "🟡"
    else:
        return "🔴"

def create_risk_gauge(score, title):
    """Create a gauge chart for risk score"""
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': title},
        delta = {'reference': 50},
        gauge = {
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
    
    fig = px.pie(
        df, 
        values='Count', 
        names='File Type',
        title="📁 File Types Scanned"
    )
    return fig

# Main dashboard
st.markdown('<h1 class="main-header">🛡️ Security Auditor Dashboard</h1>', unsafe_allow_html=True)

# Load data
data = load_latest_report()

if data is None:
    st.error("❌ No security reports found. Please run an audit first.")
    st.info("Run: `python main.py --mode audit`")
else:
    # Sidebar for report selection
    st.sidebar.title("📊 Report Selection")
    
    # Get all available reports from both directories
    all_reports = []
    for dir_path in ["reports", "security_auditor/reports"]:
        if os.path.exists(dir_path):
            # Support both old and new naming
            report_files = glob.glob(os.path.join(dir_path, "security_report_*.json"))
            audit_files = glob.glob(os.path.join(dir_path, "security_audit_report_*.json"))
            all_reports.extend(report_files)
            all_reports.extend(audit_files)
    
    # Get the currently loaded report name
    current_report = None
    # Find which report was loaded
    report_names = [os.path.basename(f) for f in all_reports]
    
    if report_names:
        # Determine the current report by checking which one matches
        # Since load_latest_report() was used, find the latest one
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
        
        if len(report_names) > 1:
            # Show current report info
            st.sidebar.info(f"📌 Currently Viewing:\n**{current_report}**")
            st.sidebar.markdown("---")
            
            selected_report = st.sidebar.selectbox("Select Different Report", [current_report] + [r for r in report_names if r != current_report])
            if selected_report and selected_report != current_report:
                try:
                    # Find the full path of the selected report
                    full_path = None
                    for dir_path in ["reports", "security_auditor/reports"]:
                        potential_path = os.path.join(dir_path, selected_report)
                        if os.path.exists(potential_path):
                            full_path = potential_path
                            break
                    
                    if full_path:
                        with open(full_path, 'r') as f:
                            data = json.load(f)
                        st.sidebar.success(f"✅ Switched to {selected_report}")
                except Exception as e:
                    st.error(f"Error loading selected report: {e}")
        else:
            st.sidebar.info(f"📄 Current Report:\n**{current_report}**")
    
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
        risk_icon = get_risk_color(overall_score)
        st.metric(
            "🎯 Overall Risk Score", 
            f"{overall_score}/100",
            delta=f"{risk_icon} {risk_level}"
        )
    
    with col2:
        files_scanned = files.get('files_scanned', 0)
        st.metric("📁 Files Scanned", files_scanned)
    
    with col3:
        vuln_count = len(vulnerabilities.get('vulnerabilities', []))
        st.metric("🔍 Vulnerabilities", vuln_count)
    
    with col4:
        emails_scanned = email.get('emails_scanned', 0)
        st.metric("📧 Emails Scanned", emails_scanned)
    
    # Risk Gauge
    st.subheader("🎯 Risk Assessment")
    col1, col2 = st.columns([1, 1])
    
    with col1:
        gauge_fig = create_risk_gauge(overall_score, "Overall Risk")
        st.plotly_chart(gauge_fig, use_container_width=True)
    
    with col2:
        # Component scores
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
                for port in ports[:10]:  # Show first 10
                    st.code(port)
                if len(ports) > 10:
                    st.write(f"... and {len(ports) - 10} more ports")
    
    with tab2:
        st.subheader("🔍 Vulnerability Scan")
        total_packages = vulnerabilities.get('total_packages', 0)
        vuln_list = vulnerabilities.get('vulnerabilities', [])
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Packages Scanned", total_packages)
        with col2:
            st.metric("Vulnerabilities Found", len(vuln_list))
        
        if vuln_list:
            st.write("**Vulnerabilities Detected:**")
            for vuln in vuln_list:
                st.error(f"❌ {vuln}")
        else:
            st.success("✅ No vulnerabilities found!")
    
    with tab3:
        st.subheader("📁 File Security Scan")
        files_scanned = files.get('files_scanned', 0)
        file_results = files.get('results', [])
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Files Scanned", files_scanned)
            st.metric("Files Analyzed", len(file_results))
        
        with col2:
            # File type chart
            if file_results:
                file_chart = create_file_type_chart(file_results)
                if file_chart:
                    st.plotly_chart(file_chart, use_container_width=True)
        
        # Show file details
        if file_results:
            st.write("**File Scan Results:**")
            for i, result in enumerate(file_results[:20]):  # Show first 20
                file_path = result.get('file', 'Unknown')
                file_name = os.path.basename(file_path)
                size = result.get('size', 0)
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
            # Create network port chart
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