# 🚀 Security Auditor - Usage Guide

## Quick Start

### Run the Complete Security Dashboard

```bash
python main.py
```

or explicitly:

```bash
python main.py --mode live
```

This will:
1. ✅ Open a live dashboard on `http://localhost:8501`
2. ✅ Show scanning interface with real-time progress
3. ✅ Display comprehensive security report after scan
4. ✅ Visualize all results with charts and metrics

## Command Options

### 1. Live Dashboard (Recommended)
**Default mode** - Interactive dashboard with scan and report display

```bash
python main.py
# or
python main.py --mode live
```

**Features:**
- 🔄 "Run New Security Scan" button in sidebar
- 📊 Real-time progress indicators
- 📈 Visual charts and graphs
- 🎯 Interactive risk assessment
- 📁 Detailed component analysis

### 2. Dashboard Only
View existing reports without scanning

```bash
python main.py --mode dashboard
```

**Features:**
- 📊 View previously generated reports
- 📅 Select different report files
- 📈 Visualize historical data

### 3. Command Line Audit Only
Run scan and save report without dashboard

```bash
python main.py --mode audit
```

**Features:**
- ⚡ Fast command-line execution
- 💾 Saves report to `reports/` directory
- 📝 Output score summary

## How It Works

### Step-by-Step Process

1. **Launch Dashboard**
   ```bash
   python main.py
   ```
   - Opens Streamlit on localhost:8501
   - Shows "No reports found" if first run

2. **Run Security Scan**
   - Click "🔄 Run New Security Scan" button in sidebar
   - Watch real-time progress:
     - 🔍 Scanning Configuration (20%)
     - 🔍 Analyzing Vulnerabilities (40%)
     - 📁 Scanning Files (60%)
     - 📧 Checking Emails (80%)
     - 📊 Generating Report (100%)

3. **View Results**
   - Dashboard automatically displays new report
   - See risk score (0-100)
   - Explore tabs:
     - **Configuration** - Firewall, SSH, network
     - **Vulnerabilities** - Package security
     - **Files** - File security analysis
     - **Email** - Phishing detection
     - **Network** - Port analysis

## Dashboard Features

### Main Metrics
- **Overall Risk Score** - 0-100 scale with color coding
- **Files Scanned** - Total files analyzed
- **Vulnerabilities Found** - Security issues detected
- **Emails Scanned** - Phishing emails detected

### Visualizations
- 🎯 **Risk Gauge** - Overall security posture
- 📊 **Component Breakdown** - Individual risk scores
- 📁 **File Types Chart** - Distribution of scanned files
- 📡 **Network Ports** - Listening port analysis

### Interactive Elements
- ⏱️ Real-time scanning progress
- 🔄 Re-scan anytime with one click
- 📅 Select historical reports from dropdown
- 💾 Automatic report saving

## Example Workflow

```bash
# 1. Start the dashboard
python main.py

# 2. In the browser (localhost:8501):
#    - Click "🔄 Run New Security Scan"
#    - Wait for progress bar to complete
#    - View comprehensive security report
#    - Explore different tabs
#    - Review risk scores and recommendations

# 3. Run another scan later:
#    - Click scan button again
#    - New report automatically generated
#    - Dashboard updates with latest results
```

## Troubleshooting

### Dashboard won't open
```bash
# Install dependencies first
pip install -r requirements.txt

# Then run
python main.py
```

### No reports showing
- Make sure you've run a scan (click scan button)
- Check `reports/` directory exists
- Look for `security_report_*.json` files

### Scanning takes too long
- File scanner is most time-consuming
- Reduce files in scan directories
- Configure scan paths in `config.yaml`

### Port 8501 already in use
```bash
# Kill existing Streamlit process
# Or use different port:
streamlit run security_auditor/dashboard/live_dashboard.py --server.port 8502
```

## Tips

💡 **Best Practices:**
- Run scans regularly (daily/weekly)
- Keep an eye on risk score trends
- Review vulnerabilities tab for critical issues
- Check email tab for phishing attempts
- Monitor open ports in network tab

💡 **Keyboard Shortcuts:**
- `R` - Rerun app (refresh dashboard)
- `C` - Clear cache
- `Ctrl+C` - Stop server

💡 **Data Storage:**
- Reports saved in `reports/` directory
- Timestamped filenames: `security_report_YYYYMMDD_HHMMSS.json`
- View historical reports via sidebar dropdown

## Next Steps

After reviewing your security report:

1. **Fix High-Risk Issues** - Address vulnerabilities immediately
2. **Configure Scan Settings** - Adjust `config.yaml` as needed
3. **Set Up Notifications** - Integrate with email alerts
4. **Train ML Model** - Improve email phishing detection
   ```bash
   python train_email_model.py --data_path your_dataset.csv
   ```

## Support

For issues or questions:
- Check logs in `security_auditor/logs/` directory
- Review configuration in `security_auditor/config/config.yaml`
- Examine generated reports in `reports/` directory
