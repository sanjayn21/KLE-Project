# 🛡️ Security Auditor - AI-Powered Security Scanner

Unified security auditing system with ML-based phishing detection, vulnerability scanning, file analysis, and real-time dashboard.

## 🚀 Quick Start

### Option 1: Run Dashboard (Recommended)
```bash
python security_auditor/main.py
```
Opens interactive dashboard on `http://localhost:8501`

### Option 2: Run Audit Only
```bash
python security_auditor/main.py --mode audit
```

### Option 3: Use Batch File (Windows)
Double-click `run_dashboard.bat`

## 📋 Features

- **🔍 Vulnerability Scanning** - NVD database integration
- **📁 File Security Analysis** - VirusTotal integration  
- **📧 ML Email Phishing Detection** - Trained model with 88.9% accuracy
- **🛡️ Configuration Auditing** - Firewall, SSH, network services
- **📊 Real-time Dashboard** - Interactive visualizations
- **📈 Risk Assessment** - Comprehensive scoring system

## 📂 Project Structure

```
KLE-Project/
├── README.md                    # This file
├── run_dashboard.bat           # Quick launcher (Windows)
├── emails.csv                   # ML training dataset
├── reports/                     # Security reports (JSON)
├── security_auditor/
│   ├── main.py                  # Main entry point
│   ├── config/
│   │   └── config.yaml         # Configuration
│   ├── apis/
│   │   ├── nvd_client.py      # NVD API client
│   │   ├── virustotal_client.py
│   │   └── gmail_client.py    # Gmail API client
│   ├── scanners/
│   │   ├── config_scanner.py  # System config audit
│   │   ├── vulnerability_scanner.py
│   │   ├── file_scanner.py
│   │   └── email_scanner.py   # ML phishing detection
│   ├── ml_engine/
│   │   ├── email_ml_trainer.py # ML training
│   │   ├── models/             # Trained models
│   │   └── risk_analyzer.py
│   ├── dashboard/
│   │   ├── live_dashboard.py  # Interactive dashboard
│   │   └── security_dashboard.py
│   └── utils/
│       ├── logger.py
│       └── report_generator.py
└── logs/                        # Application logs
```

## 🎯 Dashboard Usage

1. **Launch Dashboard**
   ```bash
   python security_auditor/main.py
   ```

2. **Run Security Scan**
   - Click "🔄 Run New Security Scan" button in sidebar
   - Watch real-time progress
   - Results display automatically

3. **View Results**
   - Overall risk score (0-100)
   - Configuration issues
   - Vulnerabilities found
   - File security analysis
   - Email phishing detection
   - Network port analysis

## 🤖 ML Email Phishing Detection

### Training Completed ✅
- **Model**: Random Forest
- **Accuracy**: 88.90%
- **Features**: 10 phishing indicators
- **Location**: `security_auditor/ml_engine/models/`

### How It Works

The model extracts features from emails:
1. **Having_IP** - IP address detection
2. **Having_At_Symbol** - @ symbol usage
3. **Prefix_Suffix** - URL patterns
4. **URL_Length_Long** - Suspicious URL length
5. **HTTPS_Token_in_URL** - Secure connections
6. **Suspicious_TLD** - .tk, .click, etc.
7. **Shortening_Service** - URL shorteners
8. **Contains_Password_Field** - Password requests
9. **Domain_Old** - Domain age heuristic
10. **Alexa_Popular** - Popular domains

### Retraining (Optional)

If you have a new dataset:
```bash
python security_auditor/train_email_model.py --data_path emails.csv

# Options:
# --model_type random_forest (default)
# --model_type gradient_boosting
# --model_type logistic_regression
# --model_type svm
```

## ⚙️ Configuration

Edit `security_auditor/config/config.yaml`:

```yaml
apis:
  nvd:
    api_key: "YOUR_NVD_API_KEY"
  virustotal:
    api_key: "YOUR_VT_API_KEY"
  gmail:
    credentials_file: "config/gmail_credentials.json"
    token_file: "config/gmail_token.json"

scan:
  high_risk_dirs:
    - /home/USER/Downloads
    - /tmp
  check_firewall: true
  check_ssh: true
```

## 🔑 API Setup

### Gmail API (Optional)
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth 2.0 credentials
3. Save as `security_auditor/config/gmail_credentials.json`

### VirusTotal API (Optional)
1. Get API key from [VirusTotal](https://www.virustotal.com/)
2. Add to `config/config.yaml`

### NVD API (Optional)
1. Get key from [NVD](https://nvd.nist.gov/developers/api-key)
2. Add to `config/config.yaml`

## 📊 Report Format

Reports are saved as JSON in `reports/`:
- `security_audit_report_YYYYMMDD_HHMMSS.json`
- Includes risk scores, vulnerabilities, file analysis
- Dashboard automatically loads latest report

## 📦 Installation

```bash
# Install dependencies
pip install -r security_auditor/requirements.txt

# Install additional ML dependencies
pip install pandas numpy scikit-learn joblib streamlit plotly
```

## 🛠️ Commands

### Dashboard
```bash
python security_auditor/main.py
# or
python security_auditor/main.py --mode live
```

### Audit Only
```bash
python security_auditor/main.py --mode audit
```

### Train Email Model
```bash
python security_auditor/train_email_model.py --data_path emails.csv
```

### View Old Reports
```bash
python security_auditor/main.py --mode dashboard
```

## 📈 Model Performance

### Training Results
- **Dataset**: 5,000 emails (Kaggle)
- **Phishing**: 2,962 (59%)
- **Legitimate**: 2,038 (41%)
- **Test Accuracy**: 88.90%
- **Cross-Validation**: 88.58% (±1.01%)

### Classification Metrics
- **Precision**: 0.93 (Phishing detection)
- **Recall**: 0.88 (Phishing coverage)
- **F1-Score**: 0.90

## 🔍 Security Components

### 1. Configuration Scanner
- Firewall status
- SSH configuration
- Network listening ports
- Service detection

### 2. Vulnerability Scanner
- Package security audit
- CVE database lookup
- Update recommendations

### 3. File Scanner
- VirusTotal integration
- Suspicious file detection
- File type analysis

### 4. Email Scanner
- ML phishing detection
- Gmail API integration
- Real-time analysis

## 📝 Logs

View logs in `logs/` directory:
- ConfigScanner.log
- VulnerabilityScanner.log
- FileScanner.log
- EmailScanner.log
- SecurityAuditor.log

## 🐛 Troubleshooting

### Dashboard won't open
```bash
pip install streamlit plotly
python security_auditor/main.py
```

### ML model not found
```bash
# Retrain the model
python security_auditor/train_email_model.py --data_path emails.csv
```

### API errors
- Check API keys in `config/config.yaml`
- Verify credentials files exist
- Check internet connection

### Port already in use
```bash
streamlit run security_auditor/dashboard/live_dashboard.py --server.port 8502
```

## 📊 Dashboard Features

- **Real-time scanning** with progress indicators
- **Interactive charts** (gauges, bar charts, pie charts)
- **Risk scoring** (0-100 scale)
- **Historical reports** selection
- **Component tabs**:
  - Configuration
  - Vulnerabilities
  - Files
  - Email
  - Network

## 🎓 How It Works

### Training Phase
1. Load CSV with precomputed features
2. Train Random Forest classifier
3. Save model to disk

### Detection Phase
1. Extract email subject/body
2. Compute 10 features from content
3. Apply trained model
4. Return phishing probability

### Fallback
- If ML model unavailable, uses rule-based detection
- Keywords: urgent, verify, suspended, etc.

## 📄 License

This project is for educational and security auditing purposes.

## 🤝 Support

For issues or questions:
- Check logs in `logs/` directory
- Review configuration in `config/config.yaml`
- Examine generated reports

---

**Built with**: Python, scikit-learn, Streamlit, VirusTotal, NVD, Gmail API

**ML Model**: Random Forest Classifier (88.9% accuracy)
