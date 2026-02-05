# 🛡️ Guardian - Web Scam Analyzer

A comprehensive web application for analyzing URLs to detect scams, phishing attempts, and security threats using multiple threat intelligence APIs and machine learning.

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://advanced-url.streamlit.app/)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## ✨ Features

### 🔒 Security Analysis
- SSL/TLS certificate validation
- HTTPS enforcement check
- Certificate expiry monitoring

### 🌐 Domain Analysis
- WHOIS information lookup
- Domain age verification
- Registrar details
- Nameserver configuration

### 🚨 Threat Intelligence
- **VirusTotal** - Multi-engine malware scanning
- **Google Safe Browsing** - Real-time threat detection
- **PhishTank** - Phishing database lookup
- **urlscan.io** - Website scanning and analysis
- **AbuseIPDB** - IP reputation checking

### 📊 Risk Assessment
- Comprehensive risk scoring (0-100)
- Detailed warnings and recommendations
- Visual risk meter and gauges
- Batch analysis capabilities

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Bawan2001/URL-Checker.git
cd URL-Checker
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create a `.env` file in the root directory with your API keys:
```env
# VirusTotal API Key (Get from: https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Google Safe Browsing API Key (Get from: https://console.cloud.google.com/)
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key

# AbuseIPDB API Key (Get from: https://www.abuseipdb.com/api)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# URLScan.io API Key (Get from: https://urlscan.io/user/profile/)
URLSCAN_API_KEY=your_urlscan_api_key
```

> **Note:** The application will work with limited features if API keys are not provided.

---

## ▶️ How to Run

### Run the Application
```bash
streamlit run app.py
```

The application will open in your default browser at `http://localhost:8501`

### Alternative: Specify Port
```bash
streamlit run app.py --server.port 8080
```

---

## 📖 Usage Guide

1. **Open the Application** - Navigate to `http://localhost:8501` in your browser
2. **Enter URL** - Type or paste the URL you want to analyze in the input field
3. **Click Analyze** - Press the "🔍 ANALYZE" button
4. **View Results** - Review the comprehensive security analysis including:
   - Risk Score (0-100)
   - Threat Intelligence Reports
   - SSL Certificate Status
   - WHOIS Information
   - URL Feature Analysis

### Analysis Modes
- **Single URL** - Analyze one URL at a time
- **Batch Analysis** - Upload a CSV file with multiple URLs

---

## 📁 Project Structure
```
URL-Checker/
├── app.py              # Main Streamlit application
├── analyzer.py         # URL analysis logic and API integrations
├── requirements.txt    # Python dependencies
├── .env               # Environment variables (API keys)
├── debug_whois.py     # WHOIS debugging utility
├── verify_apis.py     # API verification script
└── README.md          # This file
```

---

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Find and kill the process using port 8501
# Windows:
netstat -ano | findstr :8501
taskkill /PID <PID> /F

# Then run again:
streamlit run app.py
```

### Missing Dependencies
```bash
pip install --upgrade -r requirements.txt
```

### API Rate Limits
If you encounter API rate limit errors, wait a few minutes before trying again or use your own API keys.

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Bawan** - [GitHub](https://github.com/Bawan2001)

---

## ⭐ Support

If you found this project helpful, please give it a star! ⭐