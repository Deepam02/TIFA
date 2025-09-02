# 🛡️ Threat Intelligence Feed Aggregator

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/streamlit-1.30+-red.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AI Powered](https://img.shields.io/badge/AI-Gemini%202.5-green.svg)](https://ai.google.dev/)
[![Live Demo](https://img.shields.io/badge/Demo-Live%20Platform-brightgreen.svg)](https://tifa-societe.streamlit.app/#live-threat-intelligence-feed)

> An AI-powered threat intelligence aggregation platform that consolidates and analyzes cyber threat data from multiple online sources using Google Gemini AI.

## 🌐 Live Demo
**👉 [Try TIFA Live Platform](https://tifa-societe.streamlit.app/#live-threat-intelligence-feed)**

Experience the full platform with real-time threat intelligence feeds, AI-powered analysis, and interactive analytics.

![Dashboard Preview](https://github.com/Deepam02/TIFA/blob/master/image.png
)

## 🌟 Features

### 🤖 **AI-Powered Analysis**
- **Google Gemini Integration**: Uses Gemini 2.5 Flash for intelligent threat analysis
- **Smart API Key Rotation**: Automatically switches between multiple API keys
- **Model Fallback System**: 4-tier model hierarchy for maximum reliability
- **Beautiful Summaries**: Structured threat analysis with actionable insights

### 🔍 **Multi-Source Intelligence**
- **15+ Premium Sources**: CISA, SANS, Krebs on Security, Malwarebytes, ThreatPost, and more
- **RSS/Atom Parsing**: Real-time feed aggregation with error handling
- **Background Processing**: Non-blocking threat collection
- **Source Verification**: Validated threat intelligence feeds with health monitoring

### 📊 **IOC Extraction**
- **13+ IOC Types**: IPs, domains, URLs, hashes (MD5/SHA1/SHA256), CVEs, emails, registry keys, and more
- **Advanced Patterns**: Context-aware pattern matching for indicators
- **False Positive Filtering**: Intelligent filtering of common false positives
- **Contextual Analysis**: IOCs linked to threat context and campaigns

### 🎯 **Professional Dashboard**
- **Modern Streamlit UI**: Professional cybersecurity interface with dark theme
- **Real-time Updates**: Live threat feed with auto-refresh capabilities
- **Interactive Analytics**: Advanced charts and visualizations with Plotly
- **Comprehensive Search**: Full-text search, IOC hunting, and bulk analysis

## 🚀 Getting Started

### 🌐 **Try the Live Demo**
Experience TIFA instantly without any setup:
**👉 [Launch TIFA Platform](https://tifa-societe.streamlit.app/#live-threat-intelligence-feed)**

### 📋 **What You Can Do**
- **View Live Threats**: See real-time threat intelligence from 15+ premium sources
- **Search IOCs**: Hunt for specific indicators of compromise across all collected threats
- **Analyze Trends**: Explore interactive analytics and threat patterns
- **Export Data**: Download threat intelligence for your security tools

### 🔧 **For Developers**
If you want to run your own instance or contribute to the project:
- **Clone Repository**: `git clone https://github.com/Deepam02/TIFA.git`
- **Install Dependencies**: `pip install -r requirements.txt`
- **Configure API Keys**: Add your Gemini API keys to `.streamlit/secrets.toml`
- **Run Application**: `streamlit run app.py`

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   RSS/Atom     │───▶│   Feed Collector │───▶│   Database      │
│   Sources       │    │   (core.py)      │    │   (SQLite)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   IOC Extract   │◀───│   Background     │───▶│   AI Analyzer   │
│   (13+ Types)   │    │   Processor      │    │   (Gemini 2.5)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Streamlit UI   │
                       │   (app.py)       │
                       └──────────────────┘
```

## 📁 Project Structure

```
TIFA/
├── 📄 app.py                    # Main Streamlit application
├── 📄 streamlit_app.py          # Cloud deployment entry point
├── 📄 core.py                   # Core business logic & AI integration
├── 📄 database.py               # Database operations & caching
├── 📄 models.py                 # Data models & schemas
├── 📄 config.py                 # Configuration settings
├── 📄 aggregator.py             # Threat intelligence aggregation
├── 📄 ai_analyzer.py            # AI analysis framework
├── 📄 gemini_analyzer.py        # Google Gemini integration
├── 📄 feed_collector.py         # RSS/Atom feed collection
├── 📄 ioc_extractor.py          # IOC pattern extraction
├── 📄 alert_system.py           # Alerting and notifications
├── 📄 requirements.txt          # Python dependencies
├── 📄 README.md                 # This file
├── 📁 .streamlit/               # Streamlit configuration
│   ├── config.toml              # UI configuration
│   └── secrets.toml             # API keys & secrets
└── 📁 src/
    └── utils/                   # Utility scripts
        ├── init_database.py     # Database initialization
        ├── migrate_db.py        # Database migration
        └── fix_schema.py        # Schema fixes
```

## 🤖 AI Integration

### Gemini Model Hierarchy
1. **Gemini 2.5 Flash** - Primary (10 RPM, 250K TPM, 250 RPD)
2. **Gemini 2.5 Flash-Lite** - Secondary (15 RPM, 250K TPM, 1000 RPD)
3. **Gemini 2.0 Flash** - Backup (15 RPM, 1M TPM, 200 RPD)
4. **Gemini 2.0 Flash-Lite** - Fallback (30 RPM, 1M TPM, 200 RPD)

### AI Analysis Output Example
```
🎯 THREAT CLASSIFICATION
Type: Ransomware
Severity: High
Confidence: High

🔍 KEY FINDINGS
• Active ransomware campaign targeting healthcare sector
• New variant of LockBit using advanced evasion techniques
• 127 indicators of compromise identified

⚠️ IMPACT ASSESSMENT
• Affected Systems: Windows networks, domain controllers
• Attack Vector: Phishing emails with malicious attachments
• Potential Damage: Data encryption, system lockout, ransom demands

🛡️ DEFENSIVE ACTIONS
• Immediate: Block identified IOCs in security tools
• Short-term: Update endpoint protection signatures
• Monitoring: Watch for behavioral indicators in network traffic

📊 IOC SUMMARY
• 127 indicators extracted from content
• Primary types: File Hashes, IP Addresses, Domains
```

## 🔧 Configuration

### Environment Variables (Recommended)
```bash
export GEMINI_API_KEY_1="your-first-key"
export GEMINI_API_KEY_2="your-second-key"
export AI_PROVIDER="gemini"
export SERVER_PORT="7860"
```

### Threat Sources Configuration
```python
THREAT_FEEDS = [
    {
        'name': 'US-CERT CISA',
        'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'type': 'rss'
    },
    # ... more sources
]
```

## 🌐 Deployment

### Hugging Face Spaces (Recommended)
1. Fork this repository
2. Create a new Space on Hugging Face
3. Connect your repository
4. Set environment variables for API keys
5. Deploy automatically

### Docker
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 7860
CMD ["python", "app.py"]
```

### Local Development
```bash
python main.py  # Auto-opens browser, localhost only
```

## 📊 Performance

### Capacity with 2 API Keys
- **Total RPM**: 120+ requests per minute
- **Daily Capacity**: 3,500+ requests per day
- **Concurrent Users**: 10+ simultaneous users
- **Response Time**: <2 seconds average

### System Limits
- **Max Feeds**: 20 items per source
- **Auto-refresh**: Every 5 minutes
- **Search Results**: 50 per query
- **Export Limit**: 100 items

## 🛠️ Development

### Adding New Threat Sources
1. Edit `config.py` THREAT_FEEDS
2. Add RSS/Atom feed URL
3. Test with feed validator

### Extending IOC Patterns
1. Update `config.py` IOC_PATTERNS
2. Add regex patterns for new indicator types
3. Test pattern matching

### Customizing AI Prompts
1. Edit `gemini_analyzer.py`
2. Modify prompt templates
3. Test with various threat types

## 🔍 Troubleshooting

### Common Issues

**"AI Analysis unavailable"**
- Check API keys are valid and not expired
- Verify internet connection
- Monitor rate limits in logs

**"No threats found"**
- RSS feeds may be temporarily down
- Check feed URLs are accessible
- Try manual refresh

**Performance Issues**
- Check database size (SQLite has limits)
- Monitor memory usage
- Consider database cleanup

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Google Gemini AI** for powerful threat analysis capabilities
- **Streamlit** for the amazing web interface framework
- **CISA, SANS, Krebs Security** for reliable threat intelligence feeds





*A comprehensive cybersecurity threat intelligence platform designed to help security teams proactively monitor and respond to emerging threats.*
