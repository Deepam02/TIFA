"""
Database initialization script with sample threat intelligence data
"""
import sqlite3
import json
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_sample_data():
    """Create sample threat intelligence data for demo purposes."""
    
    sample_threats = [
        {
            "id": "demo_apt_2025_001",
            "title": "APT29 Targeting Government Agencies with New Malware Variant",
            "source": "Cyber Threat Intelligence",
            "link": "https://example.com/apt29-analysis",
            "published_date": (datetime.now() - timedelta(hours=2)).isoformat(),
            "summary": "Advanced Persistent Threat group APT29 has been observed using a new malware variant targeting government agencies. The campaign involves spear-phishing emails with malicious attachments that deploy sophisticated backdoors. Multiple IOCs have been identified including C2 domains and file hashes.",
            "category": "APT",
            "severity": "Critical",
            "iocs": json.dumps({
                "domains": ["evil-c2-server.com", "malicious-update.net", "fake-gov-portal.org"],
                "ips": ["185.220.101.42", "192.0.2.123", "203.0.113.67"],
                "hashes": ["a1b2c3d4e5f6789012345678901234567890abcd", "5d41402abc4b2a76b9719d911017c592"],
                "emails": ["admin@fake-gov-portal.org", "security@malicious-update.net"]
            }),
            "created_at": (datetime.now() - timedelta(hours=2)).isoformat()
        },
        {
            "id": "demo_ransomware_2025_002", 
            "title": "LockBit 4.0 Ransomware Exploiting CVE-2024-12345 in Enterprise Networks",
            "source": "Ransomware Intelligence",
            "link": "https://example.com/lockbit-analysis",
            "published_date": (datetime.now() - timedelta(hours=5)).isoformat(),
            "summary": "A new variant of LockBit ransomware is actively exploiting CVE-2024-12345 vulnerability in enterprise VPN solutions. The attack chain involves initial access through the vulnerability, lateral movement, and deployment of ransomware with double extortion tactics.",
            "category": "Ransomware", 
            "severity": "High",
            "iocs": json.dumps({
                "cves": ["CVE-2024-12345"],
                "domains": ["lockbit-payment.onion", "victim-data-leak.onion"],
                "ips": ["198.51.100.89", "172.16.0.99"],
                "hashes": ["def456789abc012345678901234567890abcdef12", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"],
                "urls": ["https://lockbit-payment.onion/payment", "https://victim-data-leak.onion/leaks"]
            }),
            "created_at": (datetime.now() - timedelta(hours=5)).isoformat()
        },
        {
            "id": "demo_phishing_2025_003",
            "title": "Large-Scale Office 365 Credential Harvesting Campaign",
            "source": "Email Security Intelligence", 
            "link": "https://example.com/phishing-campaign",
            "published_date": (datetime.now() - timedelta(hours=8)).isoformat(),
            "summary": "A sophisticated phishing campaign is targeting Office 365 users with convincing fake login pages. The campaign uses compromised legitimate domains and advanced evasion techniques to bypass email security filters.",
            "category": "Phishing",
            "severity": "Medium",
            "iocs": json.dumps({
                "domains": ["office365-secure-login.com", "ms-update-portal.net", "microsoft-auth.org"],
                "urls": ["https://office365-secure-login.com/auth", "https://ms-update-portal.net/login"],
                "ips": ["203.0.113.45", "198.51.100.78"],
                "emails": ["no-reply@office365-secure-login.com", "security@ms-update-portal.net"]
            }),
            "created_at": (datetime.now() - timedelta(hours=8)).isoformat()
        },
        {
            "id": "demo_malware_2025_004",
            "title": "Banking Trojan Targeting Financial Institutions in Europe",
            "source": "Financial Threat Intelligence",
            "link": "https://example.com/banking-trojan",
            "published_date": (datetime.now() - timedelta(hours=12)).isoformat(),
            "summary": "A new banking trojan variant has been detected targeting financial institutions across Europe. The malware uses web injection techniques to steal credentials and implements advanced anti-analysis capabilities.",
            "category": "Malware",
            "severity": "High", 
            "iocs": json.dumps({
                "domains": ["fake-bank-update.eu", "secure-banking-portal.net"],
                "ips": ["192.0.2.156", "203.0.113.89"],
                "hashes": ["fedcba0987654321098765432109876543210fed", "abcdef1234567890abcdef1234567890abcdef12"],
                "urls": ["https://fake-bank-update.eu/update", "https://secure-banking-portal.net/auth"]
            }),
            "created_at": (datetime.now() - timedelta(hours=12)).isoformat()
        },
        {
            "id": "demo_botnet_2025_005",
            "title": "Emotet Botnet Resurges with New Distribution Methods",
            "source": "Botnet Tracking",
            "link": "https://example.com/emotet-analysis", 
            "published_date": (datetime.now() - timedelta(days=1)).isoformat(),
            "summary": "The Emotet botnet has resurged with new distribution methods including malicious Excel documents and compromised WordPress sites. The botnet is being used to deliver additional payloads including TrickBot and QakBot.",
            "category": "Botnet",
            "severity": "Medium",
            "iocs": json.dumps({
                "domains": ["emotet-c2-backup.com", "bot-command-server.net"],
                "ips": ["172.16.0.123", "10.0.0.45", "192.168.1.99"],
                "hashes": ["123456789abcdef0123456789abcdef012345678", "987654321fedcba0987654321fedcba098765432"],
                "emails": ["invoice@fake-company.com", "payment@suspicious-domain.org"]
            }),
            "created_at": (datetime.now() - timedelta(days=1)).isoformat()
        }
    ]
    
    return sample_threats

def initialize_database():
    """Initialize database with sample data."""
    try:
        # Connect to database
        conn = sqlite3.connect('threat_intel.db')
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                link TEXT,
                published_date TEXT,
                summary TEXT,
                category TEXT,
                severity TEXT,
                iocs TEXT,
                created_at TEXT,
                updated_at TEXT,
                ai_analysis TEXT
            )
        ''')
        
        # Check if data already exists
        cursor.execute("SELECT COUNT(*) FROM threat_intel")
        count = cursor.fetchone()[0]
        
        if count == 0:
            logger.info("Database is empty, inserting sample data...")
            
            # Insert sample data
            sample_threats = create_sample_data()
            
            for threat in sample_threats:
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_intel 
                    (id, title, source, link, published_date, summary, category, severity, iocs, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat['id'],
                    threat['title'], 
                    threat['source'],
                    threat['link'],
                    threat['published_date'],
                    threat['summary'],
                    threat['category'],
                    threat['severity'],
                    threat['iocs'],
                    threat['created_at']
                ))
            
            conn.commit()
            logger.info(f"✅ Inserted {len(sample_threats)} sample threats into database")
        else:
            logger.info(f"Database already contains {count} threats")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize database: {e}")
        return False

if __name__ == "__main__":
    initialize_database()
