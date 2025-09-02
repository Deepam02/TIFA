"""
AI Analysis module for threat intelligence with Gemini integration
"""

import logging
from typing import Dict, List
from ..core.models import ThreatIntelItem
from ..core.config import Config

# Import based on configuration
try:
    if Config.AI_PROVIDER == "gemini":
        from .gemini_analyzer import GeminiAIAnalyzer
        AI_AVAILABLE = True
    else:
        AI_AVAILABLE = False
        GeminiAIAnalyzer = None
except ImportError:
    AI_AVAILABLE = False
    GeminiAIAnalyzer = None

class AIAnalyzer:
    """AI-powered threat analysis using configurable providers"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.analyzer = None
        
        if AI_AVAILABLE and Config.AI_PROVIDER == "gemini" and GeminiAIAnalyzer:
            try:
                self.analyzer = GeminiAIAnalyzer()
                self.logger.info("✅ Gemini AI Analyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"❌ Failed to initialize Gemini AI: {e}")
                self.analyzer = None
        
        if not self.analyzer:
            self.logger.warning("🔄 Using fallback mock analyzer")
    
    def generate_summary(self, threat_item: ThreatIntelItem) -> str:
        """Generate AI-powered threat summary"""
        if self.analyzer and hasattr(self.analyzer, 'generate_threat_summary'):
            try:
                return self.analyzer.generate_threat_summary(threat_item)
            except Exception as e:
                self.logger.error(f"AI summary generation failed: {e}")
                return self._generate_fallback_summary(threat_item)
        else:
            return self._generate_fallback_summary(threat_item)
    
    def assess_severity(self, threat_item: ThreatIntelItem) -> str:
        """Assess threat severity using AI"""
        content = threat_item.title + " " + threat_item.description
        
        if self.analyzer and hasattr(self.analyzer, 'assess_threat_severity'):
            try:
                return self.analyzer.assess_threat_severity(content)
            except Exception as e:
                self.logger.error(f"AI severity assessment failed: {e}")
                return self._fallback_severity_assessment(content)
        else:
            return self._fallback_severity_assessment(content)
    
    def _generate_fallback_summary(self, threat_item: ThreatIntelItem) -> str:
        """Generate fallback summary when AI is unavailable"""
        ioc_count = sum(len(iocs) for iocs in threat_item.iocs.values())
        ioc_types = [ioc_type.replace('_', ' ').title() for ioc_type, iocs in threat_item.iocs.items() if iocs]
        
        severity = self._fallback_severity_assessment(threat_item.title + " " + threat_item.description)
        threat_type = self._identify_threat_type(threat_item.title + " " + threat_item.description)
        
        return f"""
🎯 THREAT CLASSIFICATION
Type: {threat_type}
Severity: {severity}
Confidence: Medium (Auto-classified)

🔍 KEY FINDINGS
• Threat intelligence from {threat_item.source}
• Published: {threat_item.published}
• Contains {ioc_count} potential indicators of compromise

⚠️ IMPACT ASSESSMENT
• Review full article for detailed impact analysis
• Check organizational exposure to mentioned threats
• Assess relevance to current security posture

🛡️ DEFENSIVE ACTIONS  
• Immediate: Review threat indicators against current logs
• Short-term: Update threat detection signatures
• Monitoring: Implement watch for extracted IOCs

📊 IOC SUMMARY
• {ioc_count} indicators extracted from content
• Types detected: {', '.join(ioc_types[:3]) if ioc_types else 'None specific'}
• AI-powered analysis temporarily unavailable

💡 Note: This is an automated summary. For detailed analysis, please review the full threat report.
"""
    
    def _identify_threat_type(self, content: str) -> str:
        """Identify threat type based on content"""
        content_lower = content.lower()
        
        threat_types = {
            "Malware": ['malware', 'trojan', 'virus', 'worm', 'backdoor'],
            "Phishing": ['phishing', 'email', 'campaign', 'social engineering'],
            "Vulnerability": ['vulnerability', 'cve', 'exploit', 'patch', 'bug'],
            "Ransomware": ['ransomware', 'encryption', 'ransom', 'crypto'],
            "APT": ['apt', 'advanced', 'persistent', 'nation-state'],
            "DDoS": ['ddos', 'denial', 'service', 'botnet'],
            "Data Breach": ['breach', 'leak', 'stolen', 'exposed', 'compromise'],
            "Zero-Day": ['zero-day', 'zero day', '0-day']
        }
        
        for threat_type, keywords in threat_types.items():
            if any(keyword in content_lower for keyword in keywords):
                return threat_type
        
        return "Security Advisory"
    
    def _fallback_severity_assessment(self, content: str) -> str:
        """Fallback severity assessment using keyword analysis"""
        content_lower = content.lower()
        
        # Critical indicators
        critical_keywords = ['zero-day', 'critical vulnerability', 'active exploitation', 'worm', 'nation-state']
        if any(keyword in content_lower for keyword in critical_keywords):
            return "Critical"
        
        # High severity indicators  
        high_keywords = ['ransomware', 'remote code execution', 'privilege escalation', 'data breach']
        if any(keyword in content_lower for keyword in high_keywords):
            return "High"
        
        # Medium severity indicators
        medium_keywords = ['vulnerability', 'exploit', 'malware', 'phishing', 'trojan']
        if any(keyword in content_lower for keyword in medium_keywords):
            return "Medium"
        
        # Default to Medium for cybersecurity content
        return "Medium"
    
    def get_ai_stats(self) -> Dict:
        """Get AI analyzer statistics"""
        if self.analyzer and hasattr(self.analyzer, 'get_stats'):
            try:
                return self.analyzer.get_stats()
            except Exception as e:
                self.logger.error(f"Failed to get AI stats: {e}")
                return {}
        
        return {
            "provider": "fallback",
            "status": "AI unavailable",
            "using_mock": True
        }
