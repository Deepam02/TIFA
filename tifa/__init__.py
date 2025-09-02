"""
TIFA - Threat Intelligence Feed Aggregator
Enterprise-grade threat intelligence platform with AI-powered analysis.
"""

__version__ = "2.0.0"
__author__ = "TIFA Team"
__description__ = "Elite Threat Intelligence Feed Aggregator with AI Analysis"

# Main exports for easy imports
from .core.models import ThreatIntelItem
from .core.config import Config
from .database.manager import ThreatIntelDatabase
from .analyzers.ai_analyzer import AIAnalyzer
from .analyzers.gemini_analyzer import GeminiAIAnalyzer
from .analyzers.ioc_extractor import IOCExtractor
from .analyzers.correlator import ThreatCorrelator
from .collectors.feed_collector import FeedCollector
from .core.aggregator import ThreatIntelAggregator
from .core.alerts import LiveAlertSystem

__all__ = [
    'ThreatIntelItem',
    'Config', 
    'ThreatIntelDatabase',
    'AIAnalyzer',
    'GeminiAIAnalyzer', 
    'IOCExtractor',
    'ThreatCorrelator',
    'FeedCollector',
    'ThreatIntelAggregator',
    'LiveAlertSystem'
]
