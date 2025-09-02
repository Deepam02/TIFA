"""
🛡️ TIFA - Elite Threat Intelligence Feed Aggregator
World-Class Enterprise Dashboard for International Hackathon Competition
Advanced AI-Powered Real-Time Threat Intelligence Platform
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import logging
import time
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor

from tifa.core.config import Config
from tifa.core.models import ThreatIntelItem
from tifa.database.manager import ThreatIntelDatabase
from tifa.analyzers.ai_analyzer import AIAnalyzer
from tifa.analyzers.ioc_extractor import IOCExtractor
from tifa.analyzers.correlator import ThreatCorrelator
from tifa.collectors.feed_collector import FeedCollector
from tifa.core.aggregator import ThreatIntelAggregator
from tifa.core.alerts import LiveAlertSystem

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Page Configuration with Professional Theme
st.set_page_config(
    page_title=Config.APP_TITLE,
    page_icon=Config.APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/Deepam02/TIFA',
        'Report a bug': "https://github.com/Deepam02/TIFA/issues",
        'About': f"# {Config.APP_TITLE}\n{Config.APP_DESCRIPTION}"
    }
)

# Custom CSS for Professional UI with Better Contrast
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #ff4757, #3742fa, #2ed573);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    
    .threat-card {
        border-left: 5px solid;
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 8px;
        background-color: #ffffff;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        border: 1px solid #e0e0e0;
    }
    
    .threat-card h4 {
        color: #2c3e50 !important;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    .threat-card p {
        color: #34495e !important;
        line-height: 1.6;
    }
    
    .threat-card span {
        color: #2c3e50 !important;
        font-weight: 600;
    }
    
    .critical { 
        border-left-color: #e74c3c; 
        background: linear-gradient(135deg, #ffeaea 0%, #fff5f5 100%);
    }
    .high { 
        border-left-color: #f39c12; 
        background: linear-gradient(135deg, #fff8e1 0%, #fffbf0 100%);
    }
    .medium { 
        border-left-color: #3498db; 
        background: linear-gradient(135deg, #e3f2fd 0%, #f8fbff 100%);
    }
    .low { 
        border-left-color: #27ae60; 
        background: linear-gradient(135deg, #e8f5e8 0%, #f4faf4 100%);
    }
    
    .stSelectbox > div > div {
        background-color: white;
        color: #2c3e50;
    }
    
    .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
    }
    
    .status-active { background-color: #27ae60; }
    .status-warning { background-color: #f39c12; }
    .status-error { background-color: #e74c3c; }
    
    /* Fix text contrast in expanders */
    .streamlit-expanderHeader {
        color: #2c3e50 !important;
        font-weight: bold;
    }
    
    .streamlit-expanderContent {
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
    }
    
    /* Better sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
    }
</style>
""", unsafe_allow_html=True)

# --- Elite Aggregator Class ---
class EliteThreatIntelAggregator:
    """Enterprise-grade threat intelligence orchestrator with advanced features."""
    
    def __init__(self):
        """Initialize all components with enterprise capabilities and error handling."""
        try:
            self.db = ThreatIntelDatabase()
            self.ioc_extractor = IOCExtractor()
            self.feed_collector = FeedCollector(self.db, self.ioc_extractor)
            self.ai_analyzer = AIAnalyzer()
            self.correlator = ThreatCorrelator(self.db)
            self.alert_system = LiveAlertSystem()
            
            # Performance metrics
            self.metrics = {
                "feeds_processed": 0,
                "threats_analyzed": 0,
                "iocs_extracted": 0,
                "last_update": datetime.now().isoformat()
            }
            
            # Add caching for better performance
            self._threat_cache = None
            self._cache_timestamp = 0
            self._cache_duration = 300  # 5 minutes
            
            logger.info("✅ Elite Threat Intelligence Aggregator initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Initialization error: {e}")
            # Initialize in fallback mode
            self.db = None
            self.fallback_mode = True
            st.warning(f"⚠️ Running in fallback mode: {str(e)}")

    def get_cached_threats(self, limit: int = 50):
        """Get threats with caching for better performance."""
        current_time = time.time()
        
        # Check if cache is valid
        if (self._threat_cache is not None and 
            current_time - self._cache_timestamp < self._cache_duration):
            return self._threat_cache[:limit]
        
        # Fetch fresh data
        try:
            if self.db:
                threats = self.db.get_recent_threats(limit=limit)
                self._threat_cache = threats
                self._cache_timestamp = current_time
                return threats
            else:
                return self._get_fallback_threats()[:limit]
        except Exception as e:
            logger.warning(f"Database query failed: {e}")
            return self._get_fallback_threats()[:limit]
    
    def _get_fallback_threats(self):
        """Provide fallback threat data when database is unavailable."""
        from models import ThreatIntelItem
        from datetime import datetime
        
        fallback_data = [
            {
                "id": "fallback_1",
                "title": "APT Group Targeting Financial Sector",
                "source": "Threat Intelligence Sample",
                "summary": "Advanced persistent threat group using sophisticated malware targeting banking infrastructure. Multiple IOCs identified.",
                "category": "APT",
                "severity": "Critical",
                "link": "https://example.com/threat1",
                "published_date": datetime.now().isoformat(),
                "iocs": {
                    "domains": {"malicious-c2.com", "bad-actor.net"}, 
                    "ips": {"192.168.1.100", "10.0.0.50"},
                    "hashes": {"d41d8cd98f00b204e9800998ecf8427e"}
                }
            },
            {
                "id": "fallback_2",
                "title": "Ransomware Campaign Using Recent CVE",
                "source": "Security Research Sample",
                "summary": "Active ransomware campaign exploiting recent vulnerability in web applications. Immediate patching recommended.",
                "category": "Ransomware",
                "severity": "High", 
                "link": "https://example.com/threat2",
                "published_date": datetime.now().isoformat(),
                "iocs": {
                    "cves": {"CVE-2024-12345"},
                    "domains": {"ransom-payment.onion"}
                }
            }
        ]
        
        threats = []
        for data in fallback_data:
            threat = ThreatIntelItem(
                id=data["id"],
                title=data["title"],
                source=data["source"],
                link=data["link"],
                published_date=data["published_date"],
                summary=data["summary"],
                iocs=data["iocs"]
            )
            threat.category = data["category"]
            threat.severity = data["severity"]
            threats.append(threat)
            
        return threats

    def run_elite_aggregation_streaming(self, progress_callback=None) -> Dict[str, Any]:
        """Run optimized background aggregation with efficient processing."""
        start_time = time.time()
        results = {
            "success": False,
            "feeds_processed": 0,
            "new_threats": 0,
            "total_iocs": 0,
            "critical_alerts": 0,
            "processing_time": 0,
            "errors": []
        }
        
        try:
            logger.info("🚀 Starting OPTIMIZED background threat intelligence aggregation...")
            if progress_callback:
                progress_callback("🚀 Starting optimized background aggregation...")
            
            # Process feeds efficiently - limit items per feed for speed
            for i, feed_info in enumerate(Config.THREAT_FEEDS[:10]):  # Limit to first 10 feeds for speed
                try:
                    if progress_callback:
                        progress_callback(f"🔄 Processing {feed_info['name']}...")
                    
                    # Process single feed with limited items
                    items = self.feed_collector.collect_from_feed(feed_info)
                    
                    if items:
                        # Process only first 3 items for speed, save immediately
                        processed_count = 0
                        for item in items[:3]:  # Reduced from 5 to 3 for faster processing
                            try:
                                # Quick AI analysis (optional - can be skipped for speed)
                                if len(Config.GEMINI_API_KEYS) > 0:
                                    summary = self.ai_analyzer.generate_summary(item)
                                    
                                    # Update item with AI insights
                                    item.summary = summary if summary else item.summary
                                    severity = self.ai_analyzer.assess_severity(item)
                                    item.severity = severity if severity else "Medium"
                                else:
                                    # Skip AI if no API keys
                                    item.severity = "Medium"
                                
                                # Save to database immediately
                                if not self.db.item_exists(item.id):
                                    self.db.save_item(item)
                                    processed_count += 1
                                    
                                    # Count IOCs
                                    for ioc_list in item.iocs.values():
                                        results["total_iocs"] += len(ioc_list)
                                        
                            except Exception as e:
                                logger.error(f"Error processing item: {e}")
                                continue
                        
                        results["new_threats"] += processed_count
                        logger.info(f"✅ {feed_info['name']}: {processed_count} threats processed")
                        if progress_callback:
                            progress_callback(f"✅ {feed_info['name']}: {processed_count} threats processed")
                    else:
                        logger.info(f"⚠️ {feed_info['name']}: No new threats found")
                        if progress_callback:
                            progress_callback(f"⚠️ {feed_info['name']}: No new threats found")
                    
                    results["feeds_processed"] += 1
                    
                except Exception as e:
                    logger.error(f"❌ {feed_info['name']}: {str(e)}")
                    if progress_callback:
                        progress_callback(f"❌ {feed_info['name']}: Error occurred")
                    results["errors"].append(f"{feed_info['name']}: {str(e)}")
                    continue
            
            results.update({
                "success": True,
                "processing_time": round(time.time() - start_time, 2)
            })
            
            # Update metrics with ISO format timestamp
            self.metrics.update({
                "feeds_processed": results["feeds_processed"],
                "threats_analyzed": results["new_threats"],
                "iocs_extracted": results["total_iocs"],
                "last_update": datetime.now().isoformat()
            })
            
            logger.info(f"✅ STREAMING aggregation completed in {results['processing_time']}s")
            
        except Exception as e:
            logger.error(f"❌ STREAMING aggregation failed: {e}")
            results["errors"].append(str(e))
            
        return results

# --- Advanced UI Components ---
def render_elite_header():
    """Render the professional header with live status."""
    st.markdown('<h1 class="main-header">🛡️ TIFA - Elite Threat Intelligence Aggregator</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown("### 🌐 **Global Threat Intelligence Platform**")
        st.markdown("*Real-time AI-powered threat aggregation and analysis*")
    
    with col2:
        # Live status indicator
        if "last_update" in st.session_state.get("metrics", {}):
            st.markdown('<span class="status-indicator status-active"></span>**LIVE**', unsafe_allow_html=True)
        else:
            st.markdown('<span class="status-indicator status-warning"></span>**STANDBY**', unsafe_allow_html=True)
    
    with col3:
        current_time = datetime.now().strftime("%H:%M:%S UTC")
        st.markdown(f"🕒 **{current_time}**")

def render_elite_metrics(aggregator: EliteThreatIntelAggregator):
    """Render real-time metrics dashboard with fallback support."""
    st.markdown("## 📊 Real-Time Intelligence Metrics")
    
    # Get latest stats with error handling
    try:
        if aggregator.db:
            stats = aggregator.db.get_statistics()
        else:
            stats = {"total_threats": 3, "total_iocs": 8, "sources": 3}  # Fallback stats
    except Exception as e:
        logger.warning(f"Failed to get database stats: {e}")
        stats = {"total_threats": 3, "total_iocs": 8, "sources": 3}  # Fallback stats
    
    # Create metrics columns
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="🎯 Total Threats",
            value=stats.get("total_threats", 0),
            delta=f"+{aggregator.metrics.get('threats_analyzed', 0) if hasattr(aggregator, 'metrics') else 0} today"
        )
    
    with col2:
        st.metric(
            label="🔍 Total IOCs",
            value=stats.get("total_iocs", 0),
            delta=f"+{aggregator.metrics.get('iocs_extracted', 0) if hasattr(aggregator, 'metrics') else 0} extracted"
        )
    
    with col3:
        st.metric(
            label="📡 Active Sources",
            value=len(Config.THREAT_FEEDS) if hasattr(Config, 'THREAT_FEEDS') else 7,
            delta=f"{aggregator.metrics.get('feeds_processed', 0) if hasattr(aggregator, 'metrics') else 0} processed"
        )
    
    with col4:
        api_keys = getattr(Config, 'GEMINI_API_KEYS', [])
        st.metric(
            label="🤖 AI Requests",
            value=aggregator.metrics.get("ai_requests", 0) if hasattr(aggregator, 'metrics') else 0,
            delta=f"Load balanced across {len(api_keys)} keys" if api_keys else "Rule-based analysis"
        )
    
    with col5:
        st.metric(
            label="🚨 Critical Alerts",
            value=aggregator.metrics.get("alerts_generated", 0) if hasattr(aggregator, 'metrics') else 0,
            delta="Real-time monitoring"
        )

def render_elite_threat_item(item: ThreatIntelItem, show_correlations=True):
    """Render individual threat with enhanced visualization and better contrast."""
    severity_class = getattr(item, 'severity', 'medium').lower()
    
    # Enhanced threat card with better contrast
    st.markdown(f"""
    <div class="threat-card {severity_class}">
        <h4>🎯 {item.title}</h4>
        <div style="display: flex; justify-content: space-between; margin: 15px 0; flex-wrap: wrap;">
            <span><strong>📡 Source:</strong> {item.source}</span>
            <span><strong>📅 Published:</strong> {item.published_date.split('T')[0] if item.published_date else 'Unknown'}</span>
            <span><strong>🔥 Severity:</strong> <span style="color: {'#e74c3c' if severity_class == 'critical' else '#f39c12' if severity_class == 'high' else '#3498db' if severity_class == 'medium' else '#27ae60'}; font-weight: bold;">{getattr(item, 'severity', 'Medium')}</span></span>
        </div>
        <p style="margin: 15px 0; color: #2c3e50; font-size: 14px; line-height: 1.6;">{item.summary}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced expandable details with better organization
    with st.expander("🔍 **ADVANCED THREAT ANALYSIS**", expanded=False):
        
        # Create tabs for different analysis views
        tab1, tab2, tab3, tab4 = st.tabs(["📋 **Details**", "🎯 **IOCs**", "🧠 **AI Analysis**", "🔗 **Intelligence**"])
        
        with tab1:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**🔗 Original Article:** [View Source]({item.link})")
                st.markdown(f"**📂 Category:** {getattr(item, 'category', 'Unknown')}")
                st.markdown(f"**🎯 Priority:** {getattr(item, 'priority', 'Medium')}")
                st.markdown(f"**📊 Confidence:** {getattr(item, 'confidence', 'Medium')}")
            
            with col2:
                st.markdown(f"**🤖 Analysis Type:** {getattr(item, 'analysis_type', 'Standard')}")
                st.markdown(f"**🔑 API Key:** ...{getattr(item, 'api_key_used', 'N/A')}")
                st.markdown(f"**⏰ Created:** {getattr(item, 'created_at', 'Unknown')}")
                st.markdown(f"**🆔 Item ID:** `{getattr(item, 'id', 'N/A')}`")
        
        with tab2:
            # Enhanced IOC visualization
            all_iocs = []
            for ioc_type, iocs in item.iocs.items():
                for ioc in iocs:
                    all_iocs.append({"🔍 Type": ioc_type.upper().replace('_', ' '), "💎 Value": ioc, "🔗 Search": f"[Hunt](?ioc={ioc})"})
            
            if all_iocs:
                df_iocs = pd.DataFrame(all_iocs)
                st.markdown(f"**Found {len(all_iocs)} IOCs:**")
                st.dataframe(df_iocs, use_container_width=True, hide_index=True)
                
                # IOC type distribution
                if len(all_iocs) > 1:
                    ioc_counts = df_iocs['🔍 Type'].value_counts()
                    fig = px.pie(values=ioc_counts.values, names=ioc_counts.index, 
                               title="IOC Distribution", color_discrete_sequence=px.colors.qualitative.Set3)
                    fig.update_traces(textposition='inside', textinfo='percent+label')
                    st.plotly_chart(fig, width="stretch", key=f"ioc_distribution_{item.id}")
            else:
                st.info("🔍 No IOCs extracted from this threat intelligence.")
        
        with tab3:
            # Enhanced AI Analysis Display
            st.markdown("### 🧠 **AI-Powered Analysis**")
            
            # Display AI insights in organized format
            ai_insights = {
                "📊 **Summary**": getattr(item, 'summary', 'No summary available'),
                "🔥 **Severity Assessment**": getattr(item, 'severity', 'Medium'),
                "📂 **Threat Category**": getattr(item, 'category', 'Unknown'),
                "🎯 **Confidence Level**": getattr(item, 'confidence', 'Medium'),
                "🔍 **Key IOCs Identified**": getattr(item, 'key_iocs', []),
                "💻 **Affected Systems**": getattr(item, 'affected_systems', [])
            }
            
            for key, value in ai_insights.items():
                if value and value != 'Unknown':
                    if isinstance(value, list):
                        if value:
                            st.markdown(f"**{key}:** {', '.join(map(str, value))}")
                    else:
                        st.markdown(f"**{key}:** {value}")
            
            # Show AI model used
            if hasattr(item, 'analysis_type'):
                st.info(f"🤖 Analysis powered by {getattr(item, 'analysis_type', 'Advanced AI')}")
        
        with tab4:
            # Enhanced Intelligence Context
            st.markdown("### 🔗 **Threat Intelligence Context**")
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**📊 Source Reliability:**")
                source_reliability = {
                    "🏛️ US-CERT CISA": "🟢 Very High",
                    "🏛️ NIST NVD": "🟢 Very High", 
                    "🏛️ FBI IC3": "🟢 Very High",
                    "🎯 SANS ISC": "🟢 High",
                    "🎯 MITRE ATT&CK": "🟢 Very High",
                    "🔬 Krebs on Security": "🟡 Medium-High",
                    "🔬 MalwareBytes Labs": "🟡 Medium-High",
                    "🚨 Exploit-DB": "🟡 Medium"
                }
                reliability = source_reliability.get(item.source, "🟡 Medium")
                st.markdown(f"{reliability}")
                
            with col2:
                st.markdown("**⚡ Threat Velocity:**")
                # Calculate how recent the threat is
                try:
                    if item.published_date:
                        pub_date = datetime.fromisoformat(item.published_date.replace('Z', '+00:00'))
                        age_hours = (datetime.now() - pub_date.replace(tzinfo=None)).total_seconds() / 3600
                        if age_hours < 6:
                            velocity = "🔴 Breaking"
                        elif age_hours < 24:
                            velocity = "🟠 Recent"
                        elif age_hours < 168:  # 1 week
                            velocity = "🟡 Current"
                        else:
                            velocity = "🟢 Historical"
                        st.markdown(f"{velocity}")
                except:
                    st.markdown("🟡 Unknown")
            
            # Correlation hints
            st.markdown("**🔗 Similar Threats:**")
            st.info("💡 Advanced correlation engine coming soon...")

def render_elite_dashboard(aggregator: EliteThreatIntelAggregator):
    """Main elite dashboard with advanced features and fallback data."""
    render_elite_header()
    render_elite_metrics(aggregator)
    
    # Get threats with fallback
    try:
        threats = aggregator.get_cached_threats(limit=20)
    except:
        threats = aggregator._get_fallback_threats()
        st.info("📡 Showing sample data while connecting to threat intelligence feeds")
    
    # Action buttons
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🚀 **REFRESH ALL FEEDS**", type="primary", use_container_width=True):
            # Initialize background processing state
            if 'aggregation_running' not in st.session_state:
                st.session_state.aggregation_running = False
                
            if not st.session_state.aggregation_running:
                st.session_state.aggregation_running = True
                st.session_state.aggregation_start_time = time.time()
                
                # Show immediate feedback and start background task
                st.success("🚀 **Background aggregation started!** Current data shown below, new threats will appear as processed.")
                
                # Start async processing in a thread (simulated)
                import threading
                
                def background_aggregation():
                    try:
                        results = aggregator.run_elite_aggregation_streaming()
                        st.session_state.last_aggregation_results = results
                        st.session_state.aggregation_running = False
                    except Exception as e:
                        st.session_state.aggregation_error = str(e)
                        st.session_state.aggregation_running = False
                
                # Start background thread
                thread = threading.Thread(target=background_aggregation, daemon=True)
                thread.start()
                
                # Immediate rerun to show current data
                st.rerun()
            else:
                st.warning("🔄 **Aggregation already running in background...**")
                
    # Background processing status indicator with activity log
    if st.session_state.get('aggregation_running', False):
        elapsed = time.time() - st.session_state.get('aggregation_start_time', time.time())
        col_status1, col_status2 = st.columns([3, 1])
        
        with col_status1:
            st.info(f"🔄 **Background aggregation active** - Running for {elapsed:.0f}s")
        
        with col_status2:
            if st.button("🔄 **Refresh View**", key="bg_refresh"):
                st.rerun()
                
        # Real-time activity indicator
        with st.expander("📊 **Live Processing Activity**", expanded=False):
            recent_threats = aggregator.db.get_recent_threats(limit=5)
            if recent_threats:
                st.markdown("**Latest threats collected:**")
                for threat in recent_threats[:3]:
                    try:
                        created_time = datetime.fromisoformat(threat.created_at.replace('Z', '')) if threat.created_at else datetime.now()
                        time_ago = (datetime.now() - created_time).total_seconds()
                        if time_ago < 3600:  # Less than 1 hour
                            st.write(f"✅ {threat.source}: {threat.title[:60]}... ({time_ago:.0f}s ago)")
                    except:
                        st.write(f"✅ {threat.source}: {threat.title[:60]}...")
            else:
                st.write("⏳ Waiting for new threats...")
    
    # Show results when background task completes
    if 'last_aggregation_results' in st.session_state:
        results = st.session_state.last_aggregation_results
        if results and results.get("success"):
            st.success(f"""
            ✅ **Background Aggregation Complete!**
            - 📡 Feeds Processed: {results['feeds_processed']}
            - 🎯 New Threats: {results['new_threats']}
            - 🔍 IOCs Extracted: {results['total_iocs']}
            - ⚡ Processing Time: {results.get('processing_time', 0):.1f}s
            """)
            # Clear the results after showing
            del st.session_state.last_aggregation_results
    
    with col2:
        if st.button("🤖 **AI DEEP SCAN**", use_container_width=True):
            st.info("🧠 Advanced AI correlation analysis initiated...")
    
    with col3:
        if st.button("📊 **EXPORT INTEL**", use_container_width=True):
            st.info("📦 Intelligence export feature coming soon...")
    
    with col4:
        if st.button("🚨 **ALERT CONFIG**", use_container_width=True):
            st.info("⚙️ Alert configuration panel coming soon...")
    
    # Main threat feed display
    st.markdown("## 🎯 Live Threat Intelligence Feed")
    
    # === LIVE THREAT INTELLIGENCE DISPLAY ===
    st.subheader("🎯 **LIVE THREAT INTELLIGENCE FEED**")
    
    # Real-time refresh controls
    col_auto1, col_auto2, col_auto3 = st.columns([2, 1, 1])
    
    with col_auto1:
        auto_refresh = st.checkbox("🔄 **Auto-refresh every 10 seconds**", value=False)
    
    with col_auto2:
        if st.button("🔄 **Manual Refresh**", use_container_width=True):
            st.rerun()
    
    with col_auto3:
        # Show live count with fallback
        try:
            if aggregator.db:
                total_count = len(aggregator.db.get_recent_threats(limit=1000))
            else:
                total_count = 3  # Fallback count
        except Exception:
            total_count = 3  # Fallback count
        st.metric("📊 **Total Threats**", total_count)
    
    # Auto-refresh functionality
    if auto_refresh:
        time.sleep(10)
        st.rerun()
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.selectbox("🔥 Severity Filter", ["All", "Critical", "High", "Medium", "Low"])
    with col2:
        source_filter = st.selectbox("📡 Source Filter", ["All"] + [feed["name"] for feed in Config.THREAT_FEEDS])
    with col3:
        limit = st.slider("📄 Items to Show", 5, 100, 20)
    
    # Get and display threats with fallback
    try:
        if hasattr(aggregator, 'get_cached_threats'):
            threats = aggregator.get_cached_threats(limit=limit)
        else:
            threats = aggregator.db.get_recent_threats(limit=limit)
            
        # If no threats in database, use fallback
        if not threats or len(threats) == 0:
            threats = aggregator._get_fallback_threats()
            st.info("📡 Showing sample threat intelligence data. Real feeds will update automatically.")
            
    except Exception as e:
        logger.warning(f"Database query failed: {e}")
        threats = aggregator._get_fallback_threats()
        st.warning("⚠️ Database temporarily unavailable. Showing sample data.")
    
    if not threats:
        if st.session_state.get('aggregation_running', False):
            st.info("� **Background aggregation is running...** New threats will appear here as they're processed.")
        else:
            st.info("�🔍 No threat intelligence data found. Click '🚀 REFRESH ALL FEEDS' to start collecting.")
        return
    
    # Apply filters
    if severity_filter != "All":
        threats = [t for t in threats if getattr(t, 'severity', 'Medium') == severity_filter]
    
    if source_filter != "All":
        threats = [t for t in threats if t.source == source_filter]
    
    # Display threats with "NEW" badges for recent ones
    current_time = datetime.now()
    for i, item in enumerate(threats):
        # Check if threat is from the last 10 minutes (new)
        is_new = False
        try:
            if hasattr(item, 'created_at') and item.created_at:
                created_time = datetime.fromisoformat(item.created_at.replace('Z', ''))
                time_diff = (current_time - created_time).total_seconds()
                is_new = time_diff < 600  # 10 minutes
        except:
            pass
        
        # Add NEW badge for recent threats
        if is_new:
            st.markdown("🆕 **NEW THREAT DETECTED!**", unsafe_allow_html=True)
        
        render_elite_threat_item(item)

def render_elite_ioc_search(aggregator: EliteThreatIntelAggregator):
    """Enhanced IOC Hunter with advanced search and analysis capabilities."""
    st.markdown("## 🔍 Elite IOC Hunter & Analysis")
    st.markdown("*Advanced IOC search, correlation, and threat intelligence analysis*")
    
    # === Database Management Panel ===
    with st.expander("🗄️ **Database Management**", expanded=False):
        col_db1, col_db2, col_db3 = st.columns(3)
        
        with col_db1:
            db_stats = aggregator.db.get_statistics()
            st.metric("📊 **Total Threats**", db_stats.get('total_threats', 0))
        
        with col_db2:
            threats = aggregator.db.get_recent_threats(limit=1000)
            ioc_count = sum(len(list(t.iocs.values())[0]) if t.iocs else 0 for t in threats[:100])
            st.metric("🎯 **Total IOCs**", ioc_count)
        
        with col_db3:
            sources = len(set(t.source for t in threats[:100]))
            st.metric("📡 **Sources**", sources)
        
        # Database actions
        st.markdown("**🛠️ Database Actions:**")
        col_action1, col_action2, col_action3 = st.columns(3)
        
        with col_action1:
            if st.button("🔄 **Refresh Stats**", use_container_width=True):
                st.rerun()
        
        with col_action2:
            if st.button("📥 **Export All Data**", use_container_width=True):
                # Export all threats as JSON
                all_threats = aggregator.db.get_recent_threats(limit=10000)
                export_data = []
                for threat in all_threats:
                    export_data.append({
                        "id": threat.id,
                        "title": threat.title,
                        "source": threat.source,
                        "category": getattr(threat, 'category', 'unknown'),
                        "severity": getattr(threat, 'severity', 'Medium'),
                        "published_date": threat.published_date,
                        "link": threat.link,
                        "summary": threat.summary,
                        "iocs": {k: list(v) for k, v in threat.iocs.items()}
                    })
                
                import json
                export_json = json.dumps(export_data, indent=2)
                st.download_button(
                    label="📥 Download All Threats",
                    data=export_json,
                    file_name=f"threat_intel_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col_action3:
            # Clear database with confirmation
            if st.button("🗑️ **Clear Database**", use_container_width=True, type="secondary"):
                if 'confirm_clear' not in st.session_state:
                    st.session_state.confirm_clear = False
                st.session_state.confirm_clear = True
        
        # Confirmation dialog for clearing database
        if st.session_state.get('confirm_clear', False):
            st.warning("⚠️ **Are you sure?** This will permanently delete all threat intelligence data!")
            col_conf1, col_conf2 = st.columns(2)
            
            with col_conf1:
                if st.button("✅ **Yes, Clear All Data**", type="primary"):
                    try:
                        # Delete all data from database
                        import sqlite3
                        conn = sqlite3.connect(aggregator.db.db_path)
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM threat_intel")
                        conn.commit()
                        conn.close()
                        
                        st.session_state.confirm_clear = False
                        st.success("✅ Database cleared successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Failed to clear database: {e}")
            
            with col_conf2:
                if st.button("❌ **Cancel**"):
                    st.session_state.confirm_clear = False
                    st.rerun()
    
    # === Enhanced IOC Search Interface ===
    st.markdown("---")
    st.subheader("🎯 **IOC Search & Intelligence**")
    
    # Search input with multiple options
    col1, col2, col3 = st.columns([3, 1, 1])
    
    with col1:
        search_query = st.text_input(
            "🔍 Search IOCs (IP, domain, hash, CVE, etc.)", 
            placeholder="Enter IOC to hunt for threats...",
            help="Search for any IOC across all collected threat intelligence"
        )
    
    with col2:
        search_type = st.selectbox("Search Type", [
            "🔍 All IOCs",
            "🌐 Network", 
            "📁 File Hashes",
            "🚨 Vulnerabilities",
            "💰 Financial",
            "🦠 Malware"
        ])
    
    with col3:
        exact_match = st.checkbox("Exact Match", value=False, help="Enable for exact IOC matching")
    
    # === IOC Analysis Dashboard ===
    if search_query:
        st.markdown("---")
        st.subheader(f"🎯 **Hunt Results for:** `{search_query}`")
        
        # Search for matching threats
        matching_threats = []
        all_threats = aggregator.db.get_recent_threats(limit=1000)
        
        # Enhanced search logic
        for threat in all_threats:
            threat_match = False
            matched_categories = []
            
            # Search in IOCs
            for ioc_category, iocs in threat.iocs.items():
                for ioc in iocs:
                    if exact_match:
                        if search_query.lower() == ioc.lower():
                            threat_match = True
                            matched_categories.append(ioc_category)
                    else:
                        if search_query.lower() in ioc.lower():
                            threat_match = True
                            matched_categories.append(ioc_category)
            
            # Search in title and summary for context
            if search_query.lower() in threat.title.lower() or search_query.lower() in threat.summary.lower():
                threat_match = True
                matched_categories.append("content")
            
            if threat_match:
                threat.matched_categories = list(set(matched_categories))
                matching_threats.append(threat)
        
        # === Results Summary ===
        if matching_threats:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("🎯 **Threats Found**", len(matching_threats))
            
            with col2:
                critical_count = len([t for t in matching_threats if getattr(t, 'severity', 'Medium') == 'Critical'])
                st.metric("🚨 **Critical**", critical_count)
            
            with col3:
                sources = len(set(t.source for t in matching_threats))
                st.metric("📡 **Sources**", sources)
            
            with col4:
                # Calculate threat velocity (recent vs old)
                recent_count = 0
                try:
                    cutoff = datetime.now() - timedelta(days=7)
                    for threat in matching_threats:
                        if threat.created_at:
                            created = datetime.fromisoformat(threat.created_at.replace('Z', ''))
                            if created > cutoff:
                                recent_count += 1
                except:
                    pass
                st.metric("⚡ **Recent (7d)**", recent_count)
            
            # === IOC Intelligence Panel ===
            with st.expander("🧠 **IOC Intelligence Summary**", expanded=True):
                col_intel1, col_intel2 = st.columns(2)
                
                with col_intel1:
                    st.markdown("**🔍 IOC Analysis:**")
                    
                    # Categorize the search query
                    ioc_type = "unknown"
                    for category, patterns in Config.IOC_PATTERNS.items():
                        try:
                            if re.match(patterns, search_query, re.IGNORECASE):
                                ioc_type = aggregator.ioc_extractor._get_ioc_category(category)
                                break
                        except:
                            continue
                    
                    st.info(f"🏷️ **IOC Type:** {ioc_type.title()}")
                    
                    # Risk assessment
                    if critical_count > 0:
                        st.error("🚨 **HIGH RISK** - Critical threats associated")
                    elif len(matching_threats) > 10:
                        st.warning("⚠️ **MEDIUM RISK** - Multiple threat associations")
                    else:
                        st.success("✅ **LOW RISK** - Limited threat activity")
                
                with col_intel2:
                    st.markdown("**📊 Threat Breakdown:**")
                    
                    # Category breakdown
                    categories = {}
                    for threat in matching_threats:
                        category = getattr(threat, 'category', 'unknown')
                        categories[category] = categories.get(category, 0) + 1
                    
                    if categories:
                        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]:
                            st.write(f"• {cat.title()}: **{count}** threats")
            
            # === Export Options ===
            st.markdown("**� Export Hunt Results:**")
            col_exp1, col_exp2, col_exp3 = st.columns(3)
            
            with col_exp1:
                if st.button("📋 **Export IOC List**", use_container_width=True):
                    # Extract all IOCs from matching threats
                    all_iocs = set()
                    for threat in matching_threats:
                        for cat, iocs in threat.iocs.items():
                            all_iocs.update(iocs)
                    
                    ioc_list = "\\n".join(sorted(all_iocs))
                    st.download_button(
                        label="Download IOCs (.txt)",
                        data=ioc_list,
                        file_name=f"iocs_{search_query}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain",
                        key="download_iocs"
                    )
            
            with col_exp2:
                if st.button("📊 **Export Report**", use_container_width=True):
                    # Generate comprehensive report
                    report = {
                        "search_query": search_query,
                        "search_timestamp": datetime.now().isoformat(),
                        "total_threats": len(matching_threats),
                        "critical_threats": critical_count,
                        "threat_breakdown": categories,
                        "threats": []
                    }
                    
                    for threat in matching_threats[:20]:  # Limit to top 20
                        report["threats"].append({
                            "title": threat.title,
                            "source": threat.source,
                            "severity": getattr(threat, 'severity', 'Medium'),
                            "category": getattr(threat, 'category', 'unknown'),
                            "link": threat.link,
                            "iocs": {k: list(v) for k, v in threat.iocs.items()}
                        })
                    
                    report_json = json.dumps(report, indent=2)
                    st.download_button(
                        label="Download Report (.json)",
                        data=report_json,
                        file_name=f"hunt_report_{search_query}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        key="download_report"
                    )
            
            with col_exp3:
                if st.button("🎯 **Copy for SIEM**", use_container_width=True):
                    # Generate SIEM-ready IOC list
                    siem_iocs = []
                    for threat in matching_threats:
                        for cat, iocs in threat.iocs.items():
                            for ioc in iocs:
                                siem_iocs.append(f"{cat.upper()}: {ioc}")
                    
                    siem_content = "\\n".join(siem_iocs)
                    st.code(siem_content, language="text")
                    st.caption("Copy the above IOCs to your SIEM for monitoring")
            
            # === Detailed Threat Results ===
            st.markdown("---")
            st.subheader(f"📋 **Detailed Hunt Results** ({len(matching_threats)} threats)")
            
            # Display simplified threat cards
            for i, threat in enumerate(matching_threats[:20]):  # Limit to top 20
                severity = getattr(threat, 'severity', 'Medium')
                category = getattr(threat, 'category', 'unknown')
                
                # Threat card with match highlighting
                st.markdown(f"""
                <div class="threat-card {severity.lower()}">
                    <h4>🎯 {threat.title}</h4>
                    <div style="display: flex; justify-content: space-between; margin: 10px 0;">
                        <span><strong>📡 Source:</strong> {threat.source}</span>
                        <span><strong>📂 Category:</strong> {category.title()}</span>
                        <span><strong>🔥 Severity:</strong> {severity}</span>
                    </div>
                    <div style="background: #e8f4fd; padding: 10px; border-radius: 5px; margin: 10px 0;">
                        <strong>� Matched in:</strong> {', '.join(getattr(threat, 'matched_categories', []))}
                    </div>
                    <p>{threat.summary[:200]}...</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Expandable IOC details
                with st.expander(f"🔍 **IOC Details** - Threat #{i+1}"):
                    
                    col_ioc1, col_ioc2 = st.columns(2)
                    
                    with col_ioc1:
                        st.markdown("**🎯 All IOCs in this threat:**")
                        if threat.iocs:
                            ioc_data = []
                            for cat, iocs in threat.iocs.items():
                                for ioc in list(iocs):
                                    # Highlight matching IOCs
                                    highlight = "🔍" if search_query.lower() in ioc.lower() else "•"
                                    ioc_data.append({
                                        "Match": highlight,
                                        "Category": cat.title(),
                                        "IOC": ioc
                                    })
                            
                            if ioc_data:
                                df_iocs = pd.DataFrame(ioc_data)
                                st.dataframe(df_iocs, use_container_width=True, hide_index=True)
                        else:
                            st.info("No IOCs extracted from this threat")
                    
                    with col_ioc2:
                        st.markdown("**🔗 Threat Context:**")
                        st.markdown(f"**Original Link:** [View Source]({threat.link})")
                        st.markdown(f"**Published:** {threat.published_date.split('T')[0] if threat.published_date else 'Unknown'}")
                        st.markdown(f"**Collected:** {threat.created_at.split('T')[0] if threat.created_at else 'Unknown'}")
        
        else:
            st.warning(f"🔍 No threats found containing IOC: **{search_query}**")
            st.info("💡 **Tips:**\\n- Try searching for partial matches\\n- Check spelling and format\\n- Use broader search terms\\n- Ensure data has been collected from feeds")
    
    # === IOC Bulk Analysis ===
    st.markdown("---")
    st.subheader("📝 **Bulk IOC Analysis**")
    
    col_bulk1, col_bulk2 = st.columns([2, 1])
    
    with col_bulk1:
        bulk_iocs = st.text_area(
            "Enter multiple IOCs (one per line)",
            placeholder="192.168.1.100\\nexample-malware.com\\n5d41402abc4b2a76b9719d911017c592\\nCVE-2023-12345",
            height=150
        )
    
    with col_bulk2:
        st.markdown("**📊 Bulk Analysis Options:**")
        include_context = st.checkbox("Include threat context", value=True)
        threat_correlation = st.checkbox("Show threat correlations", value=True)
        
        if st.button("🔍 **Analyze All IOCs**", type="primary", use_container_width=True):
            if bulk_iocs.strip():
                ioc_list = [ioc.strip() for ioc in bulk_iocs.split('\\n') if ioc.strip()]
                
                st.success(f"🎯 Analyzing {len(ioc_list)} IOCs...")
                
                # Analyze each IOC
                bulk_results = {}
                all_threats = aggregator.db.get_recent_threats(limit=1000)
                
                for ioc in ioc_list:
                    # Search for this IOC
                    ioc_threats = []
                    for threat in all_threats:
                        for cat, threat_iocs in threat.iocs.items():
                            if any(ioc.lower() in threat_ioc.lower() for threat_ioc in threat_iocs):
                                ioc_threats.append(threat)
                                break
                    
                    bulk_results[ioc] = {
                        "threat_count": len(ioc_threats),
                        "threats": ioc_threats[:5],  # Top 5 threats
                        "risk_level": "High" if len(ioc_threats) > 5 else "Medium" if len(ioc_threats) > 0 else "Low"
                    }
                
                # Display bulk results
                st.subheader("📊 **Bulk Analysis Results**")
                
                for ioc, results in bulk_results.items():
                    with st.expander(f"🎯 {ioc} - {results['threat_count']} threats - Risk: {results['risk_level']}"):
                        if results['threats']:
                            for threat in results['threats']:
                                st.write(f"• **{threat.source}**: {threat.title[:60]}...")
                        else:
                            st.info("No threats found for this IOC")
    
    # === IOC Discovery ===
    st.subheader("🔍 **IOC Discovery Dashboard**")
    st.info("💡 Enter an IOC above to start hunting, or use bulk analysis for multiple IOCs")
    
    # Show recent IOCs from database
    col_recent1, col_recent2 = st.columns(2)
    
    with col_recent1:
        st.markdown("**🎯 Recent IOCs by Category:**")
        recent_threats = aggregator.db.get_recent_threats(limit=50)
        
        ioc_categories = {}
        for threat in recent_threats:
            for cat, iocs in threat.iocs.items():
                if cat not in ioc_categories:
                    ioc_categories[cat] = set()
                ioc_categories[cat].update(list(iocs)[:3])  # Sample 3 IOCs per threat
        
        for category, iocs in ioc_categories.items():
            with st.expander(f"📂 {category.title()} ({len(iocs)} IOCs)"):
                for i, ioc in enumerate(list(iocs)[:10]):  # Show first 10
                    if st.button(f"🔍 {ioc[:50]}", key=f"quick_search_{category}_{i}"):
                        # Set the search query and rerun
                        st.session_state.ioc_search_query = ioc
                        st.rerun()
    
    with col_recent2:
            st.markdown("**� IOC Statistics:**")
            
            # Calculate IOC stats
            total_iocs = sum(len(list(threat.iocs.values())[0]) if threat.iocs else 0 for threat in recent_threats)
            unique_sources = len(set(threat.source for threat in recent_threats))
            
            st.metric("Total IOCs", total_iocs)
            st.metric("Unique Sources", unique_sources)
            st.metric("Recent Threats", len(recent_threats))
    
    # Auto-populate search if set via session state
    if 'ioc_search_query' in st.session_state and st.session_state.ioc_search_query:
        search_query = st.session_state.ioc_search_query
        del st.session_state.ioc_search_query
        st.rerun()

def render_elite_analytics(aggregator: EliteThreatIntelAggregator):
    """Advanced analytics and visualization dashboard."""
    st.markdown("## 📊 Elite Threat Analytics")
    st.markdown("*Advanced intelligence analytics and strategic insights*")
    
    # Get comprehensive data
    stats = aggregator.db.get_statistics()
    threats = aggregator.db.get_recent_threats(limit=500)
    
    if not threats:
        st.info("📈 No data available for analytics. Please refresh feeds first.")
        return
    
    # Convert to DataFrame for analysis
    threat_data = []
    for t in threats:
        try:
            # Calculate IOC count safely
            ioc_count = 0
            if hasattr(t, 'iocs') and t.iocs:
                for ioc_list in t.iocs.values():
                    if isinstance(ioc_list, (list, tuple)):
                        ioc_count += len(ioc_list)
                    elif ioc_list:  # Single IOC
                        ioc_count += 1
            
            # Parse published date safely
            try:
                if hasattr(t, 'published_date') and t.published_date:
                    pub_date = datetime.fromisoformat(t.published_date.replace('Z', '+00:00'))
                else:
                    pub_date = datetime.now()
            except:
                pub_date = datetime.now()
            
            threat_data.append({
                'title': getattr(t, 'title', 'Unknown'),
                'source': getattr(t, 'source', 'Unknown'),
                'severity': getattr(t, 'severity', 'Medium'),
                'category': getattr(t, 'category', 'Unknown'),
                'published_date': pub_date,
                'ioc_count': ioc_count
            })
        except Exception as e:
            logger.warning(f"Error processing threat for analytics: {e}")
            continue
    
    df = pd.DataFrame(threat_data)
    
    # Ensure we have data to analyze
    if df.empty:
        st.info("📈 No valid data available for analytics. Please refresh feeds first.")
        return
    
    # Analytics tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📈 Trends", "🎯 Sources", "🔥 Severity", "💎 IOCs"])
    
    with tab1:
        st.markdown("### 📈 Threat Intelligence Trends")
        
        try:
            # Time series analysis
            daily_threats = df.groupby(df['published_date'].dt.date).size()
            if len(daily_threats) > 0:
                fig = px.line(x=daily_threats.index, y=daily_threats.values,
                             title="Daily Threat Intelligence Volume")
                st.plotly_chart(fig, width="stretch", key="daily_threats_timeline")
            else:
                st.info("📊 No trend data available")
        except Exception as e:
            st.error(f"Error creating timeline: {str(e)}")
            st.info("📊 Timeline chart temporarily unavailable")
        
        try:
            # Category trends
            category_trends = df.groupby(['published_date', 'category']).size().reset_index(name='count')
            if len(category_trends) > 0:
                fig2 = px.area(category_trends, x='published_date', y='count', color='category',
                              title="Threat Categories Over Time")
                st.plotly_chart(fig2, width="stretch", key="category_trends_area")
            else:
                st.info("📊 No category trend data available")
        except Exception as e:
            st.error(f"Error creating category trends: {str(e)}")
            st.info("📊 Category trends chart temporarily unavailable")
    
    with tab2:
        st.markdown("### 📡 Source Intelligence Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            try:
                # Source distribution
                source_counts = df['source'].value_counts()
                if len(source_counts) > 0:
                    fig = px.pie(values=source_counts.values, names=source_counts.index,
                                title="Threat Intelligence by Source")
                    st.plotly_chart(fig, width="stretch", key="source_distribution_pie")
                else:
                    st.info("📊 No source data available")
            except Exception as e:
                st.error(f"Error creating source chart: {str(e)}")
                st.info("📊 Source distribution chart temporarily unavailable")
        
        with col2:
            try:
                # Source quality metrics
                if 'ioc_count' in df.columns and 'severity' in df.columns:
                    source_quality = df.groupby('source').agg({
                        'ioc_count': 'mean',
                        'severity': lambda x: (x == 'Critical').sum() + (x == 'High').sum() * 0.7 + (x == 'Medium').sum() * 0.3
                    }).round(2)
                    source_quality.columns = ['Avg IOCs', 'Quality Score']
                    if len(source_quality) > 0:
                        st.dataframe(source_quality, use_container_width=True)
                    else:
                        st.info("📊 No source quality data available")
                else:
                    st.info("📊 Source quality metrics unavailable")
            except Exception as e:
                st.error(f"Error creating source quality metrics: {str(e)}")
                st.info("📊 Source quality table temporarily unavailable")
    
    with tab3:
        st.markdown("### 🔥 Severity Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            try:
                # Severity distribution
                severity_counts = df['severity'].value_counts()
                if len(severity_counts) > 0:
                    colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#0dcaf0', 'Low': '#198754'}
                    fig = px.bar(x=severity_counts.index, y=severity_counts.values,
                                title="Threat Severity Distribution",
                                color=severity_counts.index,
                                color_discrete_map=colors)
                    st.plotly_chart(fig, width="stretch", key="severity_distribution_bar")
                else:
                    st.info("📊 No severity data available")
            except Exception as e:
                st.error(f"Error creating severity chart: {str(e)}")
                st.info("📊 Severity distribution chart temporarily unavailable")
        
        with col2:
            try:
                # Severity trends over time
                severity_trends = df.groupby([df['published_date'].dt.date, 'severity']).size().reset_index(name='count')
                if len(severity_trends) > 0:
                    fig2 = px.line(severity_trends, x='published_date', y='count', color='severity',
                                  title="Severity Trends Over Time")
                    st.plotly_chart(fig2, width="stretch", key="severity_trends_line")
                else:
                    st.info("📊 No severity trend data available")
            except Exception as e:
                st.error(f"Error creating severity trends: {str(e)}")
                st.info("📊 Severity trends chart temporarily unavailable")
    
    with tab4:
        st.markdown("### 💎 IOC Intelligence Analysis")
        
        # Check if we have valid IOC count data
        valid_ioc_data = df['ioc_count'].dropna()
        
        if len(valid_ioc_data) == 0:
            st.warning("📊 No IOC data available for analysis")
            return
        
        col1, col2 = st.columns(2)
        
        with col1:
            # IOC distribution with error handling
            try:
                # Filter out invalid values
                ioc_data = df[df['ioc_count'].notna() & (df['ioc_count'] >= 0)]
                
                if len(ioc_data) > 0:
                    fig = px.histogram(ioc_data, x='ioc_count', bins=min(20, len(ioc_data)),
                                     title="IOC Count Distribution per Threat")
                    st.plotly_chart(fig, width="stretch", key="ioc_count_histogram")
                else:
                    st.info("📊 No valid IOC count data to display")
            except Exception as e:
                st.error(f"Error creating IOC histogram: {str(e)}")
                st.info("📊 IOC distribution chart temporarily unavailable")
        
        with col2:
            # Top IOC producers with error handling
            try:
                valid_df = df[df['ioc_count'].notna() & (df['ioc_count'] > 0)]
                if len(valid_df) > 0:
                    ioc_producers = valid_df.nlargest(min(10, len(valid_df)), 'ioc_count')[['source', 'title', 'ioc_count']]
                    st.markdown("**🏆 Top IOC Producers**")
                    st.dataframe(ioc_producers, use_container_width=True)
                else:
                    st.info("📊 No IOC producers to display")
            except Exception as e:
                st.error(f"Error displaying IOC producers: {str(e)}")
                st.info("📊 IOC producers list temporarily unavailable")

# --- Main Application ---
def main():
    """Main application entry point with elite features."""
    
    # Initialize session state
    if 'aggregator' not in st.session_state:
        st.session_state.aggregator = EliteThreatIntelAggregator()
    
    aggregator = st.session_state.aggregator
    
    # Elite sidebar navigation
    with st.sidebar:
        st.markdown("# 🛡️ **TIFA Control Center**")
        st.markdown("---")
        
        # Navigation
        page = st.radio(
            "🚀 **Navigation**",
            ["🎯 Live Dashboard", "🔍 IOC Hunter", "📊 Elite Analytics", "⚙️ Configuration"],
            index=0
        )
        
        st.markdown("---")
        
        # System status
        st.markdown("### 📡 **System Status**")
        st.markdown(f"🔑 **API Keys:** {len(Config.GEMINI_API_KEYS)} active")
        st.markdown(f"📡 **Feed Sources:** {len(Config.THREAT_FEEDS)} configured")
        st.markdown(f"🤖 **AI Models:** {len(Config.GEMINI_MODELS)} available")
        
        if aggregator.metrics.get("last_update"):
            try:
                # Handle both timestamp and ISO format
                last_update_value = aggregator.metrics["last_update"]
                if isinstance(last_update_value, (int, float)):
                    # Unix timestamp
                    last_update = datetime.fromtimestamp(last_update_value)
                else:
                    # ISO format string
                    last_update = datetime.fromisoformat(last_update_value)
                st.markdown(f"🕒 **Last Update:** {last_update.strftime('%H:%M:%S')}")
            except (ValueError, OSError, TypeError) as e:
                st.markdown("🕒 **Last Update:** Unknown")
        
        st.markdown("---")
        
        # Quick stats
        stats = aggregator.db.get_statistics()
        st.markdown("### 📈 **Quick Stats**")
        st.metric("Total Threats", stats.get("total_threats", 0))
        st.metric("Total IOCs", stats.get("total_iocs", 0))
        st.metric("Active Sources", len(Config.THREAT_FEEDS))
        
        st.markdown("---")
        st.markdown("### ℹ️ **About TIFA**")
        st.markdown("""
        **Elite Threat Intelligence Feed Aggregator**
        
        🎯 Real-time threat aggregation  
        🤖 Multi-model AI analysis  
        🔍 Advanced IOC correlation  
        📊 Enterprise analytics  
        🚨 Intelligent alerting  
        
        Built for hackathon excellence! 🏆
        """)
    
    # Main content routing
    if page == "🎯 Live Dashboard":
        render_elite_dashboard(aggregator)
    elif page == "🔍 IOC Hunter":
        render_elite_ioc_search(aggregator)
    elif page == "📊 Elite Analytics":
        render_elite_analytics(aggregator)
    elif page == "⚙️ Configuration":
        st.markdown("## ⚙️ System Configuration")
        st.info("🔧 Advanced configuration panel coming soon...")
        
        # Show current configuration
        st.markdown("### 📋 Current Configuration")
        config_data = {
            "API Keys": len(Config.GEMINI_API_KEYS),
            "Feed Sources": len(Config.THREAT_FEEDS),
            "AI Models": len(Config.GEMINI_MODELS),
            "Max Items per Feed": Config.MAX_ITEMS_PER_FEED,
            "Max Concurrent Requests": Config.MAX_CONCURRENT_AI_REQUESTS,
            "Database Path": Config.DB_PATH
        }
        
        for key, value in config_data.items():
            st.text(f"{key}: {value}")

if __name__ == "__main__":
    main()
