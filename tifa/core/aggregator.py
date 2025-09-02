"""
Main aggregator class that coordinates all components
"""

import json
from datetime import datetime
from typing import List, Dict
import logging
from .models import ThreatIntelItem
from ..database.manager import ThreatIntelDatabase
from ..analyzers.ioc_extractor import IOCExtractor
from ..collectors.feed_collector import FeedCollector
from ..analyzers.ai_analyzer import AIAnalyzer
from .config import Config

logger = logging.getLogger(__name__)

class ThreatIntelAggregator:
    """Main aggregator class that coordinates all components"""
    
    def __init__(self):
        self.db = ThreatIntelDatabase()
        self.ioc_extractor = IOCExtractor()
        self.feed_collector = FeedCollector(self.db, self.ioc_extractor)
        self.ai_analyzer = AIAnalyzer()  # Now uses Gemini by default
        self.last_update = None
        self.is_updating = False
    
    def refresh_feeds(self, progress_callback=None) -> str:
        """Refresh all threat intelligence feeds and process them"""
        if self.is_updating:
            return "Update already in progress..."
        
        self.is_updating = True
        
        try:
            logger.info("Starting feed refresh...")
            
            # Step 1: Collect feeds
            new_items = self.feed_collector.collect_all_feeds()
            
            if not new_items:
                logger.warning("No new items collected from feeds")
                return "No new threat intelligence items found."
            
            # Step 2: Process with AI analysis
            processed_count = 0
            for item in new_items:
                try:
                    # Generate AI summary
                    item.summary = self.ai_analyzer.generate_summary(item)
                    
                    # Assess severity
                    item.severity = self.ai_analyzer.assess_severity(item)
                    
                    # Save to database
                    self.db.save_threat_intel(item)
                    processed_count += 1
                    
                    if progress_callback:
                        progress_callback(processed_count, len(new_items))
                
                except Exception as e:
                    logger.error(f"Error processing item {item.id}: {str(e)}")
                    continue
            
            self.last_update = datetime.now()
            success_msg = f"Successfully updated {processed_count} threat intelligence items."
            logger.info(success_msg)
            
            return success_msg
            
        except Exception as e:
            error_msg = f"Error during feed refresh: {str(e)}"
            logger.error(error_msg)
            return error_msg
        
        finally:
            self.is_updating = False
    
    def get_dashboard_data(self) -> Dict:
        """Get data for dashboard display"""
        recent_threats = self.db.get_recent_threats(Config.MAX_RECENT_THREATS)
        stats = self.db.get_statistics()
        
        # Calculate additional statistics
        total_iocs = sum(
            sum(len(iocs) for iocs in threat.iocs.values()) 
            for threat in recent_threats
        )
        
        dashboard_stats = {
            'total_threats': stats['total_threats'],
            'high_severity': stats['severity_counts'].get('High', 0),
            'medium_severity': stats['severity_counts'].get('Medium', 0),
            'low_severity': stats['severity_counts'].get('Low', 0),
            'total_iocs': total_iocs,
            'last_update': self.last_update.strftime("%Y-%m-%d %H:%M:%S") if self.last_update else "Never",
            'source_counts': stats['source_counts']
        }
        
        return {
            'threats': recent_threats,
            'stats': dashboard_stats
        }
    
    def search_threats(self, query: str) -> List[ThreatIntelItem]:
        """Search threats by query"""
        if not query.strip():
            return []
        
        return self.db.search_threats(query, Config.MAX_SEARCH_RESULTS)
    
    def get_threats_by_severity(self, severity: str) -> List[ThreatIntelItem]:
        """Get threats filtered by severity"""
        return self.db.get_threats_by_severity(severity)
    
    def get_threats_by_source(self, source: str) -> List[ThreatIntelItem]:
        """Get threats filtered by source"""
        return self.db.get_threats_by_source(source)
    
    def export_iocs(self, format_type: str = "json") -> str:
        """Export IOCs in specified format"""
        threats = self.db.get_recent_threats(Config.MAX_EXPORT_ITEMS)
        all_iocs = {}
        
        # Aggregate all IOCs
        for threat in threats:
            for ioc_type, iocs in threat.iocs.items():
                if ioc_type not in all_iocs:
                    all_iocs[ioc_type] = []
                all_iocs[ioc_type].extend(iocs)
        
        # Remove duplicates
        for ioc_type in all_iocs:
            all_iocs[ioc_type] = list(set(all_iocs[ioc_type]))
        
        if format_type.lower() == "json":
            return json.dumps(all_iocs, indent=2)
        elif format_type.lower() == "csv":
            return self._export_iocs_csv(all_iocs)
        else:
            return str(all_iocs)
    
    def _export_iocs_csv(self, all_iocs: Dict) -> str:
        """Export IOCs in CSV format"""
        csv_lines = ["IOC_Type,IOC_Value,Threat_Count"]
        
        for ioc_type, iocs in all_iocs.items():
            for ioc in iocs:
                # Count how many threats contain this IOC
                threat_count = self._count_threats_with_ioc(ioc)
                csv_lines.append(f"{ioc_type},{ioc},{threat_count}")
        
        return "\n".join(csv_lines)
    
    def _count_threats_with_ioc(self, ioc_value: str) -> int:
        """Count how many threats contain a specific IOC"""
        # This is a simplified implementation
        # In a production system, you might want to optimize this with database queries
        recent_threats = self.db.get_recent_threats(Config.MAX_EXPORT_ITEMS)
        count = 0
        
        for threat in recent_threats:
            for ioc_list in threat.iocs.values():
                if ioc_value in ioc_list:
                    count += 1
                    break  # Don't count the same threat multiple times
        
        return count
    
    def get_status(self) -> Dict:
        """Get system status information"""
        return {
            'is_updating': self.is_updating,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'database_path': self.db.db_path,
            'feed_count': len(Config.THREAT_FEEDS),
            'ai_mode': 'gemini' if hasattr(self.ai_analyzer, 'analyzer') and self.ai_analyzer.analyzer else 'fallback'
        }
