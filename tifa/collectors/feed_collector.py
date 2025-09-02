"""
Feed collection from RSS/Atom sources and threat intelligence aggregation
"""

import feedparser
import hashlib
from datetime import datetime
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from ..core.models import ThreatIntelItem
from ..database.manager import ThreatIntelDatabase
from ..analyzers.ioc_extractor import IOCExtractor
from ..core.config import Config

logger = logging.getLogger(__name__)

class FeedCollector:
    """Collect threat intelligence from RSS/Atom feeds and other sources"""
    
    def __init__(self, db: ThreatIntelDatabase, ioc_extractor: IOCExtractor):
        self.db = db
        self.ioc_extractor = ioc_extractor
        self.feeds = Config.THREAT_FEEDS
    
    def collect_from_feed(self, feed_info: dict) -> List[ThreatIntelItem]:
        """Collect threat intelligence from a single RSS/Atom feed"""
        items = []
        
        try:
            logger.info(f"Fetching feed: {feed_info['name']}")
            feed = feedparser.parse(feed_info['url'])
            
            if not hasattr(feed, 'entries'):
                logger.warning(f"No entries found in feed: {feed_info['name']}")
                return items
            
            for entry in feed.entries[:Config.MAX_ITEMS_PER_FEED]:
                try:
                    # Generate unique ID
                    item_id = hashlib.md5(f"{entry.link}_{entry.title}".encode()).hexdigest()
                    
                    # Extract text content
                    content = self._extract_content(entry)
                    
                    # Extract IOCs
                    iocs = self.ioc_extractor.extract_iocs(content)
                    
                    # Create threat intel item
                    item = ThreatIntelItem(
                        title=entry.title,
                        summary=self._truncate_description(getattr(entry, 'summary', '')),
                        source=feed_info['name'],
                        published_date=getattr(entry, 'published', datetime.now().isoformat()),
                        link=entry.link,
                        iocs=iocs
                    )
                    
                    items.append(item)
                    
                except Exception as e:
                    logger.error(f"Error processing entry from {feed_info['name']}: {str(e)}")
                    continue
            
            logger.info(f"Collected {len(items)} items from {feed_info['name']}")
            
        except Exception as e:
            logger.error(f"Error collecting from {feed_info['name']}: {str(e)}")
        
        return items
    
    def _extract_content(self, entry) -> str:
        """Extract full content from feed entry"""
        content_parts = []
        
        if hasattr(entry, 'title'):
            content_parts.append(entry.title)
        
        if hasattr(entry, 'summary'):
            content_parts.append(entry.summary)
        
        if hasattr(entry, 'content'):
            for content_item in entry.content:
                content_parts.append(content_item.value)
        
        return " ".join(content_parts)
    
    def _truncate_description(self, description: str, max_length: int = 500) -> str:
        """Truncate description to reasonable length"""
        if len(description) > max_length:
            return description[:max_length] + "..."
        return description
    
    def _extract_tags(self, text: str) -> List[str]:
        """Extract relevant tags from text"""
        tags = []
        text_lower = text.lower()
        
        for keyword in Config.THREAT_KEYWORDS:
            if keyword in text_lower:
                tags.append(keyword)
        
        return list(set(tags))  # Remove duplicates
    
    def collect_all_feeds(self) -> List[ThreatIntelItem]:
        """Collect from all configured feeds using multi-threading"""
        all_items = []
        
        with ThreadPoolExecutor(max_workers=Config.MAX_FEED_WORKERS) as executor:
            future_to_feed = {
                executor.submit(self.collect_from_feed, feed): feed
                for feed in self.feeds
            }
            
            for future in as_completed(future_to_feed):
                feed = future_to_feed[future]
                try:
                    items = future.result()
                    all_items.extend(items)
                except Exception as e:
                    logger.error(f"Error in feed collection for {feed['name']}: {str(e)}")
        
        logger.info(f"Total items collected from all feeds: {len(all_items)}")
        return all_items
