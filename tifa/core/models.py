"""
Data models for the Threat Intelligence Aggregator.
"""
from datetime import datetime
from typing import Dict, Set, Any

class ThreatIntelItem:
    """
    Represents a single piece of threat intelligence data.
    
    Attributes:
        id (str): A unique identifier for the item, typically a combination of source and link.
        title (str): The title of the threat intelligence report or article.
        link (str): The direct URL to the original source.
        summary (str): A summary of the threat intelligence.
        source (str): The name of the feed or source (e.g., "Krebs on Security").
        published_date (str): The publication date of the item in ISO format.
        iocs (Dict[str, Set[str]]): A dictionary of Indicators of Compromise, categorized by type (e.g., "ips", "domains").
        severity (str): The assessed severity of the threat (e.g., "Low", "Medium", "High").
        created_at (str): The timestamp when the item was added to the database.
    """
    def __init__(self, title: str, link: str, summary: str, source: str, published_date: str, iocs: Dict[str, Set[str]], severity: str = "Medium"):
        self.id = f"{source}:{link}"
        self.title = title
        self.link = link
        self.summary = summary
        self.source = source
        self.published_date = published_date
        self.iocs = iocs
        self.severity = severity
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the object to a dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "link": self.link,
            "summary": self.summary,
            "source": self.source,
            "published_date": self.published_date,
            "iocs": {k: list(v) for k, v in self.iocs.items()},
            "severity": self.severity,
            "created_at": self.created_at
        }
