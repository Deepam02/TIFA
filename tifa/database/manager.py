"""
Database management for the Threat Intelligence Aggregator.
Handles all interactions with the SQLite database.
"""
import sqlite3
import json
import logging
from typing import List, Dict, Any
from ..core.models import ThreatIntelItem
from ..core.config import Config

logger = logging.getLogger(__name__)

class ThreatIntelDatabase:
    """Handles all database operations for storing and retrieving threat intelligence."""
    
    def __init__(self, db_path: str = Config.DB_PATH):
        """Initializes the database and creates the necessary table if it doesn't exist."""
        self.db_path = db_path
        self._create_table()

    def _create_table(self):
        """Creates the 'threat_intel' table with a proper schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_intel (
                        id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        link TEXT UNIQUE,
                        summary TEXT,
                        source TEXT NOT NULL,
                        published_date TEXT,
                        iocs TEXT,
                        severity TEXT,
                        created_at TEXT NOT NULL
                    )
                ''')
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error during table creation: {e}")
            raise

    def item_exists(self, item_id: str) -> bool:
        """Checks if an item with the given ID already exists in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM threat_intel WHERE id = ?", (item_id,))
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.error(f"Database error checking item existence: {e}")
            return False

    def save_item(self, item: ThreatIntelItem):
        """Saves a single ThreatIntelItem to the database."""
        if self.item_exists(item.id):
            logger.info(f"Item '{item.title}' already exists, skipping.")
            return

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO threat_intel (id, title, link, summary, source, published_date, iocs, severity, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    item.id, item.title, item.link, item.summary, item.source,
                    item.published_date, json.dumps({k: list(v) for k, v in item.iocs.items()}),
                    item.severity, item.created_at
                ))
                conn.commit()
                logger.info(f"Saved new threat: {item.title}")
        except sqlite3.IntegrityError:
            logger.warning(f"Integrity error: Item with link '{item.link}' likely already exists.")
        except sqlite3.Error as e:
            logger.error(f"Database error saving item: {e}")

    def get_recent_threats(self, limit: int = 50, days_back: int = None, order_by: str = "created_at") -> List[ThreatIntelItem]:
        """Retrieves a list of the most recent threat intelligence items.
        
        Args:
            limit: Maximum number of items to return
            days_back: If specified, only return items from the last N days
            order_by: Field to order by - "created_at" (when added to our DB) or "published_date" (original publication)
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Build the query based on parameters
                if days_back:
                    if order_by == "created_at":
                        query = """
                        SELECT * FROM threat_intel 
                        WHERE datetime(created_at) >= datetime('now', '-{} days')
                        ORDER BY datetime(created_at) DESC LIMIT ?
                        """.format(days_back)
                    else:
                        query = """
                        SELECT * FROM threat_intel 
                        WHERE datetime(published_date) >= datetime('now', '-{} days')
                        ORDER BY datetime(published_date) DESC LIMIT ?
                        """.format(days_back)
                else:
                    if order_by == "created_at":
                        query = "SELECT * FROM threat_intel ORDER BY datetime(created_at) DESC LIMIT ?"
                    else:
                        query = "SELECT * FROM threat_intel ORDER BY datetime(published_date) DESC LIMIT ?"
                
                cursor.execute(query, (limit,))
                rows = cursor.fetchall()
                return [self._row_to_item(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Database error getting recent threats: {e}")
            return []

    def get_threats_by_date_range(self, start_date: str = None, end_date: str = None, limit: int = 50) -> List[ThreatIntelItem]:
        """Get threats within a specific date range based on when they were added to our system."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if start_date and end_date:
                    query = """
                    SELECT * FROM threat_intel 
                    WHERE datetime(created_at) BETWEEN datetime(?) AND datetime(?)
                    ORDER BY datetime(created_at) DESC LIMIT ?
                    """
                    cursor.execute(query, (start_date, end_date, limit))
                elif start_date:
                    query = """
                    SELECT * FROM threat_intel 
                    WHERE datetime(created_at) >= datetime(?)
                    ORDER BY datetime(created_at) DESC LIMIT ?
                    """
                    cursor.execute(query, (start_date, limit))
                elif end_date:
                    query = """
                    SELECT * FROM threat_intel 
                    WHERE datetime(created_at) <= datetime(?)
                    ORDER BY datetime(created_at) DESC LIMIT ?
                    """
                    cursor.execute(query, (end_date, limit))
                else:
                    # No date filter, return recent
                    return self.get_recent_threats(limit=limit, order_by="created_at")
                
                rows = cursor.fetchall()
                return [self._row_to_item(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Database error getting threats by date range: {e}")
            return []

    def search_ioc(self, ioc_query: str) -> List[ThreatIntelItem]:
        """Searches for threats containing a specific Indicator of Compromise."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # The LIKE query is a good first pass for JSON text searching in SQLite
                cursor.execute("SELECT * FROM threat_intel WHERE iocs LIKE ? ORDER BY datetime(published_date) DESC", (f'%{ioc_query}%',))
                rows = cursor.fetchall()
                # Further filter in Python for accuracy
                return [item for item in (self._row_to_item(row) for row in rows) if self._ioc_in_item(ioc_query, item)]
        except sqlite3.Error as e:
            logger.error(f"Database error searching IOC: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """Calculates and returns key statistics about the stored threat intelligence."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM threat_intel")
                total_threats = cursor.fetchone()[0]
                
                cursor.execute("SELECT iocs FROM threat_intel")
                all_iocs_json = [row[0] for row in cursor.fetchall() if row[0]]
                total_iocs_count = sum(len(ioc_list) for ioc_json in all_iocs_json for ioc_list in json.loads(ioc_json).values())

                cursor.execute("SELECT COUNT(DISTINCT source) FROM threat_intel")
                total_sources = cursor.fetchone()[0]

                cursor.execute("SELECT MAX(datetime(published_date)) FROM threat_intel")
                last_update_row = cursor.fetchone()
                last_update = last_update_row[0] if last_update_row and last_update_row[0] else "N/A"

                return {
                    "total_threats": total_threats,
                    "total_iocs": total_iocs_count,
                    "total_sources": total_sources,
                    "last_update": last_update
                }
        except sqlite3.Error as e:
            logger.error(f"Database error getting statistics: {e}")
            return {"total_threats": 0, "total_iocs": 0, "total_sources": 0, "last_update": "Error"}

    def _row_to_item(self, row: tuple) -> ThreatIntelItem:
        """Converts a database row tuple into a ThreatIntelItem object."""
        # Column order: id, title, link, summary, source, published_date, iocs, severity, created_at
        iocs_dict = json.loads(row[6]) if row[6] else {}
        iocs_sets = {k: set(v) for k, v in iocs_dict.items()}
        
        item = ThreatIntelItem(
            title=row[1],                    # title
            link=row[2],                     # link  
            summary=row[3] or "",            # summary
            source=row[4],                   # source
            published_date=row[5],           # published_date
            iocs=iocs_sets,                  # iocs
            severity=row[7] or "Medium"      # severity
        )
        item.id = row[0]                     # id
        item.created_at = row[8]             # created_at
        return item

    def _ioc_in_item(self, ioc_query: str, item: ThreatIntelItem) -> bool:
        """Checks if the queried IOC is present in the item's IOC dictionary."""
        for ioc_list in item.iocs.values():
            if ioc_query in ioc_list:
                return True
        return False
