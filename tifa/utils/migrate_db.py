#!/usr/bin/env python3
"""
Database migration script for TIFA
Fixes table naming compatibility issues
"""
import sqlite3
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database():
    """Migrate database schema to fix compatibility issues."""
    try:
        with sqlite3.connect('threat_intel.db') as conn:
            cursor = conn.cursor()
            
            # Check if threat_items table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_items'")
            threat_items_exists = cursor.fetchone()
            
            # Check if threat_intel table exists  
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_intel'")
            threat_intel_exists = cursor.fetchone()
            
            if threat_items_exists and not threat_intel_exists:
                # Rename threat_items to threat_intel
                cursor.execute('ALTER TABLE threat_items RENAME TO threat_intel')
                logger.info('✅ Renamed threat_items table to threat_intel')
            elif not threat_intel_exists:
                # Create threat_intel table
                cursor.execute('''
                    CREATE TABLE threat_intel (
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
                logger.info('✅ Created threat_intel table')
            else:
                logger.info('✅ threat_intel table already exists')
            
            conn.commit()
            logger.info('🎯 Database migration completed successfully!')
            
    except Exception as e:
        logger.error(f'❌ Migration error: {e}')
        raise

if __name__ == "__main__":
    migrate_database()
