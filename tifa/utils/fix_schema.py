#!/usr/bin/env python3
"""
Complete database schema fix for TIFA
Ensures all column names match the application requirements
"""
import sqlite3
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_database_schema():
    """Fix database schema completely."""
    try:
        with sqlite3.connect('threat_intel.db') as conn:
            cursor = conn.cursor()
            
            # Drop existing table if it exists
            cursor.execute('DROP TABLE IF EXISTS threat_intel_backup')
            
            # Create backup of existing data
            cursor.execute('''
                CREATE TABLE threat_intel_backup AS 
                SELECT * FROM threat_intel
            ''')
            
            # Drop the problematic table
            cursor.execute('DROP TABLE threat_intel')
            
            # Create new table with correct schema
            cursor.execute('''
                CREATE TABLE threat_intel (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    link TEXT UNIQUE,
                    summary TEXT,
                    source TEXT NOT NULL,
                    published_date TEXT,
                    iocs TEXT,
                    severity TEXT DEFAULT 'Medium',
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Migrate data from backup (mapping old columns to new)
            cursor.execute('''
                INSERT INTO threat_intel (
                    id, title, link, summary, source, published_date, iocs, severity, created_at
                )
                SELECT 
                    id,
                    title,
                    COALESCE(link, ''),
                    COALESCE(summary, description, ''),
                    source,
                    COALESCE(published, ''),
                    COALESCE(iocs, '{}'),
                    COALESCE(severity, 'Medium'),
                    COALESCE(created_at, datetime('now'))
                FROM threat_intel_backup
            ''')
            
            # Drop backup table
            cursor.execute('DROP TABLE threat_intel_backup')
            
            conn.commit()
            logger.info('✅ Database schema fixed successfully!')
            
            # Verify the new schema
            cursor.execute('PRAGMA table_info(threat_intel)')
            columns = cursor.fetchall()
            logger.info('📋 New schema:')
            for col in columns:
                logger.info(f'  {col[1]} ({col[2]})')
                
    except Exception as e:
        logger.error(f'❌ Schema fix error: {e}')
        raise

if __name__ == "__main__":
    fix_database_schema()
