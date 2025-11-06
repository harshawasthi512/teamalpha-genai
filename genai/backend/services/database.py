import sqlite3
import aiosqlite
from datetime import datetime, timedelta
import requests
from config import settings
from typing import List, Set
import asyncio

class PhishingDatabase:
    def __init__(self):
        self.db_path = "phishing_urls.db"
        self._init_sync_db()  # Initialize sync first
    
    def _init_sync_db(self):
        """Initialize SQLite database synchronously"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS phishing_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    source TEXT DEFAULT 'phishing_army',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS update_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    domains_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'success'
                )
            ''')
            
            conn.commit()
    
    async def download_phishing_army_data(self) -> Set[str]:
        """Download latest PhishingArmy blocklist"""
        try:
            print("Downloading PhishingArmy data...")
            response = requests.get(settings.PHISHING_ARMY_URL, timeout=30)
            response.raise_for_status()
            
            domains = set()
            for line in response.text.strip().split('\n'):
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.add(domain)
            
            print(f"Downloaded {len(domains)} domains from PhishingArmy")
            return domains
            
        except Exception as e:
            print(f"Error downloading PhishingArmy data: {e}")
            return set()
    
    async def update_phishing_domains(self):
        """Update the phishing domains database"""
        try:
            domains = await self.download_phishing_army_data()
            if not domains:
                print("No domains downloaded, skipping update")
                return
            
            # Use synchronous operations for database updates
            with sqlite3.connect(self.db_path) as conn:
                # Clear old data
                conn.execute("DELETE FROM phishing_domains WHERE source = 'phishing_army'")
                
                # Insert new domains
                inserted_count = 0
                for domain in domains:
                    try:
                        conn.execute(
                            "INSERT INTO phishing_domains (domain, source) VALUES (?, ?)",
                            (domain, 'phishing_army')
                        )
                        inserted_count += 1
                    except sqlite3.IntegrityError:
                        # Skip duplicate domains
                        pass
                
                # Log the update
                conn.execute(
                    "INSERT INTO update_log (domains_count, status) VALUES (?, ?)",
                    (inserted_count, 'success')
                )
                
                conn.commit()
                print(f"Successfully updated {inserted_count} phishing domains")
                
        except Exception as e:
            print(f"Error updating phishing domains: {e}")
            # Log the error
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO update_log (domains_count, status) VALUES (?, ?)",
                    (0, f'error: {str(e)}')
                )
                conn.commit()
    
    async def should_update(self) -> bool:
        """Check if database should be updated (24-hour interval)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT last_update FROM update_log ORDER BY last_update DESC LIMIT 1"
                )
                result = cursor.fetchone()
                
                if not result:
                    return True  # Never updated, need initial update
                
                last_update = datetime.fromisoformat(result[0])
                return datetime.now() - last_update > timedelta(hours=24)
                
        except Exception as e:
            print(f"Error checking update status: {e}")
            return True
    
    async def is_phishing_domain(self, domain: str) -> bool:
        """Check if domain exists in phishing database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM phishing_domains WHERE domain = ? LIMIT 1",
                    (domain,)
                )
                result = cursor.fetchone()
                return result is not None
                
        except Exception as e:
            print(f"Error checking phishing domain: {e}")
            return False
    
    async def get_domain_count(self) -> int:
        """Get total number of phishing domains in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM phishing_domains")
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            print(f"Error getting domain count: {e}")
            return 0
    
    async def get_last_update_info(self) -> dict:
        """Get information about the last update"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT last_update, domains_count, status FROM update_log ORDER BY last_update DESC LIMIT 1"
                )
                result = cursor.fetchone()
                
                if result:
                    return {
                        "last_update": result[0],
                        "domains_count": result[1],
                        "status": result[2]
                    }
                return {}
                
        except Exception as e:
            print(f"Error getting update info: {e}")
            return {}

phishing_db = PhishingDatabase()