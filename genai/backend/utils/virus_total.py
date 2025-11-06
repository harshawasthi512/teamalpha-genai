import requests
import base64
import time
from config import settings
from models.schemas import VirusTotalResponse
from typing import Dict, Any
import hashlib
import sqlite3
from datetime import datetime, timedelta

class VirusTotalClient:
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = settings.VIRUSTOTAL_URL
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self._init_cache()
    
    def _init_cache(self):
        """Initialize SQLite cache for VirusTotal results"""
        self.cache_conn = sqlite3.connect('virustotal_cache.db', check_same_thread=False)
        self.cache_conn.execute('''
            CREATE TABLE IF NOT EXISTS vt_cache (
                url_hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                result_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.cache_conn.commit()
    
    def _get_cache_key(self, url: str) -> str:
        """Generate cache key for URL"""
        return hashlib.md5(url.encode()).hexdigest()
    
    def _get_cached_result(self, url: str) -> Dict[str, Any]:
        """Get cached result for URL"""
        cache_key = self._get_cache_key(url)
        cursor = self.cache_conn.execute(
            "SELECT result_data FROM vt_cache WHERE url_hash = ? AND created_at > datetime('now', '-1 hour')",
            (cache_key,)
        )
        result = cursor.fetchone()
        return eval(result[0]) if result else None
    
    def _set_cached_result(self, url: str, result: Dict[str, Any]):
        """Cache result for URL"""
        cache_key = self._get_cache_key(url)
        self.cache_conn.execute(
            "INSERT OR REPLACE INTO vt_cache (url_hash, url, result_data) VALUES (?, ?, ?)",
            (cache_key, url, str(result))
        )
        self.cache_conn.commit()
    
    def scan_url(self, url: str) -> VirusTotalResponse:
        """Scan URL using VirusTotal API with caching"""
        # Check cache first
        cached_result = self._get_cached_result(url)
        if cached_result:
            print(f"Using cached result for: {url}")
            return VirusTotalResponse(data=cached_result)
        
        try:
            # Check if API key is configured
            if not self.api_key or self.api_key == "your_virustotal_api_key_here":
                return VirusTotalResponse(error="API key not configured")
            
            # Quick submission without waiting for full analysis
            response = requests.post(
                self.base_url,
                headers=self.headers,
                data=f"url={url}",
                timeout=5  # Shorter timeout
            )
            
            if response.status_code == 200:
                analysis_id = response.json()['data']['id']
                result = self._get_analysis_result_quick(analysis_id)
                if result and result.data:
                    self._set_cached_result(url, result.data)
                return result
            else:
                return VirusTotalResponse(error=f"API Error: {response.status_code}")
                
        except Exception as e:
            return VirusTotalResponse(error=f"Scan failed: {str(e)}")
    
    def _get_analysis_result_quick(self, analysis_id: str) -> VirusTotalResponse:
        """Get analysis result with minimal waiting"""
        try:
            # Try to get result immediately
            response = requests.get(
                f"{self.base_url}/{analysis_id}",
                headers=self.headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                # Check if we have enough data to make a decision
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                if stats:
                    return VirusTotalResponse(data=data)
            
            # If not ready, return what we have
            return VirusTotalResponse(data={'data': {'attributes': {'last_analysis_stats': {}}}})
                
        except Exception as e:
            return VirusTotalResponse(error=str(e))

virus_total_client = VirusTotalClient()