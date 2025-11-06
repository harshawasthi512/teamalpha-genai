from utils.virus_total import virus_total_client
from services.database import phishing_db
from models.schemas import URLScanResult, RiskLevel
from typing import List
import asyncio
import time
from urllib.parse import urlparse
import re

class URLAnalyzer:
    def __init__(self):
        self.phishing_db = phishing_db
    
    async def analyze_urls(self, urls: List[str]) -> List[URLScanResult]:
        """Analyze list of URLs"""
        if not urls:
            print("❌ No URLs to analyze")
            return []
        
        print(f"🔍 Analyzing {len(urls)} URLs: {urls}")
        start_time = time.time()
        
        results = []
        for url in urls:
            try:
                print(f"📊 Scanning URL: {url}")
                
                # Step 1: Check PhishingArmy
                phishing_army_result = await self._check_phishing_army(url)
                
                # Step 2: Check VirusTotal (with timeout)
                virustotal_result = await self._scan_virustotal(url)
                
                # Step 3: Calculate risk level
                risk_level = await self._calculate_risk_level(url, phishing_army_result, virustotal_result)
                
                # Prepare result
                vt_result_dict = None
                if virustotal_result and hasattr(virustotal_result, 'data') and virustotal_result.data:
                    vt_result_dict = virustotal_result.dict()
                
                result = URLScanResult(
                    url=url,
                    virustotal_result=vt_result_dict,
                    phishing_army_result=phishing_army_result,
                    risk_level=risk_level
                )
                
                results.append(result)
                print(f"✅ URL {url} -> Risk: {risk_level}, PhishingArmy: {phishing_army_result}")
                
            except Exception as e:
                print(f"❌ Error processing URL {url}: {e}")
                # Return a result even if there's an error
                results.append(URLScanResult(
                    url=url,
                    virustotal_result=None,
                    phishing_army_result=False,
                    risk_level=RiskLevel.SUSPICIOUS
                ))
        
        scan_time = time.time() - start_time
        print(f"✅ URL scanning completed in {scan_time:.2f}s - Found {len(results)} results")
        return results
    
    async def _check_phishing_army(self, url: str) -> bool:
        """Check URL against PhishingArmy database"""
        try:
            domain = urlparse(url).netloc
            return await self.phishing_db.is_phishing_domain(domain)
        except Exception as e:
            print(f"❌ Error checking PhishingArmy for {url}: {e}")
            return False
    
    async def _scan_virustotal(self, url: str):
        """Scan URL with VirusTotal with timeout"""
        try:
            # Only scan suspicious URLs to save API calls
            if not self._is_suspicious_by_heuristics(url):
                return None
                
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, virus_total_client.scan_url, url
                ),
                timeout=5.0
            )
            return result
        except asyncio.TimeoutError:
            print(f"⏰ VirusTotal timeout for {url}")
            return None
        except Exception as e:
            print(f"❌ VirusTotal error for {url}: {e}")
            return None
    
    async def _calculate_risk_level(self, url: str, phishing_army: bool, virustotal_result) -> RiskLevel:
        """Calculate risk level for URL"""
        
        # Immediate malicious if in PhishingArmy
        if phishing_army:
            return RiskLevel.MALICIOUS
        
        # Check heuristics
        if self._has_suspicious_patterns(url):
            return RiskLevel.SUSPICIOUS
        
        # Check VirusTotal results
        if virustotal_result and hasattr(virustotal_result, 'data') and virustotal_result.data:
            data = virustotal_result.data
            if isinstance(data, dict):
                attributes = data.get('data', {}).get('attributes', {}) if 'data' in data else data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                
                if malicious_count > 3:
                    return RiskLevel.MALICIOUS
                elif malicious_count > 0:
                    return RiskLevel.SUSPICIOUS
        
        return RiskLevel.SAFE
    
    def _is_suspicious_by_heuristics(self, url: str) -> bool:
        """Check if URL should be scanned with VirusTotal"""
        return self._has_suspicious_patterns(url)
    
    def _has_suspicious_patterns(self, url: str) -> bool:
        """Check for suspicious URL patterns"""
        url_lower = url.lower()
        
        try:
            domain = urlparse(url).netloc
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online', '.gq', '.bid']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # Brand impersonation
            brands = ['amazon', 'paypal', 'microsoft', 'apple', 'google', 'bank', 'security', 'verify', 'login', 'account']
            for brand in brands:
                if brand in domain and f"{brand}.com" not in domain:
                    return True
            
            # Suspicious domain structure
            if domain.count('-') > 2:
                return True
            if domain.count('.') > 3:
                return True
                
        except Exception as e:
            print(f"❌ Error in pattern check: {e}")
        
        return False

url_analyzer = URLAnalyzer()