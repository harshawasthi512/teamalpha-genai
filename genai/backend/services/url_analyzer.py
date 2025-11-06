from utils.virus_total import virus_total_client
from services.database import phishing_db
from models.schemas import URLScanResult, RiskLevel
from typing import List
import asyncio
import aiohttp
import time
from urllib.parse import urlparse

class URLAnalyzer:
    def __init__(self):
        self.phishing_db = phishing_db
        # Initialize database on startup
        asyncio.create_task(self._initialize_database())
    
    async def _initialize_database(self):
        """Initialize database with PhishingArmy data if needed"""
        try:
            if await self.phishing_db.should_update():
                print("Initial PhishingArmy database update needed...")
                await self.phishing_db.update_phishing_domains()
            else:
                count = await self.phishing_db.get_domain_count()
                print(f"Phishing database ready with {count} domains")
        except Exception as e:
            print(f"Error initializing database: {e}")
    
    async def check_phishing_army_batch(self, urls: List[str]) -> List[bool]:
        """Check multiple URLs against PhishingArmy in batch"""
        results = []
        for url in urls:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                result = await self.phishing_db.is_phishing_domain(domain)
                results.append(result)
            except Exception:
                results.append(False)
        return results
    async def analyze_urls(self, urls: List[str]) -> List[URLScanResult]:
        """Analyze list of URLs using parallel processing"""
        if not urls:
            return []
        
        print(f"Parallel scanning {len(urls)} URLs...")
        start_time = time.time()
        
        # Step 1: Batch PhishingArmy checks (fast, local database)
        phishing_army_results = await self.check_phishing_army_batch(urls)
        
        # Step 2: Parallel VirusTotal scans (slow, external API)
        vt_tasks = []
        for url in urls:
            vt_tasks.append(
                asyncio.get_event_loop().run_in_executor(
                    None, virus_total_client.scan_url, url
                )
            )
        
        # Wait for all VirusTotal scans with timeout
        try:
            virustotal_results = await asyncio.wait_for(
                asyncio.gather(*vt_tasks, return_exceptions=True), 
                timeout=10.0  # 10 second timeout for all VT scans
            )
        except asyncio.TimeoutError:
            print("VirusTotal scan timeout, using partial results")
            # Cancel remaining tasks and get partial results
            virustotal_results = []
            for task in vt_tasks:
                if task.done():
                    try:
                        virustotal_results.append(task.result())
                    except:
                        virustotal_results.append(None)
                else:
                    virustotal_results.append(None)
        
        # Step 3: Process results
        results = []
        for i, url in enumerate(urls):
            try:
                phishing_army_result = phishing_army_results[i]
                if isinstance(phishing_army_result, Exception):
                    phishing_army_result = False
                
                virustotal_result = virustotal_results[i]
                if isinstance(virustotal_result, Exception):
                    virustotal_result = None
                
                risk_level = await self._calculate_risk_level(url, phishing_army_result, virustotal_result)
                
                # Prepare VirusTotal result for serialization
                vt_result_dict = None
                if virustotal_result and hasattr(virustotal_result, 'data') and virustotal_result.data:
                    vt_result_dict = virustotal_result.dict()
                
                results.append(URLScanResult(
                    url=url,
                    virustotal_result=vt_result_dict,
                    phishing_army_result=phishing_army_result,
                    risk_level=risk_level
                ))
                
            except Exception as e:
                print(f"Error processing URL {url}: {e}")
                results.append(URLScanResult(
                    url=url,
                    virustotal_result=None,
                    phishing_army_result=False,
                    risk_level=RiskLevel.SUSPICIOUS
                ))
        
        scan_time = time.time() - start_time
        print(f"URL scanning completed in {scan_time:.2f}s")
        return results
    
    async def _calculate_risk_level(self, url: str, phishing_army: bool, virustotal_result) -> RiskLevel:
        """Calculate overall risk level based on all factors"""
        
        # Immediate malicious if in PhishingArmy (fastest check)
        if phishing_army:
            return RiskLevel.MALICIOUS
        
        # Quick heuristic checks (very fast)
        if self._has_suspicious_patterns(url):
            return RiskLevel.SUSPICIOUS
        
        # VirusTotal check (slowest, but we have timeout)
        if virustotal_result and hasattr(virustotal_result, 'data') and virustotal_result.data:
            data = virustotal_result.data
            if isinstance(data, dict):
                attributes = data.get('data', {}).get('attributes', {}) if 'data' in data else data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                
                if malicious_count > 3:  # Lower threshold for faster decision
                    return RiskLevel.MALICIOUS
                elif malicious_count > 0:
                    return RiskLevel.SUSPICIOUS
        
        return RiskLevel.SAFE
    
    def _has_suspicious_patterns(self, url: str) -> bool:
        """Fast heuristic checks for suspicious URLs"""
        url_lower = url.lower()
        
        # Quick domain checks
        try:
            domain = urlparse(url).netloc
            
            # Common phishing TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online', '.gq']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # Brand impersonation
            brands = ['amazon', 'paypal', 'microsoft', 'apple', 'google', 'bank', 'security', 'verify', 'login']
            for brand in brands:
                if brand in domain and f"{brand}.com" not in domain:
                    return True
            
            # Excessive subdomains or hyphens
            if domain.count('.') > 3 or domain.count('-') > 2:
                return True
                
        except:
            pass
        
        return False

url_analyzer = URLAnalyzer()