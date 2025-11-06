import re
from typing import List
from urllib.parse import urlparse

class URLExtractorService:
    def __init__(self):
        pass
        
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from email content"""
        try:
            # Use comprehensive regex pattern for URL extraction
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*'
            urls = re.findall(url_pattern, text)
            
            # Also find URLs without http(s) but with common domain patterns
            domain_pattern = r'(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?[/\w\.-]*\??[/\w\.-=&%]*'
            domain_urls = re.findall(domain_pattern, text)
            
            # Filter domain_urls to only include those that look like real URLs
            filtered_domains = []
            for domain in domain_urls:
                if self._looks_like_url(domain) and domain not in urls:
                    # Add https prefix
                    filtered_domains.append(f"https://{domain}")
            
            all_urls = urls + filtered_domains
            
            # Clean URLs
            cleaned_urls = []
            for url in all_urls:
                clean_url = self._clean_url(url)
                if clean_url and self._is_valid_url(clean_url):
                    cleaned_urls.append(clean_url)
            
            # Remove duplicates while preserving order
            unique_urls = []
            for url in cleaned_urls:
                if url not in unique_urls:
                    unique_urls.append(url)
            
            print(f"✅ Extracted {len(unique_urls)} URLs: {unique_urls}")
            return unique_urls
            
        except Exception as e:
            print(f"❌ Error extracting URLs: {e}")
            return []
    
    def _looks_like_url(self, text: str) -> bool:
        """Check if text looks like a URL"""
        # Common URL indicators
        url_indicators = ['/', '?', '=', '&', '.com', '.net', '.org', '.tk', '.ml', '.ga']
        return any(indicator in text for indicator in url_indicators)
    
    def _clean_url(self, url: str) -> str:
        """Clean URL by removing trailing punctuation"""
        if not url:
            return ""
        
        # Remove common trailing characters
        clean_url = url.strip()
        clean_url = re.sub(r'[.,;:!?)\]\}>]+$', '', clean_url)
        
        # Ensure it starts with http if it doesn't
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = f"https://{clean_url}"
        
        return clean_url
    
    def _is_valid_url(self, url: str) -> bool:
        """Basic URL validation"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme) and bool(parsed.netloc)
        except:
            return False

url_extractor = URLExtractorService()