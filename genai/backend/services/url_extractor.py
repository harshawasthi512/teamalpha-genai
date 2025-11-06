import re
from urlextract import URLExtract
from typing import List

class URLExtractorService:
    def __init__(self):
        self.extractor = URLExtract()
        
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from email content"""
        try:
            urls = self.extractor.find_urls(text)
            # Clean and deduplicate URLs
            cleaned_urls = []
            for url in urls:
                # Remove common trailing characters
                clean_url = re.sub(r'[.,;:!?)]+$', '', url)
                if clean_url not in cleaned_urls:
                    cleaned_urls.append(clean_url)
            return cleaned_urls
        except Exception as e:
            print(f"Error extracting URLs: {e}")
            return []

url_extractor = URLExtractorService()