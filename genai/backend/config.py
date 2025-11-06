import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    DATABASE_URL = os.getenv("DATABASE_URL")
    
    # PhishingArmy configuration
    PHISHING_ARMY_URL = "https://phishing.army/download/phishing_army_blocklist.txt"
    
    # VirusTotal configuration
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
    
settings = Settings()