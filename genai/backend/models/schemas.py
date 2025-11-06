from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Any, Optional
from enum import Enum

class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

class URLScanResult(BaseModel):
    url: str
    virustotal_result: Optional[Dict[str, Any]] = None
    phishing_army_result: Optional[bool] = None
    risk_level: RiskLevel

class VirusTotalResponse(BaseModel):
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class ScanRequest(BaseModel):
    subject: str
    content: str

class GeminiAnalysis(BaseModel):
    threat_score: int
    risk_level: RiskLevel
    detailed_analysis: str
    url_breakdown: List[Dict[str, Any]]
    behavioral_analysis: str
    recommendations: List[str]
    confidence: float

class ScanResponse(BaseModel):
    analysis: GeminiAnalysis
    url_scan_results: List[URLScanResult]
    processing_time: float