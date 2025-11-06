from services.url_extractor import url_extractor
from services.url_analyzer import url_analyzer
from utils.gemini_client import gemini_client
from models.schemas import ScanRequest, ScanResponse, URLScanResult, GeminiAnalysis, RiskLevel
from typing import List
import time
import asyncio

class ContentAnalyzer:
    def __init__(self):
        self.url_extractor = url_extractor
        self.url_analyzer = url_analyzer
        self.gemini_client = gemini_client
    
    async def analyze_email(self, scan_request: ScanRequest) -> ScanResponse:
        """Main analysis pipeline"""
        start_time = time.time()
        
        try:
            print(f"Starting analysis for: {scan_request.subject}")
            
            # Step 1: Extract URLs
            print("Extracting URLs...")
            urls = self.url_extractor.extract_urls(scan_request.content)
            print(f"Found {len(urls)} URLs: {urls}")
            
            # Step 2: Analyze URLs
            print("Analyzing URLs...")
            url_scan_results = await self.url_analyzer.analyze_urls(urls)
            print(f"URL analysis completed: {len(url_scan_results)} results")
            
            # Step 3: Comprehensive analysis with Gemini
            print("Starting Gemini analysis...")
            
            # Use run_in_executor to handle sync Gemini call in async context
            gemini_analysis = await asyncio.get_event_loop().run_in_executor(
                None,
                self.gemini_client.analyze_email,
                scan_request.subject,
                scan_request.content,
                url_scan_results
            )
            
            processing_time = time.time() - start_time
            print(f"Total processing time: {processing_time:.2f}s")
            
            return ScanResponse(
                analysis=gemini_analysis,
                url_scan_results=url_scan_results,
                processing_time=round(processing_time, 2)
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            print(f"Analysis error: {e}")
            import traceback
            traceback.print_exc()
            
            # Return error response
            error_analysis = GeminiAnalysis(
                threat_score=50,
                risk_level=RiskLevel.SUSPICIOUS,
                detailed_analysis=f"Analysis failed: {str(e)}",
                url_breakdown=[],
                behavioral_analysis="Unable to complete analysis due to error",
                recommendations=["Please try again later", "Exercise caution with this email"],
                confidence=0.0
            )
            
            return ScanResponse(
                analysis=error_analysis,
                url_scan_results=[],
                processing_time=round(processing_time, 2)
            )

content_analyzer = ContentAnalyzer()