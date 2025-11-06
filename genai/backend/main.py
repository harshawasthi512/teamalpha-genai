from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from models.schemas import ScanRequest, ScanResponse
from services.content_analyzer import content_analyzer
from services.database import phishing_db
import uvicorn

app = FastAPI(
    title="Email Security Scanner API",
    description="Advanced email security analysis with URL scanning and AI content analysis",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your extension's origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) 

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    try:
        # Use asyncio to run the async initialization
        asyncio.create_task(initialize_database())
    except Exception as e:
        print(f"Startup error: {e}")

async def initialize_database():
    """Async database initialization"""
    try:
        if await phishing_db.should_update():
            print("Performing initial PhishingArmy database update...")
            await phishing_db.update_phishing_domains()
        else:
            count = await phishing_db.get_domain_count()
            print(f"Phishing database ready with {count} domains")
    except Exception as e:
        print(f"Database initialization error: {e}")

@app.get("/")
async def root():
    return {"message": "Email Security Scanner API", "status": "running"}

@app.get("/test-gemini")
async def test_gemini():
    """Test endpoint to check if Gemini is working"""
    try:
        from utils.gemini_client import gemini_client
        from models.schemas import URLScanResult, RiskLevel
        
        # Create a simple test
        test_urls = [
            URLScanResult(
                url="https://google.com",
                virustotal_result=None,
                phishing_army_result=False,
                risk_level=RiskLevel.SAFE
            )
        ]
        
        result = gemini_client.analyze_email(
            subject="Test Email",
            content="This is a safe test email with no threats.",
            url_results=test_urls
        )
        
        return {
            "status": "success",
            "gemini_working": True,
            "result": result.dict()
        }
    except Exception as e:
        return {
            "status": "error",
            "gemini_working": False,
            "error": str(e)
        }

@app.get("/debug/models")
async def debug_models():
    """Debug endpoint to check available Gemini models"""
    try:
        import google.generativeai as genai
        if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "your_gemini_api_key_here":
            return {"error": "Gemini API key not configured"}
        
        genai.configure(api_key=settings.GEMINI_API_KEY)
        models = genai.list_models()
        
        available_models = []
        for model in models:
            model_info = {
                "name": model.name,
                "display_name": model.display_name,
                "description": model.description,
                "supported_methods": model.supported_generation_methods
            }
            available_models.append(model_info)
        
        return {
            "available_models": available_models,
            "total_models": len(available_models)
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/health")
async def health_check():
    """Health check with database status"""
    try:
        domain_count = await phishing_db.get_domain_count()
        last_update = await phishing_db.get_last_update_info()
        return {
            "status": "healthy", 
            "service": "email-scanner",
            "phishing_domains": domain_count,
            "last_update": last_update
        }
    except Exception as e:
        return {"status": "degraded", "error": str(e)}

@app.post("/scan", response_model=ScanResponse)
async def scan_email(scan_request: ScanRequest):
    """
    Analyze email for security threats
    
    - **subject**: Email subject
    - **content**: Email body content
    """
    try:
        print(f"Received scan request for subject: {scan_request.subject}")
        result = await content_analyzer.analyze_email(scan_request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/admin/update-phishing-db")
async def update_phishing_database(background_tasks: BackgroundTasks):
    """Manually trigger phishing database update"""
    background_tasks.add_task(phishing_db.update_phishing_domains)
    return {"message": "Phishing database update started in background"}

@app.get("/admin/db-status")
async def get_db_status():
    """Get database status information"""
    try:
        domain_count = await phishing_db.get_domain_count()
        last_update = await phishing_db.get_last_update_info()
        needs_update = await phishing_db.should_update()
        
        return {
            "domain_count": domain_count,
            "last_update": last_update,
            "needs_update": needs_update
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting DB status: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)