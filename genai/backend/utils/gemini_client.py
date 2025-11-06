import google.generativeai as genai
from config import settings
from models.schemas import GeminiAnalysis, RiskLevel, URLScanResult
from typing import List
import json
import re

class GeminiClient:
    def __init__(self):
        try:
            if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "your_gemini_api_key_here":
                print("Warning: Gemini API key not configured")
                self.model = None
                return
                
            genai.configure(api_key=settings.GEMINI_API_KEY)
            
            # List available models to see what's supported
            try:
                models = genai.list_models()
                available_models = [model.name for model in models]
                print(f"Available Gemini models: {available_models}")
                
                # Try the latest models first
                preferred_models = [
                    'models/gemini-2.0-flash',  # Latest flash model
                    'models/gemini-1.5-flash',  # Previous flash model
                    'models/gemini-1.5-pro',    # Pro version with larger context
                    'models/gemini-1.0-pro',    # Original pro model
                    'models/gemini-pro',        # Legacy name
                ]
                
                self.model = None
                for model_name in preferred_models:
                    if model_name in available_models:
                        try:
                            self.model = genai.GenerativeModel(model_name)
                            print(f"Using model: {model_name}")
                            break
                        except Exception as e:
                            print(f"Failed to initialize {model_name}: {e}")
                            continue
                
                if not self.model:
                    # Fallback: use any available model that supports generateContent
                    for model_name in available_models:
                        try:
                            model_info = genai.get_model(model_name)
                            if 'generateContent' in model_info.supported_generation_methods:
                                self.model = genai.GenerativeModel(model_name)
                                print(f"Using available model: {model_name}")
                                break
                        except Exception as e:
                            print(f"Failed to initialize {model_name}: {e}")
                            continue
                
                if not self.model:
                    print("No suitable Gemini model found for content generation")
                    
            except Exception as e:
                print(f"Error listing models: {e}")
                # Fallback to trying the latest model directly
                try:
                    self.model = genai.GenerativeModel('gemini-2.0-flash')
                    print("Using model: gemini-2.0-flash (direct)")
                except Exception as e2:
                    print(f"Direct model initialization failed: {e2}")
                    self.model = None
                        
        except Exception as e:
            print(f"Error initializing Gemini client: {e}")
            self.model = None
    
    def analyze_email(self, subject: str, content: str, url_results: List[URLScanResult]) -> GeminiAnalysis:
        """Analyze email content with Gemini"""
        
        if not self.model:
            return self._create_fallback_analysis(subject, content, url_results, "Gemini model not available")
        
        try:
            # Prepare URL analysis summary
            url_analysis = self._prepare_url_analysis(url_results)
            
            # Create comprehensive system prompt
            prompt = self._create_analysis_prompt(subject, content, url_analysis)
            
            print("Sending request to Gemini...")
            generation_config = {
                "temperature": 0.1,  # Low temperature for consistent results
                "top_p": 0.8,
                "top_k": 40,
                "max_output_tokens": 2048,  # Increased for detailed analysis
            }
            
            safety_settings = [
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH", 
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE"
                }
            ]
            
            response = self.model.generate_content(
                prompt,
                generation_config=generation_config,
                safety_settings=safety_settings
            )
            analysis_text = response.text
            
            print("Received response from Gemini, parsing...")
            # Extract JSON from response
            json_str = self._extract_json(analysis_text)
            analysis_data = json.loads(json_str)
            
            # Validate and clean the response
            validated_data = self._validate_analysis_data(analysis_data)
            
            print("Gemini analysis completed successfully")
            return GeminiAnalysis(**validated_data)
            
        except Exception as e:
            print(f"Gemini analysis error: {e}")
            return self._create_fallback_analysis(subject, content, url_results, str(e))
    
    def _prepare_url_analysis(self, url_results: List[URLScanResult]) -> str:
        """Prepare URL analysis summary for the prompt"""
        if not url_results:
            return "No URLs found in email content"
        
        analysis_lines = ["URL SCAN RESULTS:"]
        
        for i, result in enumerate(url_results, 1):
            # VirusTotal information
            vt_info = "No data available"
            if result.virustotal_result:
                if result.virustotal_result.get('data'):
                    vt_data = result.virustotal_result['data']
                    # Handle different data structures
                    if isinstance(vt_data, dict):
                        if 'data' in vt_data and 'attributes' in vt_data['data']:
                            stats = vt_data['data']['attributes'].get('last_analysis_stats', {})
                            malicious_count = stats.get('malicious', 0)
                            suspicious_count = stats.get('suspicious', 0)
                            total_engines = sum(stats.values())
                            vt_info = f"Malicious: {malicious_count}/{total_engines}, Suspicious: {suspicious_count}/{total_engines}"
                        elif 'attributes' in vt_data:
                            stats = vt_data['attributes'].get('last_analysis_stats', {})
                            malicious_count = stats.get('malicious', 0)
                            suspicious_count = stats.get('suspicious', 0)
                            total_engines = sum(stats.values())
                            vt_info = f"Malicious: {malicious_count}/{total_engines}, Suspicious: {suspicious_count}/{total_engines}"
                        else:
                            vt_info = "Data format unexpected"
                elif result.virustotal_result.get('error'):
                    vt_info = f"Scan failed: {result.virustotal_result['error'][:100]}..."
            
            # PhishingArmy information
            phishing_army = "BLOCKED" if result.phishing_army_result else "Not found"
            
            # URL risk assessment
            risk_assessment = self._get_risk_assessment_description(result.risk_level)
            
            analysis_lines.append(
                f"{i}. URL: {result.url}\n"
                f"   - VirusTotal: {vt_info}\n"
                f"   - PhishingArmy: {phishing_army}\n"
                f"   - Risk Level: {result.risk_level.value.upper()}\n"
                f"   - Assessment: {risk_assessment}\n"
            )
        
        return "\n".join(analysis_lines)
    
    def _get_risk_assessment_description(self, risk_level: RiskLevel) -> str:
        """Get descriptive assessment for risk level"""
        descriptions = {
            RiskLevel.SAFE: "No significant threats detected",
            RiskLevel.SUSPICIOUS: "Potential security concerns, exercise caution",
            RiskLevel.MALICIOUS: "High confidence of malicious intent"
        }
        return descriptions.get(risk_level, "Unknown risk level")
    
    def _create_analysis_prompt(self, subject: str, content: str, url_analysis: str) -> str:
        """Create the comprehensive analysis prompt"""
        return f""" You are an expert cybersecurity analyst specializing in email security and phishing detection. Your analysis must be logical, balanced, and avoid false positives.
EMAIL SUBJECT: {subject}
EMAIL CONTENT: {content}
URL SECURITY SCAN RESULTS: {url_analysis}

**CORE ANALYSIS PRINCIPLES:**
1. Avoid Single-Indicator Bias: Do not classify an email as malicious based on one indicator alone. Legitimate emails can contain urgency (e.g., "Sale ends today") or generic greetings. Your assessment must be holistic.

2. Actively Search for Legitimacy: Before flagging, actively search for evidence of a legitimate email. This includes:
    - Transactional content (e.g., purchase receipts, shipping notifications, legitimate account alerts).
    - Consistent sender domain, branding, and tone.
    - URLs that point to the correct, known domain for the purported sender.

3. Context is Critical: Analyze indicators in context. A "Reset Password" link is expected in a password reset email but highly suspicious in an unsolicited invoice. Manytimes, sensitive links like reset password and account deletion request are sent by the legitimate organizations to fulfil the requirements. So, don't get confused in this case, don't just increase the threat score only because it has reset password link.

4. Weighted Scoring: The threat_score must be a weighted balance of all factors. Strong evidence of legitimacy (like a known-good domain and expected content) should significantly lower the score, even if minor suspicious elements (like a generic greeting) are present. Only mark the mail as malicious or suspicious, if anything malicious found in email, other wise it should be marked as legitimate with low threat score.


**ANALYSIS REQUIREMENTS:**

1. Threat Assessment:
    - Threat Score (0-100): 0-30=safe, 31-70=suspicious, 71-100=malicious
    - Overall Risk Level: "safe", "suspicious", or "malicious"
    - Confidence Percentage (0-100%): How confident you are in this assessment

2. Detailed Content Analysis:
    - Phishing indicators (urgency, authority, grammar) vs. Legitimacy indicators (transactional details, consistent branding).
    - Social engineering tactics used (if any).
    - Content inconsistencies and red flags (or lack thereof).
    - Language patterns (Is it typical for this sender? Is it overly generic?).

3. URL Analysis Breakdown:
    - Known-Good Domain Recognition: Explicitly identify and treat known, reputable domains as "safe" by default (e.g., google.com, microsoft.com, myntra.com, or any verifiable corporate domain).
    - Specific Risk Factors: Only flag a known-good domain if:
        - The {url_analysis} input explicitly confirms a payload, malware, or known phishing link.
        - It's a lookalike/typosquatted domain (e.g., micros**o0**ft.com).
        - The link text is deceptive (e.g., text is google.com but URL is g00gle.biz).

    - Contextual Risk: Does the URL's destination match the email's context? (e.g., a link to google.com in a "Microsoft Account" email is suspicious).

4. Behavioral Analysis:
    - Psychological manipulation techniques (if present).
    - Intended victim response/action.
    - Attack sophistication (low = generic spam, high = targeted spear-phishing).

5. Security Recommendations:
    - Immediate actions for the recipient (e.g., "This email is safe," "Delete this email," "Verify with sender").
    - Preventive measures (if suspicious or malicious).

**OUTPUT FORMAT (JSON ONLY):**
{{ "threat_score": 75, "risk_level": "malicious", "detailed_analysis": "Comprehensive analysis covering all security aspects...", "url_breakdown": [ {{ "url": "http://example.com", "risk_factors": ["brand_impersonation", "suspicious_domain", "urgency_context"], "assessment": "Detailed analysis of this specific URL...", "confidence": 85.0 }} ], "behavioral_analysis": "Analysis of psychological tactics and attacker behavior patterns...", "recommendations": [ "Do not click any links in this email", "Verify sender through official channels", "Report as phishing to security team" ], "confidence": 90.5 }}

**CRITICAL CONSTRAINTS:**
    - Respond with ONLY valid JSON, no additional text
    - Concise Analysis: All descriptive fields (detailed_analysis, behavioral_analysis, assessment) must be precise and brief. Focus on the most critical evidence.
    - threat_score: integer between 0-100
    - risk_level: exactly "safe", "suspicious", or "malicious"
    - confidence: float between 0.0-100.0
    - Base assessment on the balance of evidence from the email content and URL scan results, not just on the presence of suspicious keywords. """
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from Gemini response"""
        try:
            # Remove markdown code blocks if present
            text = text.replace('```json', '').replace('```', '').strip()
            
            # Find JSON object using regex
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                return json_match.group()
            
            # If no match, try to clean and parse directly
            return text.strip()
        except Exception as e:
            print(f"Error extracting JSON: {e}")
            raise
    
    def _validate_analysis_data(self, data: dict) -> dict:
        """Validate and clean the analysis data from Gemini"""
        # Ensure all required fields are present
        required_fields = {
            "threat_score": 50,
            "risk_level": "suspicious", 
            "detailed_analysis": "Analysis completed with some limitations",
            "url_breakdown": [],
            "behavioral_analysis": "Behavioral analysis not available",
            "recommendations": ["Exercise caution", "Verify email authenticity"],
            "confidence": 70.0
        }
        
        validated = {}
        
        for field, default in required_fields.items():
            if field in data and data[field] is not None:
                validated[field] = data[field]
            else:
                validated[field] = default
        
        # Validate specific field types and ranges
        validated["threat_score"] = max(0, min(100, int(validated["threat_score"])))
        validated["confidence"] = max(0.0, min(100.0, float(validated["confidence"])))
        
        # Ensure risk_level is valid
        valid_risk_levels = ["safe", "suspicious", "malicious"]
        if validated["risk_level"] not in valid_risk_levels:
            validated["risk_level"] = "suspicious"
        
        # Ensure url_breakdown is a list
        if not isinstance(validated["url_breakdown"], list):
            validated["url_breakdown"] = []
        
        # Ensure recommendations is a list
        if not isinstance(validated["recommendations"], list):
            validated["recommendations"] = ["Verify email authenticity"]
        
        return validated
    
    def _create_fallback_analysis(self, subject: str, content: str, url_results: List[URLScanResult], error: str = "Unknown error") -> GeminiAnalysis:
        """Create fallback analysis when Gemini fails"""
        print(f"Creating fallback analysis due to: {error}")
        
        # Calculate basic threat score based on URL results and content heuristics
        base_threat_score = 30
        
        # Increase threat score based on URL risks
        malicious_urls = [url for url in url_results if url.risk_level == RiskLevel.MALICIOUS]
        suspicious_urls = [url for url in url_results if url.risk_level == RiskLevel.SUSPICIOUS]
        
        if malicious_urls:
            base_threat_score = 85
        elif suspicious_urls:
            base_threat_score = 60
        
        # Increase threat score based on content heuristics
        suspicious_indicators = self._check_content_heuristics(subject, content)
        base_threat_score += len(suspicious_indicators) * 5
        base_threat_score = min(95, base_threat_score)
        
        # Determine risk level
        if base_threat_score >= 70:
            risk_level = RiskLevel.MALICIOUS
        elif base_threat_score >= 40:
            risk_level = RiskLevel.SUSPICIOUS
        else:
            risk_level = RiskLevel.SAFE
        
        # Create URL breakdown
        url_breakdown = []
        for url_result in url_results:
            url_breakdown.append({
                "url": url_result.url,
                "risk_factors": self._get_url_risk_factors(url_result),
                "assessment": f"Risk level: {url_result.risk_level.value}. PhishingArmy: {'Blocked' if url_result.phishing_army_result else 'Not found'}",
                "confidence": 70.0
            })
        
        return GeminiAnalysis(
            threat_score=base_threat_score,
            risk_level=risk_level,
            detailed_analysis=f"Automated analysis (Gemini unavailable: {error}). Based on URL scanning and basic heuristics: {', '.join(suspicious_indicators) if suspicious_indicators else 'No strong indicators'}",
            url_breakdown=url_breakdown,
            behavioral_analysis="Limited analysis available. Exercise caution with urgent requests and verify sender authenticity.",
            recommendations=[
                "Verify sender through official channels",
                "Do not click suspicious links",
                "Check for brand impersonation",
                "Report suspicious emails to security team"
            ],
            confidence=65.0
        )
    
    def _check_content_heuristics(self, subject: str, content: str) -> List[str]:
        """Check for common phishing indicators in content"""
        indicators = []
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediately', 'asap', 'within hours', '24 hours', 'instant', 'right away', 'emergency']
        if any(word in subject.lower() or word in content.lower() for word in urgency_words):
            indicators.append("urgency_tactics")
        
        # Authority indicators
        authority_words = ['security team', 'admin', 'support', 'verify', 'validation', 'account suspension', 'compliance']
        if any(word in content.lower() for word in authority_words):
            indicators.append("authority_claims")
        
        # Action demands
        action_words = ['click here', 'click below', 'verify now', 'act now', 'confirm immediately', 'respond now']
        if any(word in content.lower() for word in action_words):
            indicators.append("action_demands")
        
        # Brand mentions without proper context
        brands = ['amazon', 'paypal', 'microsoft', 'apple', 'google', 'bank', 'financial', 'netflix', 'facebook']
        brand_mentions = [brand for brand in brands if brand in content.lower()]
        if brand_mentions:
            indicators.append("brand_references")
        
        # Negative consequences
        negative_words = ['suspend', 'close', 'terminate', 'lock', 'restrict', 'penalty', 'fine']
        if any(word in content.lower() for word in negative_words):
            indicators.append("negative_consequences")
        
        return indicators
    
    def _get_url_risk_factors(self, url_result: URLScanResult) -> List[str]:
        """Get risk factors for a URL result"""
        risk_factors = []
        
        if url_result.phishing_army_result:
            risk_factors.append("phishing_database_match")
        
        if url_result.risk_level == RiskLevel.MALICIOUS:
            risk_factors.append("high_confidence_malicious")
        elif url_result.risk_level == RiskLevel.SUSPICIOUS:
            risk_factors.append("suspicious_indicators")
        
        # Check for brand impersonation in URL
        url_lower = url_result.url.lower()
        brands = ['amazon', 'paypal', 'microsoft', 'apple', 'google', 'bank', 'security', 'verify', 'login']
        for brand in brands:
            if brand in url_lower and f"{brand}.com" not in url_lower:
                risk_factors.append("brand_impersonation")
                break
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online']
        if any(tld in url_lower for tld in suspicious_tlds):
            risk_factors.append("suspicious_tld")
        
        # Check for hyphens in domain (common in phishing)
        from urllib.parse import urlparse
        try:
            domain = urlparse(url_result.url).netloc
            if domain.count('-') > 2:
                risk_factors.append("suspicious_domain_structure")
        except:
            pass
        
        return risk_factors if risk_factors else ["requires_further_analysis"]

gemini_client = GeminiClient()