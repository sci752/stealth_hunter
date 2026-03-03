import time
import requests
from core.models import ScanResult, Severity
from rate_limiter import limiter

def execute(target: str) -> ScanResult:
    module_name = "Domain_Takeover_Scanner"
    start_time = time.time()
    
    # Fingerprints of vulnerable, unclaimed cloud providers
    signatures = {
        "GitHub Pages": "There isn't a GitHub Pages site here.",
        "Heroku": "No such app",
        "AWS S3": "The specified bucket does not exist",
        "Azure": "project not found",
        "Fastly": "Fastly error: unknown domain",
        "Ghost": "The thing you were looking for is no longer here"
    }
    
    try:
        # We enforce a strict timeout to avoid hanging on dead DNS records
        response = requests.get(target, timeout=7)
        
        # WAF/Rate Limit Evasion Trigger
        if response.status_code in [429, 503]:
            limiter.trigger_backoff(reason=f"WAF Block on {module_name}")
            
        execution_time = round((time.time() - start_time) * 1000, 2)
        
        # Detection Logic: Check the response body for known unclaimed resource signatures
        for provider, signature in signatures.items():
            if signature in response.text:
                return ScanResult(
                    is_vulnerable=True,
                    module_name=module_name,
                    severity=Severity.CRITICAL,
                    description=f"Dangling DNS record detected. The domain points to an unclaimed {provider} service, allowing for immediate Subdomain Takeover.",
                    evidence=f"[HTTP {response.status_code}] Provider Signature Match: {provider}",
                    execution_time_ms=execution_time,
                    metadata={"attack_type": "Subdomain Takeover", "provider": provider}
                )
                
        # If no signatures match, the backend is likely secure and claimed
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Domain backend active and securely claimed.",
            execution_time_ms=execution_time
        )
        
    except requests.exceptions.RequestException as e:
        # Gracefully handle domains that fail to resolve entirely
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Domain resolution or connection failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2)
        )
      
