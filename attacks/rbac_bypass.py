import time
import requests
from core.models import ScanResult, Severity
from core.auth_manager import auth
from rate_limiter import limiter

def execute(target: str) -> ScanResult:
    """
    Business Logic Scanner: RBAC Privilege Escalation.
    Attempts to access restricted admin endpoints using a standard user's JWT.
    """
    module_name = "RBAC_Privilege_Escalation"
    start_time = time.time()
    
    # 1. Fetch low-privileged headers from the Auth Manager
    user_headers = auth.get_headers(role="user")
    
    # If no user token is loaded in your .env, skip the module safely
    if "Authorization" not in user_headers:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Skipped: No user-level JWT provided in environment variables.",
            execution_time_ms=round((time.time() - start_time) * 1000, 2)
        )

    clean_target = target.rstrip('/')
    
    # A common administrative endpoint that should strictly require an Admin JWT
    restricted_endpoint = f"{clean_target}/api/admin/dashboard_data"
    
    try:
        # 2. Fire the request using the lowly user's credentials
        response = requests.get(restricted_endpoint, headers=user_headers, timeout=5)
        
        # WAF Evasion
        if response.status_code in [429, 503]:
            limiter.trigger_backoff(reason=f"WAF Block on {module_name}")
            
        execution_time = round((time.time() - start_time) * 1000, 2)
        
        # 3. Detection Logic: 
        # If the server returns 200 OK and sensitive data instead of a 401/403, the tenant isolation is broken.
        if response.status_code == 200 and "total_revenue" in response.text.lower():
            return ScanResult(
                is_vulnerable=True,
                module_name=module_name,
                severity=Severity.CRITICAL,
                description="Zero-Trust failure. A low-privileged User JWT successfully accessed an Admin-only endpoint.",
                evidence=f"[HTTP 200] Headers sent: {user_headers} | Response: {response.text[:150]}",
                execution_time_ms=execution_time,
                metadata={"attack_type": "IDOR / Broken Access Control", "endpoint": restricted_endpoint}
            )
            
        # The system correctly blocked the user
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"RBAC intact. User token was correctly denied access (HTTP {response.status_code}).",
            execution_time_ms=execution_time
        )
        
    except requests.exceptions.RequestException as e:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Request failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2)
  )
          
