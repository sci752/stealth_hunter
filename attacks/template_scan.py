import time
import requests
from core.models import ScanResult, Severity
from rate_limiter import limiter

def execute(target: str) -> ScanResult:
    """
    Master Template for Custom Attack Modules.
    Duplicate this file whenever you want to build a new vulnerability scanner.
    """
    # Name your module (this will show up in the terminal HUD and JSON reports)
    module_name = "Template_Vulnerability_Scanner"
    start_time = time.time()
    
    # 1. Prepare your attack vector
    clean_target = target.rstrip('/')
    attack_url = f"{clean_target}/api/vulnerable_endpoint"
    
    try:
        # 2. Fire the request with a strict timeout to prevent the orchestrator from hanging
        response = requests.get(attack_url, timeout=5)
        
        # 3. WAF & Rate Limit Evasion Logic
        # If the target is choking or actively blocking us, trigger the global framework backoff
        if response.status_code in [429, 503]:
            limiter.trigger_backoff(reason=f"WAF Block on {module_name}")
            
        execution_time = round((time.time() - start_time) * 1000, 2)
        
        # 4. Vulnerability Detection Logic (Modify this block for your specific bug)
        # Check if the response is successful AND contains expected sensitive keys/errors
        if response.status_code == 200 and "sensitive_data_leak" in response.text:
            
            # RETURN THE TRIGGER: This instantly halts the orchestrator and saves evidence
            return ScanResult(
                is_vulnerable=True,
                module_name=module_name,
                severity=Severity.HIGH,  # Choose CRITICAL, HIGH, MEDIUM, LOW, or INFO
                description="Successfully detected a custom vulnerability using the template.",
                evidence=f"[HTTP 200] Response snippet: {response.text[:150]}",
                execution_time_ms=execution_time,
                metadata={
                    "attack_type": "Custom Check", 
                    "payload_used": attack_url,
                    "status_code": response.status_code
                }
            )
            
        # 5. Safe Return
        # If nothing is found, return a clean result so the orchestrator moves to the next module
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Target is secure against this custom check.",
            execution_time_ms=execution_time
        )
        
    except requests.exceptions.RequestException as e:
        # 6. Graceful Fault Tolerance
        # Catch connection timeouts or DNS errors without crashing the main framework
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Request failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2)
      )
      
