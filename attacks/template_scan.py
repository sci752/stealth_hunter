import time
import logging
import requests
from core.models import ScanResult, Severity
from rate_limiter import limiter
import config

# Setup logging
logger = logging.getLogger("TemplateScanner")


def execute(target: str) -> ScanResult:
    """
    Master Template for Custom Attack Modules.
    Duplicate this file whenever you want to build a new vulnerability scanner.
    
    This template demonstrates best practices:
    1. Proper timing measurement (only request time, not setup)
    2. WAF evasion with rate limiter integration
    3. Structured error handling
    4. Logging for observability
    5. Clean ScanResult return contract
    
    Args:
        target (str): Target URL to scan (e.g., "https://example.com")
    
    Returns:
        ScanResult: Structured result object containing vulnerability status, details, and evidence.
    """
    
    # Name your module (this will show up in logs and JSON reports)
    module_name = "Template_Vulnerability_Scanner"
    
    try:
        logger.debug(f"[{module_name}] Starting scan against {target}")
        
        # 1. Prepare your attack vector
        clean_target = target.rstrip('/')
        attack_url = f"{clean_target}/api/vulnerable_endpoint"
        
        logger.debug(f"[{module_name}] Prepared attack URL: {attack_url}")
        
        # 2. IMPORTANT: Start timing AFTER setup, only for the actual request
        start_time = time.time()
        
        try:
            # Fire the request with a strict timeout to prevent the orchestrator from hanging
            response = requests.get(
                attack_url,
                timeout=config.REQUEST_TIMEOUT_SECONDS,
                headers={
                    "User-Agent": config.DEFAULT_USER_AGENT,
                    "Accept": "application/json"
                }
            )
            
            # 3. Calculate execution time (only the request, not setup)
            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.debug(f"[{module_name}] Request completed in {execution_time}ms")
            
            # 4. WAF & Rate Limit Evasion Logic
            # If the target is choking or actively blocking us, trigger the global framework backoff
            if response.status_code in [429, 503]:
                logger.warning(
                    f"[{module_name}] WAF/Rate Limit detected (HTTP {response.status_code}). "
                    f"Triggering global backoff."
                )
                limiter.trigger_backoff(reason=f"WAF Block on {module_name} ({response.status_code})")
                
                # Return clean result so orchestrator can continue with adjusted rate
                return ScanResult(
                    is_vulnerable=False,
                    module_name=module_name,
                    severity=Severity.INFO,
                    description=f"Target returned HTTP {response.status_code}. Rate limited.",
                    execution_time_ms=execution_time,
                    metadata={"status_code": response.status_code, "blocked": True}
                )
            
            logger.debug(f"[{module_name}] Response status: {response.status_code}")
            
            # 5. Vulnerability Detection Logic
            # Check if the response is successful AND contains expected sensitive keys/errors
            if response.status_code == 200 and "sensitive_data_leak" in response.text:
                
                logger.critical(f"[{module_name}] VULNERABILITY FOUND!")
                
                # RETURN THE TRIGGER: This instantly halts the orchestrator and saves evidence
                return ScanResult(
                    is_vulnerable=True,
                    module_name=module_name,
                    severity=Severity.HIGH,  # Choose CRITICAL, HIGH, MEDIUM, LOW, or INFO
                    description="Successfully detected a custom vulnerability using the template.",
                    evidence=f"[HTTP 200] Response snippet: {response.text[:150]}",
                    payload_used=attack_url,
                    execution_time_ms=execution_time,
                    metadata={
                        "attack_type": "Custom Check",
                        "payload_used": attack_url,
                        "status_code": response.status_code,
                        "response_length": len(response.text)
                    }
                )
            
            logger.debug(f"[{module_name}] No vulnerability detected")
            
            # 6. Safe Return
            # If nothing is found, return a clean result so the orchestrator moves to the next module
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description="Target is secure against this custom check.",
                execution_time_ms=execution_time,
                metadata={
                    "status_code": response.status_code,
                    "response_length": len(response.text)
                }
            )
        
        except requests.exceptions.Timeout as timeout_err:
            # 7. Graceful Fault Tolerance - Network Timeout
            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.warning(
                f"[{module_name}] Request timeout after {config.REQUEST_TIMEOUT_SECONDS}s: {timeout_err}"
            )
            
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description=f"Request timeout after {config.REQUEST_TIMEOUT_SECONDS}s",
                execution_time_ms=execution_time,
                metadata={"error": "timeout"}
            )
        
        except requests.exceptions.ConnectionError as conn_err:
            # 8. Graceful Fault Tolerance - Connection Error
            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"[{module_name}] Connection error: {conn_err}")
            
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description=f"Connection error: {str(conn_err)[:100]}",
                execution_time_ms=execution_time,
                metadata={"error": "connection_error"}
            )
        
        except requests.exceptions.RequestException as req_err:
            # 9. Graceful Fault Tolerance - Other Request Errors
            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"[{module_name}] Request failed: {req_err}")
            
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description=f"Request failed: {str(req_err)[:100]}",
                execution_time_ms=execution_time,
                metadata={"error": "request_exception"}
            )
    
    except Exception as unexpected_err:
        # 10. Unexpected Error Handler
        execution_time = round((time.time() - start_time) * 1000, 2)
        logger.error(
            f"[{module_name}] Unexpected error: {type(unexpected_err).__name__}: {unexpected_err}",
            exc_info=config.LOG_FULL_TRACEBACK
        )
        
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            severity=Severity.INFO,
            description=f"Unexpected error: {type(unexpected_err).__name__}",
            execution_time_ms=execution_time,
            metadata={"error": type(unexpected_err).__name__}
        )
