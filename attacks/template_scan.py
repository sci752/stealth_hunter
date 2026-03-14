import time
import logging
from core.models import ScanResult, Severity
from core.http_client import session
from rate_limiter import limiter
import config

logger = logging.getLogger("TemplateScanner")


def execute(target: str) -> ScanResult:
    """
    Master Template for Custom Attack Modules.
    Duplicate this file whenever you want to build a new vulnerability scanner.

    Best practices demonstrated:
    1. Timing measured only around the HTTP request (not setup overhead)
    2. Shared session for connection pooling (core.http_client)
    3. WAF evasion via rate limiter integration
    4. Granular exception handling
    5. Structured ScanResult return contract

    Args:
        target (str): Target URL to scan (e.g., "https://example.com")

    Returns:
        ScanResult: Structured result object.
    """
    module_name = "Template_Vulnerability_Scanner"

    try:
        logger.debug(f"[{module_name}] Starting scan against {target}")

        clean_target = target.rstrip("/")
        attack_url = f"{clean_target}/api/vulnerable_endpoint"

        logger.debug(f"[{module_name}] Attack URL: {attack_url}")

        # Start timing AFTER setup, only for the actual HTTP request
        start_time = time.time()

        try:
            # Use the shared session (connection pool) instead of requests.get()
            response = session.get(
                attack_url,
                timeout=config.REQUEST_TIMEOUT_SECONDS,
            )

            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.debug(f"[{module_name}] Request completed in {execution_time}ms")

            # WAF & Rate Limit Evasion: trigger global backoff on 429/503
            if response.status_code in [429, 503]:
                logger.warning(
                    f"[{module_name}] WAF/Rate Limit detected "
                    f"(HTTP {response.status_code}). Triggering global backoff."
                )
                limiter.trigger_backoff(
                    reason=f"WAF Block on {module_name} ({response.status_code})"
                )
                return ScanResult(
                    is_vulnerable=False,
                    module_name=module_name,
                    severity=Severity.INFO,
                    description=f"Target returned HTTP {response.status_code}. Rate limited.",
                    execution_time_ms=execution_time,
                    metadata={"status_code": response.status_code, "blocked": True},
                )

            # Vulnerability Detection Logic
            if response.status_code == 200 and "sensitive_data_leak" in response.text:
                logger.critical(f"[{module_name}] VULNERABILITY FOUND!")
                return ScanResult(
                    is_vulnerable=True,
                    module_name=module_name,
                    severity=Severity.HIGH,
                    description="Successfully detected a custom vulnerability using the template.",
                    evidence=f"[HTTP 200] Response snippet: {response.text[:150]}",
                    payload_used=attack_url,
                    execution_time_ms=execution_time,
                    metadata={
                        "attack_type": "Custom Check",
                        "payload_used": attack_url,
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                    },
                )

            logger.debug(f"[{module_name}] No vulnerability detected")
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description="Target is secure against this custom check.",
                execution_time_ms=execution_time,
                metadata={
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                },
            )

        except TimeoutError:
            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"[{module_name}] Request timed out after {config.REQUEST_TIMEOUT_SECONDS}s")
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description=f"Request timeout after {config.REQUEST_TIMEOUT_SECONDS}s",
                execution_time_ms=execution_time,
                metadata={"error": "timeout"},
            )

        except ConnectionError as conn_err:
            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"[{module_name}] Connection error: {conn_err}")
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description=f"Connection error: {str(conn_err)[:100]}",
                execution_time_ms=execution_time,
                metadata={"error": "connection_error"},
            )

        except Exception as req_err:
            execution_time = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"[{module_name}] Request failed: {req_err}")
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                severity=Severity.INFO,
                description=f"Request failed: {str(req_err)[:100]}",
                execution_time_ms=execution_time,
                metadata={"error": "request_exception"},
            )

    except Exception as unexpected_err:
        logger.error(
            f"[{module_name}] Unexpected error: "
            f"{type(unexpected_err).__name__}: {unexpected_err}",
            exc_info=config.LOG_FULL_TRACEBACK,
        )
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            severity=Severity.INFO,
            description=f"Unexpected error: {type(unexpected_err).__name__}",
            execution_time_ms=0.0,
            metadata={"error": type(unexpected_err).__name__},
        )
 
