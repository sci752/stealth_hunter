import trt 
from core.models import ScanResult, Severityfrom core.http_client import session
from rate_limiter import limiter
import config


def execute(target: str) -> ScanResult:
    """
    Subdomain Takeover Scanner.
    Checks if the target domain points to an unclaimed cloud service resource.
    """
    module_name = "Domain_Takeover_Scanner"
    start_time = time.time()

    # Fingerprints of known unclaimed cloud provider error pages
    signatures = {
        "GitHub Pages": "There isn't a GitHub Pages site here.",
        "Heroku": "No such app",
        "AWS S3": "The specified bucket does not exist",
        "Azure": "project not found",
        "Fastly": "Fastly error: unknown domain",
        "Ghost": "The thing you were looking for is no longer here",
    }

    try:
        # FIX: was hardcoded timeout=7, now uses config.REQUEST_TIMEOUT_SECONDS
        # FIX: uses shared session (connection pooling) instead of requests.get()
        response = session.get(target, timeout=config.REQUEST_TIMEOUT_SECONDS)

        if response.status_code in [429, 503]:
            limiter.trigger_backoff(reason=f"WAF Block on {module_name}")

        execution_time = round((time.time() - start_time) * 1000, 2)

        for provider, signature in signatures.items():
            if signature in response.text:
                return ScanResult(
                    is_vulnerable=True,
                    module_name=module_name,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Dangling DNS record detected. The domain points to an unclaimed "
                        f"{provider} service, allowing immediate Subdomain Takeover."
                    ),
                    evidence=f"[HTTP {response.status_code}] Provider Signature Match: {provider}",
                    execution_time_ms=execution_time,
                    metadata={"attack_type": "Subdomain Takeover", "provider": provider},
                )

        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Domain backend active and securely claimed.",
            execution_time_ms=execution_time,
        )

    except Exception as e:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Domain resolution or connection failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )

