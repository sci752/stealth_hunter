import time
from core.models import ScanResult, Severity
from core.auth_manager import auth
from core.http_client import session
from rate_limiter import limiter
import config 


def execute(target: str) -> ScanResult:
    """
    Business Logic Scanner: RBAC Privilege Escalation.
    Attempts to access restricted admin endpoints using a standard user's JWT.
    """
    module_name = "RBAC_Privilege_Escalation"
    start_time = time.time()

    # Fetch low-privileged headers from the Auth Manager
    user_headers = auth.get_headers(role="user")

    # If no user token is loaded in .env, skip the module safely
    if "Authorization" not in user_headers:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Skipped: No user-level JWT provided in environment variables.",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )

    clean_target = target.rstrip("/")
    restricted_endpoint = f"{clean_target}/api/admin/dashboard_data"

    try:
        # Fire the request using the low-privilege user's credentials via shared session
        response = session.get(
            restricted_endpoint,
            headers=user_headers,
            timeout=config.REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code in [429, 503]:
            limiter.trigger_backoff(reason=f"WAF Block on {module_name}")

        execution_time = round((time.time() - start_time) * 1000, 2)

        # Detection: A 200 OK with sensitive admin data means access control is broken
        if response.status_code == 200 and "total_revenue" in response.text.lower():
            return ScanResult(
                is_vulnerable=True,
                module_name=module_name,
                severity=Severity.CRITICAL,
                description=(
                    "Zero-Trust failure. A low-privileged User JWT successfully "
                    "accessed an Admin-only endpoint."
                ),
                evidence=f"[HTTP 200] Headers sent: {user_headers} | Response: {response.text[:150]}",
                execution_time_ms=execution_time,
                metadata={
                    "attack_type": "IDOR / Broken Access Control",
                    "endpoint": restricted_endpoint,
                },
            )

        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"RBAC intact. User token correctly denied (HTTP {response.status_code}).",
            execution_time_ms=execution_time,
        )

    except Exception as e:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Request failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )
import time
from core.models import ScanResult, Severity
from core.auth_manager import auth
from core.http_client import session
from rate_limiter import limiter
import config


def execute(target: str) -> ScanResult:
    """
    Business Logic Scanner: RBAC Privilege Escalation.
    Attempts to access restricted admin endpoints using a standard user's JWT.
    """
    module_name = "RBAC_Privilege_Escalation"
    start_time = time.time()

    # Fetch low-privileged headers from the Auth Manager
    user_headers = auth.get_headers(role="user")

    # If no user token is loaded in .env, skip the module safely
    if "Authorization" not in user_headers:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Skipped: No user-level JWT provided in environment variables.",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )

    clean_target = target.rstrip("/")
    restricted_endpoint = f"{clean_target}/api/admin/dashboard_data"

    try:
        # Fire the request using the low-privilege user's credentials via shared session
        response = session.get(
            restricted_endpoint,
            headers=user_headers,
            timeout=config.REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code in [429, 503]:
            limiter.trigger_backoff(reason=f"WAF Block on {module_name}")

        execution_time = round((time.time() - start_time) * 1000, 2)

        # Detection: A 200 OK with sensitive admin data means access control is broken
        if response.status_code == 200 and "total_revenue" in response.text.lower():
            return ScanResult(
                is_vulnerable=True,
                module_name=module_name,
                severity=Severity.CRITICAL,
                description=(
                    "Zero-Trust failure. A low-privileged User JWT successfully "
                    "accessed an Admin-only endpoint."
                ),
                evidence=f"[HTTP 200] Headers sent: {user_headers} | Response: {response.text[:150]}",
                execution_time_ms=execution_time,
                metadata={
                    "attack_type": "IDOR / Broken Access Control",
                    "endpoint": restricted_endpoint,
                },
            )

        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"RBAC intact. User token correctly denied (HTTP {response.status_code}).",
            execution_time_ms=execution_time,
        )

    except Exception as e:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Request failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )

