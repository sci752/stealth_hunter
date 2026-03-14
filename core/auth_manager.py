
import os
import logging
from typing import Dict
from dotenv import load_dotenv

load_dotenv()

# FIX: Removed logging.basicConfig() call. Logging should only be configured
# once at the application entry point (orchestrator.py). Multiple basicConfig()
# calls in submodules silently conflict and can cause duplicate log lines.
logger = logging.getLogger("AuthManager")


class AuthManager:
    """
    Enterprise Authentication Handler for Zero-Trust Environments.
    Manages JWTs, Session Cookies, and API keys for RBAC and IDOR testing.

    Supported roles:
    - admin: High-privilege access for testing admin-only endpoints
    - user: Standard user access for IDOR/privilege escalation testing
    - api: API key based authentication
    - guest: Unauthenticated requests (default)
    """

    def __init__(self):
        """
        Initialize AuthManager by loading credentials from environment.
        Credentials are sourced from .env file or system environment.
        """
        self.admin_token = os.getenv("HUNTER_ADMIN_JWT", None)
        self.user_token = os.getenv("HUNTER_USER_JWT", None)
        self.api_key = os.getenv("HUNTER_API_KEY", None)

        logger.debug("AuthManager initialized")

    def get_headers(self, role: str = "guest") -> Dict[str, str]:
        """
        Returns HTTP headers with the correct authorization for the given role.

        Args:
            role (str): 'guest', 'admin', 'user', or 'api'. Default: 'guest'.

        Returns:
            Dict[str, str]: Headers dict with Authorization or X-API-Key set if available.
        """
        headers: Dict[str, str] = {
            "Accept": "application/json",
        }

        if role == "admin" and self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
            logger.debug("Admin token injected into headers")

        elif role == "user" and self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"
            logger.debug("User token injected into headers")

        elif role == "api" and self.api_key:
            headers["X-API-Key"] = self.api_key
            logger.debug("API key injected into headers")

        elif role not in ("guest",):
            logger.warning(
                f"Role '{role}' requested but no token found in environment. "
                f"Sending unauthenticated request."
            )

        return headers

    def check_auth_status(self) -> None:
        """
        Pre-flight check: logs which authentication roles are loaded.
        Called by the orchestrator before scanning begins.
        """
        if not any([self.admin_token, self.user_token, self.api_key]):
            logger.info(
                "No auth tokens detected. Framework running in "
                "Unauthenticated (Black-Box) mode."
            )
        else:
            loaded_roles = []
            if self.admin_token:
                loaded_roles.append("Admin")
            if self.user_token:
                loaded_roles.append("User")
            if self.api_key:
                loaded_roles.append("API")

            logger.info(
                f"Auth tokens loaded. Framework running in Authenticated mode. "
                f"Active roles: {', '.join(loaded_roles)}"
            )

    def has_role(self, role: str) -> bool:
        """
        Check if a specific authentication role is available.

        Args:
            role (str): Role to check: 'admin', 'user', 'api', or 'guest'.

        Returns:
            bool: True if the role has credentials loaded.
        """
        if role == "admin":
            return bool(self.admin_token)
        elif role == "user":
            return bool(self.user_token)
        elif role == "api":
            return bool(self.api_key)
        elif role == "guest":
            return True
        else:
            logger.warning(f"Unknown role requested: {role}")
            return False


# Global singleton to be imported by attack modules
auth = AuthManager()

