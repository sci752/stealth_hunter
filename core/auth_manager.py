import os
import logging
from typing import Dict

# Set up enterprise logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("AuthManager")

class AuthManager:
    """
    Enterprise Authentication Handler for Zero-Trust Environments.
    Manages JWTs, Session Cookies, and API keys for RBAC and IDOR testing.
    """
    def __init__(self):
        # Securely loads tokens from the host environment or a local .env file
        self.admin_token = os.getenv("HUNTER_ADMIN_JWT", None)
        self.user_token = os.getenv("HUNTER_USER_JWT", None)
        self.api_key = os.getenv("HUNTER_API_KEY", None)

    def get_headers(self, role: str = "guest") -> Dict[str, str]:
        """
        Injects the correct authentication headers based on the requested execution role.
        This is mandatory for testing Business Logic and Privilege Escalation.
        """
        headers = {
            "User-Agent": "StealthHunter-Enterprise/1.0",
            "Accept": "application/json"
        }

        # Dynamically attach the correct authorization structure
        if role == "admin" and self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
        elif role == "user" and self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"
        elif role == "api" and self.api_key:
            headers["X-API-Key"] = self.api_key
        elif role != "guest":
            logger.warning(f"Role '{role}' requested but no token loaded in environment. Sending unauthenticated request.")

        return headers

    def check_auth_status(self) -> None:
        """
        Pre-flight check run by the orchestrator to confirm execution mode.
        """
        if not any([self.admin_token, self.user_token, self.api_key]):
            logger.info("No auth tokens detected. Framework running in Unauthenticated (Black-Box) mode.")
        else:
            loaded_roles = []
            if self.admin_token: loaded_roles.append("Admin")
            if self.user_token: loaded_roles.append("User")
            if self.api_key: loaded_roles.append("API")
            logger.info(f"Auth loaded. Framework running in Authenticated mode. Active roles: {', '.join(loaded_roles)}")

# Global singleton to be imported by attack modules
auth = AuthManager()

