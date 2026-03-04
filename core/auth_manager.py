import os
import logging
from typing import Dict
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up enterprise logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("AuthManager")


class AuthManager:
    """
    Enterprise Authentication Handler for Zero-Trust Environments.
    Manages JWTs, Session Cookies, and API keys for RBAC and IDOR testing.
    
    Supports multiple authentication roles:
    - admin: High-privilege access for testing admin-only endpoints
    - user: Standard user access for testing IDOR/privilege escalation
    - api: API key based authentication
    - guest: Unauthenticated requests
    """
    
    def __init__(self):
        """
        Initialize AuthManager by loading credentials from environment.
        Credentials are sourced from .env file (via python-dotenv) or system environment.
        """
        # Securely loads tokens from .env file or system environment
        self.admin_token = os.getenv("HUNTER_ADMIN_JWT", None)
        self.user_token = os.getenv("HUNTER_USER_JWT", None)
        self.api_key = os.getenv("HUNTER_API_KEY", None)
        
        logger.debug("AuthManager initialized")

    def get_headers(self, role: str = "guest") -> Dict[str, str]:
        """
        Injects the correct authentication headers based on the requested execution role.
        This is mandatory for testing Business Logic and Privilege Escalation flaws.
        
        Args:
            role (str): Authentication role. Options: 'guest', 'admin', 'user', 'api'.
                Default is 'guest' for unauthenticated requests.
        
        Returns:
            Dict[str, str]: HTTP headers with appropriate authorization set.
            
        Example:
            headers = auth.get_headers(role="admin")
            response = requests.get(target_url, headers=headers)
        """
        headers = {
            "User-Agent": "StealthHunter-Enterprise/1.0",
            "Accept": "application/json"
        }

        # Dynamically attach the correct authorization structure
        if role == "admin" and self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
            logger.debug("Admin token injected into headers")
            
        elif role == "user" and self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"
            logger.debug("User token injected into headers")
            
        elif role == "api" and self.api_key:
            headers["X-API-Key"] = self.api_key
            logger.debug("API key injected into headers")
            
        elif role != "guest":
            logger.warning(
                f"Role '{role}' requested but no token loaded in environment. "
                f"Sending unauthenticated request."
            )

        return headers

    def check_auth_status(self) -> None:
        """
        Pre-flight check run by the orchestrator to confirm execution mode.
        Logs which authentication roles are available for use.
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
            role (str): Role to check ('admin', 'user', 'api').
        
        Returns:
            bool: True if the role has credentials loaded, False otherwise.
        """
        if role == "admin":
            return bool(self.admin_token)
        elif role == "user":
            return bool(self.user_token)
        elif role == "api":
            return bool(self.api_key)
        elif role == "guest":
            return True  # Guest mode always available
        else:
            logger.warning(f"Unknown role requested: {role}")
            return False


# Global singleton to be imported by attack modules
auth = AuthManager()
