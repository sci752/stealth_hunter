import os
import logging
from typing import List, Set
from urllib.parse import urlparse

# Set up enterprise logging for the ingestion pipeline
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("ScopeManager")

class ScopeManager:
    """
    Enterprise Scope Ingestion Engine.
    Handles massive lists of scraped subdomains, normalizes URLs, and guarantees deduplication.
    """
    def __init__(self, scope_file: str = "scope.txt"):
        self.scope_file = scope_file
        self.absolute_path = os.path.abspath(scope_file)

    def _normalize_url(self, target: str) -> str:
        """
        Sanitizes raw input. If a recon tool just outputs 'api.target.com', 
        this ensures it becomes a fully qualified 'https://api.target.com'.
        """
        target = target.strip()
        
        # Enforce scheme if missing
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
            
        # Parse and rebuild to strip trailing slashes or accidental paths
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def get_targets(self) -> List[str]:
        """
        Reads the mass scope file, validates domains, and returns a clean list.
        """
        if not os.path.exists(self.absolute_path):
            logger.warning(f"Scope file '{self.scope_file}' not found. Bypassing mass ingestion.")
            return []

        # Using a Set automatically prevents duplicate targets
        valid_targets: Set[str] = set()
        
        try:
            with open(self.absolute_path, 'r') as file:
                for line in file:
                    target = line.strip()
                    
                    # Ignore empty lines and commented-out domains
                    if not target or target.startswith('#'):
                        continue
                        
                    normalized = self._normalize_url(target)
                    valid_targets.add(normalized)
                    
            logger.info(f"Ingested {len(valid_targets)} unique, sanitized targets from {self.scope_file}.")
            return list(valid_targets)
            
        except Exception as e:
            logger.error(f"Critical Failure reading scope file: {e}")
            return []

# Singleton helper
def load_mass_scope(filename: str = "scope.txt") -> List[str]:
    manager = ScopeManager(filename)
    return manager.get_targets()
  
