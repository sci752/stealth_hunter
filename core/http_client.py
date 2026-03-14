"""
HTTP Client Module for Stealth Hunter
Provides a shared requests.Session with connection pooling.

All attack modules should import and use `session` from this module
instead of calling requests.get() directly. This avoids creating a new
TCP connection on every request, which is significantly faster and more
polite to targets.
"""

import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import config

logger = logging.getLogger("HttpClient")


def _build_session() -> requests.Session:
    """
    Build and configure a requests.Session with connection pooling,
    default headers, and a conservative retry policy for transient errors.

    Returns:
        requests.Session: Fully configured, ready-to-use session.
    """
    session = requests.Session()

    # Mount a pooled adapter for both HTTP and HTTPS.
    # pool_connections = number of distinct hosts to keep connections open for.
    # pool_maxsize = max simultaneous connections per host.
    adapter = HTTPAdapter(
        pool_connections=config.REQUESTS_POOL_CONNECTIONS,
        pool_maxsize=config.REQUESTS_POOL_MAXSIZE,
        # Retry only on connection errors and 503s, never on POST/PUT (not idempotent).
        max_retries=Retry(
            total=2,
            status_forcelist=[503],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            backoff_factor=0.5,
            raise_on_status=False,
        ),
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Default headers applied to every request unless overridden.
    session.headers.update({
        "User-Agent": config.DEFAULT_USER_AGENT,
        "Accept": "application/json, text/html, */*",
    })

    logger.debug(
        f"HTTP session built: pool_connections={config.REQUESTS_POOL_CONNECTIONS}, "
        f"pool_maxsize={config.REQUESTS_POOL_MAXSIZE}"
    )
    return session


# Global singleton session — import this in all attack modules.
session = _build_session()
