"""
Configuration Module for Stealth Hunter
Centralizes all magic numbers, timeouts, and behavioral settings.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ============================================================================
# RATE LIMITER CONFIGURATION
# ============================================================================

# Base requests per second. Higher = faster scanning, but more likely to trigger WAF.
# Recommended: 2.0 for stealth, 5.0+ for aggressive scans.
RATE_LIMITER_BASE_RPS = float(os.getenv("HUNTER_RATE_LIMIT_RPS", 2.0))

# Maximum delay in seconds before backing off further.
RATE_LIMITER_MAX_DELAY = float(os.getenv("HUNTER_RATE_LIMIT_MAX_DELAY", 15.0))

# Jitter range (0.0-1.0). Randomness to evade WAF fingerprinting.
# 0.25 = ±25% variance on the current delay.
RATE_LIMITER_JITTER_RANGE = float(os.getenv("HUNTER_RATE_LIMIT_JITTER", 0.25))

# Additive increase per WAF trigger (seconds). When we hit 429/503, add this much.
RATE_LIMITER_BACKOFF_INCREMENT = 2.0

# Recovery factor (0.0-1.0). How much of the throttle to remove per successful request.
# 0.1 = remove 10% of excess delay per request. Higher = faster recovery.
RATE_LIMITER_RECOVERY_FACTOR = 0.1

# ============================================================================
# REQUEST CONFIGURATION
# ============================================================================

# Default timeout for all HTTP requests (seconds). Float allows sub-second precision.
# Prevents orchestrator from hanging on unresponsive targets.
# FIX: was int() which silently truncated float values like 5.5 → 5
REQUEST_TIMEOUT_SECONDS = float(os.getenv("HUNTER_TIMEOUT", 5.0))

# User-Agent to send with all requests.
DEFAULT_USER_AGENT = "StealthHunter-Enterprise/1.0"

# ============================================================================
# ORCHESTRATOR BEHAVIOR
# ============================================================================

# Stop scanning on first vulnerability found (True) or continue to find all (False)?
HALT_ON_FIRST_VULNERABILITY = True

# Automatically save evidence reports to JSON?
AUTO_SAVE_EVIDENCE = True

# Directory where evidence reports are saved.
EVIDENCE_OUTPUT_DIR = os.getenv("HUNTER_EVIDENCE_DIR", ".")

# ============================================================================
# MODULE DISCOVERY
# ============================================================================

# Directory where attack modules are located.
ATTACKS_DIRECTORY = os.getenv("HUNTER_ATTACKS_DIR", "attacks")

# Should the framework automatically create the attacks directory if missing?
AUTO_CREATE_ATTACKS_DIR = True

# ============================================================================
# SCOPE MANAGEMENT
# ============================================================================

# Filename for mass target ingestion.
SCOPE_FILE = "scope.txt"

# Validate URLs before scanning? (Prevents invalid targets from causing errors)
VALIDATE_TARGET_URLS = True

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = os.getenv("HUNTER_LOG_LEVEL", "INFO")

# Log format string for all loggers.
LOG_FORMAT = '[%(levelname)s] %(name)s - %(message)s'

# File to write logs to. Set to None to disable file logging.
LOG_FILE = os.getenv("HUNTER_LOG_FILE", None)

# ============================================================================
# AUTHENTICATION (Zero-Trust Environment)
# ============================================================================

HUNTER_ADMIN_JWT = os.getenv("HUNTER_ADMIN_JWT", None)
HUNTER_USER_JWT = os.getenv("HUNTER_USER_JWT", None)
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", None)

# ============================================================================
# EVIDENCE REPORT NAMING
# ============================================================================

# Use microsecond precision in filenames to avoid collisions?
USE_MICROSECOND_TIMESTAMPS = True

# Include UUID in evidence filename for extra uniqueness?
USE_UUID_IN_FILENAME = True

# ============================================================================
# PERFORMANCE TUNING
# ============================================================================

# Connection pool size for requests.Session (used by core/http_client.py).
REQUESTS_POOL_CONNECTIONS = int(os.getenv("HUNTER_POOL_CONNECTIONS", 10))

# Maximum connections per host in the pool.
REQUESTS_POOL_MAXSIZE = int(os.getenv("HUNTER_POOL_MAXSIZE", 10))

# ============================================================================
# ERROR HANDLING
# ============================================================================

# Continue scanning on module failure? (True) or halt? (False)
CONTINUE_ON_MODULE_ERROR = True

# Log full stack trace for exceptions? (Useful for debugging)
LOG_FULL_TRACEBACK = os.getenv("HUNTER_LOG_TRACEBACK", "False").lower() == "true"
