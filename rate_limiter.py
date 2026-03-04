import time
import random
import threading
import logging
from typing import Optional
import config

# Setup logging
logger = logging.getLogger("RateLimiter")


class EnterpriseRateLimiter:
    """
    Advanced Global Gatekeeper utilizing a Token Bucket algorithm, 
    Jitter-Injected Evasion, and Exponential Backoff Recovery.
    
    This rate limiter helps evade WAF detection by:
    1. Enforcing consistent delays between requests
    2. Adding randomized jitter to break fingerprinting
    3. Backing off gracefully when WAF triggers (429/503)
    4. Slowly recovering to baseline speed when safe
    """
    
    def __init__(
        self, 
        base_rps: float = None, 
        max_delay: float = None, 
        jitter_range: float = None
    ):
        """
        Initialize the Enterprise Rate Limiter.
        
        Args:
            base_rps (float): Requests per second baseline. Defaults to config.RATE_LIMITER_BASE_RPS.
                Higher values = faster scanning but higher WAF trigger risk.
            max_delay (float): Maximum delay in seconds before backing off further. 
                Defaults to config.RATE_LIMITER_MAX_DELAY.
                Prevents infinite delays during sustained WAF blocking.
            jitter_range (float): Randomness variance (0.0-1.0). Defaults to config.RATE_LIMITER_JITTER_RANGE.
                0.25 = ±25% variance on current delay to evade fingerprinting.
        """
        # Use config defaults if not provided
        self.base_rps = base_rps or config.RATE_LIMITER_BASE_RPS
        self.max_delay = max_delay or config.RATE_LIMITER_MAX_DELAY
        self.jitter_range = jitter_range or config.RATE_LIMITER_JITTER_RANGE
        
        # Core Configuration
        self.base_delay = 1.0 / self.base_rps
        
        # State Management
        self.current_delay = self.base_delay
        self.last_request_time = time.monotonic()
        self.backoff_count = 0  # Track how many times we've backed off
        
        # Thread Safety for async/multi-threaded orchestrators
        self._lock = threading.Lock()
        
        logger.debug(f"RateLimiter initialized: base_rps={self.base_rps}, max_delay={self.max_delay}, jitter={self.jitter_range}")

    def _calculate_jitter(self) -> float:
        """
        Applies a randomized variance to break heuristic WAF fingerprinting.
        
        Returns:
            float: Delay with jitter applied, or base delay if jitter_range <= 0.
        """
        if self.jitter_range <= 0:
            return self.current_delay
            
        variance = self.current_delay * self.jitter_range
        jittered = self.current_delay + random.uniform(-variance, variance)
        return max(0.0, jittered)  # Ensure non-negative

    def wait(self) -> None:
        """
        Enforces the rate limit delay with automatic recovery mechanism.
        
        This method:
        1. Calculates how long to sleep based on elapsed time since last request
        2. Applies jitter to break WAF fingerprinting
        3. Sleeps if necessary
        4. Automatically recovers (speeds up) when not throttled
        
        Thread-safe: Uses a lock to prevent race conditions in multi-threaded scenarios.
        """
        with self._lock:
            now = time.monotonic()
            
            # 1. Calculate required sleep time
            elapsed = now - self.last_request_time
            jittered_delay = self._calculate_jitter()
            sleep_time = max(0.0, jittered_delay - elapsed)

            # 2. Execute Sleep
            if sleep_time > 0:
                time.sleep(sleep_time)

            # 3. Update execution state
            self.last_request_time = time.monotonic()

            # 4. Auto-Recovery: Gradually speed back up if we were previously throttled
            # Removes 10% of excess delay per successful request
            if self.current_delay > self.base_delay:
                recovery_step = (self.current_delay - self.base_delay) * config.RATE_LIMITER_RECOVERY_FACTOR
                self.current_delay = max(self.base_delay, self.current_delay - recovery_step)
                logger.debug(f"Recovery: delay reduced to {self.current_delay:.2f}s")

    def trigger_backoff(self, reason: str = "WAF or Rate Limit") -> None:
        """
        Externally triggered by attack modules upon receiving a 429 or 503.
        Implements an additive increase to throttle the framework safely.
        
        The backoff algorithm:
        1. Adds RATE_LIMITER_BACKOFF_INCREMENT (default 2s) to current delay
        2. Caps at max_delay to prevent infinite delays
        3. Logs the event for monitoring
        
        Args:
            reason (str): Human-readable reason for the backoff (e.g., "WAF Block on SQL_Injection").
        """
        with self._lock:
            old_delay = self.current_delay
            # Add backoff increment, capped at max_delay
            self.current_delay = min(
                self.max_delay, 
                self.current_delay + config.RATE_LIMITER_BACKOFF_INCREMENT
            )
            self.backoff_count += 1
            
            logger.warning(
                f"WAF BACKOFF TRIGGERED: {reason} | "
                f"Delay: {old_delay:.2f}s → {self.current_delay:.2f}s | "
                f"Backoff count: {self.backoff_count}"
            )

    def status(self) -> dict:
        """
        Returns the current telemetry of the rate limiter.
        
        Returns:
            dict: Status dictionary containing:
                - current_rps (float): Current requests per second
                - delay_seconds (float): Current delay in seconds (rounded to 2 decimals)
                - is_throttled (bool): True if delay > base_delay (i.e., we're in backoff)
                - backoff_count (int): Total number of times backoff was triggered
        """
        with self._lock:
            return {
                "current_rps": 1.0 / self.current_delay if self.current_delay > 0 else 0,
                "delay_seconds": round(self.current_delay, 2),
                "is_throttled": self.current_delay > self.base_delay,
                "backoff_count": self.backoff_count
            }

    def reset(self) -> None:
        """
        Reset the rate limiter to base state.
        Useful for testing or switching targets.
        """
        with self._lock:
            self.current_delay = self.base_delay
            self.last_request_time = time.monotonic()
            self.backoff_count = 0
            logger.info("Rate limiter reset to baseline")


# Global singleton instance for the entire orchestrator
limiter = EnterpriseRateLimiter(
    base_rps=config.RATE_LIMITER_BASE_RPS,
    max_delay=config.RATE_LIMITER_MAX_DELAY,
    jitter_range=config.RATE_LIMITER_JITTER_RANGE
)

logger.info(f"Global rate limiter initialized: {config.RATE_LIMITER_BASE_RPS} RPS baseline")
