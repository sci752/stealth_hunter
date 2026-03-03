import time
import random
import threading
from typing import Optional

class EnterpriseRateLimiter:
    """
    Advanced Global Gatekeeper utilizing a Token Bucket algorithm, 
    Jitter-Injected Evasion, and Exponential Backoff Recovery.
    """
    def __init__(
        self, 
        base_rps: float = 2.0, 
        max_delay: float = 15.0, 
        jitter_range: float = 0.25
    ):
        # Core Configuration
        self.base_delay = 1.0 / base_rps
        self.max_delay = max_delay
        self.jitter_range = jitter_range
        
        # State Management
        self.current_delay = self.base_delay
        self.last_request_time = time.monotonic()
        
        # Thread Safety for async/multi-threaded orchestrators
        self._lock = threading.Lock()

    def _calculate_jitter(self) -> float:
        """Applies a randomized variance to break heuristic WAF fingerprinting."""
        if self.jitter_range <= 0:
            return self.current_delay
            
        variance = self.current_delay * self.jitter_range
        return self.current_delay + random.uniform(-variance, variance)

    def wait(self):
        """
        Enforces the rate limit delay. 
        Includes an auto-recovery mechanism to seamlessly return to base speed.
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
            if self.current_delay > self.base_delay:
                recovery_step = (self.current_delay - self.base_delay) * 0.1
                self.current_delay = max(self.base_delay, self.current_delay - recovery_step)

    def trigger_backoff(self, reason: str = "WAF or Rate Limit"):
        """
        Externally triggered by attack modules upon receiving a 429 or 503.
        Implements an additive increase to throttle the framework safely.
        """
        with self._lock:
            old_delay = self.current_delay
            # Add 2 seconds to the delay, capped at max_delay
            self.current_delay = min(self.max_delay, self.current_delay + 2.0)
            
            print(f"\n[!] ALERT: {reason} Detected.")
            print(f"[!] THROTTLING SYSTEM: {old_delay:.2f}s -> {self.current_delay:.2f}s delay.")

    def status(self) -> dict:
        """Returns the current telemetry of the rate limiter."""
        return {
            "current_rps": 1.0 / self.current_delay if self.current_delay > 0 else 0,
            "delay_seconds": round(self.current_delay, 2),
            "is_throttled": self.current_delay > self.base_delay
        }

# Global singleton instance for the entire orchestrator
limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=15.0, jitter_range=0.25)
            
