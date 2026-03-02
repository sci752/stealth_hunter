import time
import random
import threading

class AdaptiveRateLimiter:
    """
    Enterprise global gatekeeper with dynamic WAF evasion and adaptive backoff.
    """
    def __init__(self, requests_per_second: float = 2.0, jitter: bool = True):
        self.base_delay = 1.0 / requests_per_second
        self.current_delay = self.base_delay
        self.jitter = jitter
        self.last_request_time = 0.0
        self._lock = threading.Lock()

    def wait(self):
        """Thread-safe delay mechanism called by the orchestrator before execution."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time
            wait_time = max(0.0, self.current_delay - elapsed)
            
            if self.jitter:
                # Randomize delay by +/- 20% to evade basic heuristic firewalls
                jitter_amount = self.current_delay * random.uniform(-0.2, 0.2)
                wait_time = max(0.0, wait_time + jitter_amount)

            if wait_time > 0:
                time.sleep(wait_time)
            
            self.last_request_time = time.time()
            
            # Auto-recovery: Slowly speed back up to the base delay over time
            if self.current_delay > self.base_delay:
                self.current_delay = max(self.base_delay, self.current_delay * 0.95)

    def trigger_backoff(self, multiplier: float = 2.0):
        """
        Attack modules can call this if they receive a 429 or 503 response.
        It instantly slows down the entire framework to prevent IP bans.
        """
        with self._lock:
            self.current_delay *= multiplier
            print(f"\n[!] WAF DETECTED: Rate limiter penalizing speed. New delay: {self.current_delay:.2f}s")

# Global singleton instance to be imported by the orchestrator and modules
limiter = AdaptiveRateLimiter(requests_per_second=2.0, jitter=True)
