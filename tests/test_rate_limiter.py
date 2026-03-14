
import pytest
import time
import threading
from rate_limiter import EnterpriseRateLimiter


class TestEnterpriseRateLimiter:
    """Unit tests for the EnterpriseRateLimiter class."""

    def test_initialization_default_values(self):
        """Test that rate limiter initializes with correct default values."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=15.0, jitter_range=0.25)

        assert limiter.base_rps == 2.0
        assert limiter.max_delay == 15.0
        assert limiter.jitter_range == 0.25
        assert limiter.base_delay == pytest.approx(0.5, abs=0.01)
        assert limiter.current_delay == pytest.approx(0.5, abs=0.01)
        assert limiter.backoff_count == 0

    def test_initialization_custom_values(self):
        """Test initialization with custom values."""
        limiter = EnterpriseRateLimiter(base_rps=5.0, max_delay=20.0, jitter_range=0.5)

        assert limiter.base_rps == 5.0
        assert limiter.base_delay == pytest.approx(0.2, abs=0.01)
        assert limiter.max_delay == 20.0
        assert limiter.jitter_range == 0.5

    def test_initialization_zero_jitter_not_replaced_by_default(self):
        """
        FIX: Test that passing 0.0 for jitter_range is honored, not replaced by config default.
        The old `or`-based default would replace 0.0 (falsy) with config.RATE_LIMITER_JITTER_RANGE.
        """
        limiter = EnterpriseRateLimiter(base_rps=2.0, jitter_range=0.0)
        assert limiter.jitter_range == 0.0

    def test_wait_enforces_minimum_delay(self):
        """Test that wait() enforces the minimum delay between requests."""
        limiter = EnterpriseRateLimiter(base_rps=2.0)

        start_time = time.time()
        limiter.wait()
        limiter.wait()
        elapsed = time.time() - start_time

        assert elapsed >= 0.4  # Allow small tolerance

    def test_jitter_application(self):
        """Test that jitter adds randomness to delays."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, jitter_range=0.25)

        jittered_values = []
        base_delay = limiter.current_delay

        for _ in range(10):
            jittered = limiter._calculate_jitter()
            jittered_values.append(jittered)

        unique_values = len(set([round(v, 4) for v in jittered_values]))
        assert unique_values > 1, "Jitter should produce varied values"

        for jittered in jittered_values:
            variance = base_delay * limiter.jitter_range
            assert jittered >= base_delay - variance
            assert jittered <= base_delay + variance

    def test_jitter_disabled_when_range_zero(self):
        """Test that jitter is disabled when jitter_range is 0."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, jitter_range=0.0)

        base_delay = limiter.current_delay
        jittered = limiter._calculate_jitter()

        assert jittered == base_delay

    def test_backoff_increases_delay(self):
        """Test that trigger_backoff increases the current delay."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=15.0)

        old_delay = limiter.current_delay
        limiter.trigger_backoff()
        new_delay = limiter.current_delay

        assert new_delay > old_delay
        assert limiter.backoff_count == 1

    def test_backoff_respects_max_delay(self):
        """Test that backoff is capped at max_delay."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=5.0)

        for _ in range(10):
            limiter.trigger_backoff()

        assert limiter.current_delay <= limiter.max_delay + 0.01
        assert limiter.backoff_count == 10

    def test_recovery_reduces_delay(self):
        """Test that wait() gradually recovers delay back to baseline."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=15.0)
        base_delay = limiter.base_delay

        limiter.trigger_backoff()
        throttled_delay = limiter.current_delay
        assert throttled_delay > base_delay

        for _ in range(5):
            limiter.wait()

        recovered_delay = limiter.current_delay
        assert recovered_delay < throttled_delay
        assert recovered_delay >= base_delay

    def test_status_returns_correct_values(self):
        """Test that status() returns accurate telemetry."""
        limiter = EnterpriseRateLimiter(base_rps=2.0)

        status = limiter.status()

        assert "current_rps" in status
        assert "delay_seconds" in status
        assert "is_throttled" in status
        assert "backoff_count" in status

        assert status["current_rps"] == pytest.approx(2.0, abs=0.01)
        assert status["delay_seconds"] == pytest.approx(0.5, abs=0.01)
        assert status["is_throttled"] is False
        assert status["backoff_count"] == 0

    def test_status_throttled_flag(self):
        """Test that is_throttled flag is set correctly."""
        limiter = EnterpriseRateLimiter(base_rps=2.0)

        assert limiter.status()["is_throttled"] is False

        limiter.trigger_backoff()
        assert limiter.status()["is_throttled"] is True

    def test_reset_restores_baseline(self):
        """Test that reset() returns limiter to baseline state."""
        limiter = EnterpriseRateLimiter(base_rps=2.0)
        base_delay = limiter.base_delay

        limiter.trigger_backoff()
        assert limiter.current_delay > base_delay
        assert limiter.backoff_count == 1

        limiter.reset()

        assert limiter.current_delay == base_delay
        assert limiter.backoff_count == 0
        assert limiter.status()["is_throttled"] is False

    def test_thread_safety_with_concurrent_waits(self):
        """Test that rate limiter is thread-safe with concurrent access."""
        limiter = EnterpriseRateLimiter(base_rps=2.0)
        exceptions = []

        def worker():
            try:
                for _ in range(5):
                    limiter.wait()
            except Exception as e:
                exceptions.append(e)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(exceptions) == 0

    def test_thread_safety_with_concurrent_backoffs(self):
        """Test that backoff is thread-safe with concurrent access."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=30.0)
        exceptions = []

        def worker():
            try:
                for _ in range(3):
                    limiter.trigger_backoff()
            except Exception as e:
                exceptions.append(e)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(exceptions) == 0
        assert limiter.backoff_count == 9

    def test_high_rps_configuration(self):
        """Test limiter with high RPS (aggressive scanning)."""
        limiter = EnterpriseRateLimiter(base_rps=10.0)

        assert limiter.base_delay == pytest.approx(0.1, abs=0.01)
        assert limiter.status()["current_rps"] == pytest.approx(10.0, abs=0.01)

    def test_low_rps_configuration(self):
        """Test limiter with low RPS (stealth mode)."""
        limiter = EnterpriseRateLimiter(base_rps=0.5)

        assert limiter.base_delay == pytest.approx(2.0, abs=0.01)
        assert limiter.status()["current_rps"] == pytest.approx(0.5, abs=0.01)

    def test_recovery_factor_application(self):
        """Test that recovery factor is applied correctly during recovery."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=15.0)
        base_delay = limiter.base_delay

        for _ in range(3):
            limiter.trigger_backoff()

        throttled_delay = limiter.current_delay

        limiter.wait()

        assert limiter.current_delay < throttled_delay
        assert limiter.current_delay >= base_delay


class TestRateLimiterEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_delay_does_not_crash(self):
        """Test that zero or very small delays don't cause issues."""
        limiter = EnterpriseRateLimiter(base_rps=100.0)

        limiter.wait()
        limiter.wait()
        assert limiter.current_delay > 0

    def test_very_large_backoff_increment(self):
        """Test limiter doesn't crash with large backoff values."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, max_delay=1000.0)

        for _ in range(100):
            limiter.trigger_backoff()

        assert limiter.current_delay <= 1000.0 + 0.01

    def test_negative_jitter_range_handling(self):
        """Test that negative jitter range is handled safely."""
        limiter = EnterpriseRateLimiter(base_rps=2.0, jitter_range=-0.5)

        jittered = limiter._calculate_jitter()
        assert jittered == limiter.current_delay


if __name__ == "__main__":
    # FIX: was missing closing parenthesis — caused a SyntaxError when running directly
    pytest.main([__file__, "-v", "--tb=short"])
