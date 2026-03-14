import pytest
import os
from unittest.mock import patch
from core.auth_manager import AuthManager


class TestAuthManagerInitialization:
    """Unit tests for AuthManager initialization."""

    def test_initializes_with_no_tokens_by_default(self):
        """Test that AuthManager initializes with None tokens when no env vars are set."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove any existing hunter env vars
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith("HUNTER_")}
            with patch.dict(os.environ, env, clear=True):
                manager = AuthManager()
                assert manager.admin_token is None
                assert manager.user_token is None
                assert manager.api_key is None

    def test_loads_admin_token_from_env(self):
        """Test that admin JWT is loaded from environment."""
        with patch.dict(os.environ, {"HUNTER_ADMIN_JWT": "admin_token_123"}):
            manager = AuthManager()
            assert manager.admin_token == "admin_token_123"

    def test_loads_user_token_from_env(self):
        """Test that user JWT is loaded from environment."""
        with patch.dict(os.environ, {"HUNTER_USER_JWT": "user_token_456"}):
            manager = AuthManager()
            assert manager.user_token == "user_token_456"

    def test_loads_api_key_from_env(self):
        """Test that API key is loaded from environment."""
        with patch.dict(os.environ, {"HUNTER_API_KEY": "api_key_789"}):
            manager = AuthManager()
            assert manager.api_key == "api_key_789"

    def test_loads_all_tokens_simultaneously(self):
        """Test that all tokens can be loaded at the same time."""
        env = {
            "HUNTER_ADMIN_JWT": "admin_jwt",
            "HUNTER_USER_JWT": "user_jwt",
            "HUNTER_API_KEY": "api_key",
        }
        with patch.dict(os.environ, env):
            manager = AuthManager()
            assert manager.admin_token == "admin_jwt"
            assert manager.user_token == "user_jwt"
            assert manager.api_key == "api_key"


class TestGetHeaders:
    """Unit tests for AuthManager.get_headers()."""

    def test_guest_headers_always_present(self):
        """Test that User-Agent and Accept headers are always set."""
        manager = AuthManager()
        headers = manager.get_headers(role="guest")

        assert "User-Agent" in headers
        assert "Accept" in headers
        assert "StealthHunter" in headers["User-Agent"]

    def test_guest_role_has_no_authorization(self):
        """Test that guest role does not include Authorization header."""
        manager = AuthManager()
        headers = manager.get_headers(role="guest")

        assert "Authorization" not in headers
        assert "X-API-Key" not in headers

    def test_admin_role_injects_bearer_token(self):
        """Test that admin role injects the admin JWT as Bearer token."""
        with patch.dict(os.environ, {"HUNTER_ADMIN_JWT": "admin_secret"}):
            manager = AuthManager()
            headers = manager.get_headers(role="admin")

            assert headers["Authorization"] == "Bearer admin_secret"

    def test_user_role_injects_bearer_token(self):
        """Test that user role injects the user JWT as Bearer token."""
        with patch.dict(os.environ, {"HUNTER_USER_JWT": "user_secret"}):
            manager = AuthManager()
            headers = manager.get_headers(role="user")

            assert headers["Authorization"] == "Bearer user_secret"

    def test_api_role_injects_api_key_header(self):
        """Test that api role injects X-API-Key header."""
        with patch.dict(os.environ, {"HUNTER_API_KEY": "my_api_key"}):
            manager = AuthManager()
            headers = manager.get_headers(role="api")

            assert headers["X-API-Key"] == "my_api_key"
            assert "Authorization" not in headers

    def test_admin_role_without_token_falls_back_to_guest(self):
        """Test that admin role without token returns headers without Authorization."""
        with patch.dict(os.environ, {}, clear=True):
            manager = AuthManager()
            manager.admin_token = None
            headers = manager.get_headers(role="admin")

            assert "Authorization" not in headers
            assert "User-Agent" in headers

    def test_user_role_without_token_falls_back_to_guest(self):
        """Test that user role without token returns headers without Authorization."""
        manager = AuthManager()
        manager.user_token = None
        headers = manager.get_headers(role="user")

        assert "Authorization" not in headers

    def test_unknown_role_returns_guest_headers(self):
        """Test that an unknown role returns unauthenticated headers."""
        manager = AuthManager()
        headers = manager.get_headers(role="superadmin")

        assert "Authorization" not in headers
        assert "X-API-Key" not in headers
        assert "User-Agent" in headers

    def test_default_role_is_guest(self):
        """Test that calling get_headers() with no args defaults to guest."""
        manager = AuthManager()
        headers_default = manager.get_headers()
        headers_guest = manager.get_headers(role="guest")

        assert headers_default == headers_guest


class TestHasRole:
    """Unit tests for AuthManager.has_role()."""

    def test_guest_always_available(self):
        """Test that guest role is always available."""
        manager = AuthManager()
        assert manager.has_role("guest") is True

    def test_admin_role_without_token(self):
        """Test has_role returns False for admin when no token loaded."""
        manager = AuthManager()
        manager.admin_token = None
        assert manager.has_role("admin") is False

    def test_admin_role_with_token(self):
        """Test has_role returns True for admin when token is present."""
        with patch.dict(os.environ, {"HUNTER_ADMIN_JWT": "some_token"}):
            manager = AuthManager()
            assert manager.has_role("admin") is True

    def test_user_role_without_token(self):
        """Test has_role returns False for user when no token loaded."""
        manager = AuthManager()
        manager.user_token = None
        assert manager.has_role("user") is False

    def test_user_role_with_token(self):
        """Test has_role returns True for user when token is present."""
        with patch.dict(os.environ, {"HUNTER_USER_JWT": "some_token"}):
            manager = AuthManager()
            assert manager.has_role("user") is True

    def test_api_role_without_key(self):
        """Test has_role returns False for api when no key loaded."""
        manager = AuthManager()
        manager.api_key = None
        assert manager.has_role("api") is False

    def test_api_role_with_key(self):
        """Test has_role returns True for api when key is present."""
        with patch.dict(os.environ, {"HUNTER_API_KEY": "some_key"}):
            manager = AuthManager()
            assert manager.has_role("api") is True

    def test_unknown_role_returns_false(self):
        """Test has_role returns False for unknown role strings."""
        manager = AuthManager()
        assert manager.has_role("superadmin") is False
        assert manager.has_role("root") is False
        assert manager.has_role("") is False


class TestCheckAuthStatus:
    """Unit tests for AuthManager.check_auth_status()."""

    def test_no_tokens_runs_without_error(self):
        """Test that check_auth_status() runs cleanly with no tokens."""
        manager = AuthManager()
        manager.admin_token = None
        manager.user_token = None
        manager.api_key = None

        # Should not raise any exception
        manager.check_auth_status()

    def test_with_tokens_runs_without_error(self):
        """Test that check_auth_status() runs cleanly with tokens loaded."""
        with patch.dict(os.environ, {
            "HUNTER_ADMIN_JWT": "admin",
            "HUNTER_USER_JWT": "user",
            "HUNTER_API_KEY": "key",
        }):
            manager = AuthManager()
            manager.check_auth_status()  # Should not raise


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

