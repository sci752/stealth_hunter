"""
Tests package for Stealth Hunter

This directory contains all unit and integration tests for the framework.

Running tests:
    pytest tests/ -v              # Run all tests
    pytest tests/test_rate_limiter.py -v   # Run specific test file
    pytest -k "test_backoff" -v   # Run tests matching pattern
    pytest --cov=. tests/         # Run with coverage report

Test organization:
    test_rate_limiter.py          - Tests for rate limiting logic
    test_auto_discovery.py        - Tests for module discovery engine
    test_scope_manager.py         - Tests for scope/target management
    test_orchestrator.py          - Integration tests (when created)

Best practices:
    1. Each test should be isolated and not depend on others
    2. Use fixtures for setup/teardown (see pytest docs)
    3. Use descriptive test names: test_<feature>_<scenario>
    4. Mock external dependencies (requests, file I/O, etc.)
    5. Test both happy path and error cases
"""
