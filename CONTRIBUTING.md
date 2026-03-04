# 🤝 Contributing to Stealth Hunter

Thank you for contributing to Stealth Hunter! This guide explains how to add custom attack modules and contribute to the framework.

---

## 📋 Table of Contents

1. [Adding Custom Attack Modules](#adding-custom-attack-modules)
2. [Module Contract (Data Structure)](#module-contract-data-structure)
3. [Best Practices](#best-practices)
4. [Testing Your Module](#testing-your-module)
5. [Troubleshooting](#troubleshooting)

---

## Adding Custom Attack Modules

### Quick Start (5 minutes)

1. **Copy the template:**
   ```bash
   cp attacks/template_scan.py attacks/my_custom_exploit.py
   ```

2. **Edit the file** and implement your vulnerability check:
   ```python
   def execute(target: str) -> ScanResult:
       module_name = "My_Custom_Exploit"
       # Your detection logic here
       return ScanResult(...)
   ```

3. **Run the orchestrator** — your module is auto-discovered:
   ```bash
   python orchestrator.py
   ```

That's it! No core modifications needed.

---

## Module Contract (Data Structure)

Every attack module **MUST** return a `ScanResult` object. This is the data contract that keeps the framework modular.

### Function Signature

```python
def execute(target: str) -> ScanResult:
    """
    Args:
        target (str): Target URL (e.g., "https://example.com")
    
    Returns:
        ScanResult: Structured result with vulnerability status and evidence
    """
```

### ScanResult Fields

```python
from core.models import ScanResult, Severity

result = ScanResult(
    # REQUIRED: Is the target vulnerable?
    is_vulnerable: bool,
    
    # REQUIRED: Unique module identifier (for logging/reports)
    module_name: str,
    
    # OPTIONAL: Risk level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    severity: Severity = Severity.INFO,
    
    # REQUIRED: Technical explanation of the vulnerability
    description: str,
    
    # OPTIONAL: Raw proof of concept (HTTP response, query result, etc.)
    evidence: Optional[str] = None,
    
    # OPTIONAL: The specific payload/vector that triggered the bug
    payload_used: Optional[str] = None,
    
    # OPTIONAL: Custom data for your attack type (dict)
    metadata: Dict[str, Any] = {},
    
    # OPTIONAL: Time taken to execute (milliseconds)
    execution_time_ms: float = 0.0
)
```

### Example Return Values

**Vulnerability Found:**
```python
return ScanResult(
    is_vulnerable=True,
    module_name="SQL_Injection_Login",
    severity=Severity.CRITICAL,
    description="SQL injection found in login endpoint via username parameter",
    evidence="HTTP/1.1 200 OK\n[email protected]' OR 1=1; --",
    payload_used="' OR 1=1; --",
    execution_time_ms=125.5,
    metadata={
        "endpoint": "/api/login",
        "parameter": "username",
        "attack_type": "Classic SQL Injection"
    }
)
```

**Target Secure (Nothing Found):**
```python
return ScanResult(
    is_vulnerable=False,
    module_name="SQL_Injection_Login",
    description="Target is secure against SQL injection on login endpoint",
    execution_time_ms=95.2
)
```

**Rate Limited (WAF Detected):**
```python
limiter.trigger_backoff(reason="WAF Block on SQL_Injection_Login")
return ScanResult(
    is_vulnerable=False,
    module_name="SQL_Injection_Login",
    description="Target returned HTTP 429 (Rate Limited)",
    metadata={"blocked": True, "status_code": 429}
)
```

---

## Best Practices

### 1. Use the Rate Limiter
Always respect the global rate limiter to avoid triggering WAF:

```python
from rate_limiter import limiter

def execute(target: str) -> ScanResult:
    # Wait before making request
    limiter.wait()
    
    response = requests.get(target)
    
    # If blocked, tell the orchestrator to back off
    if response.status_code in [429, 503]:
        limiter.trigger_backoff(reason="WAF Block on MyModule")
```

### 2. Use Config for Settings
Pull timeout, user-agent, and other settings from config.py:

```python
import config

response = requests.get(
    url,
    timeout=config.REQUEST_TIMEOUT_SECONDS,
    headers={"User-Agent": config.DEFAULT_USER_AGENT}
)
```

### 3. Use Logging
Log progress for observability:

```python
import logging
logger = logging.getLogger("MyModule")

logger.debug(f"Testing {target}")
logger.info(f"Request completed in {execution_time}ms")
logger.warning(f"WAF detected, backing off")
logger.error(f"Module failed: {error}")
```

### 4. Handle Exceptions Gracefully
Catch specific exceptions, not generic `Exception`:

```python
try:
    response = requests.get(url, timeout=5)
except requests.exceptions.Timeout:
    logger.warning("Request timeout")
    return ScanResult(is_vulnerable=False, ...)
except requests.exceptions.ConnectionError:
    logger.warning("Connection failed")
    return ScanResult(is_vulnerable=False, ...)
except requests.exceptions.RequestException as e:
    logger.error(f"Request error: {e}")
    return ScanResult(is_vulnerable=False, ...)
```

### 5. Measure Only Request Time
Don't include setup time in execution_time_ms:

```python
# ❌ WRONG: Includes setup
start = time.time()
clean_target = target.rstrip('/')
attack_url = f"{clean_target}/endpoint"
response = requests.get(attack_url)
execution_time = round((time.time() - start) * 1000, 2)

# ✅ RIGHT: Only measures request
clean_target = target.rstrip('/')
attack_url = f"{clean_target}/endpoint"
start = time.time()
response = requests.get(attack_url)
execution_time = round((time.time() - start) * 1000, 2)
```

### 6. Use Authentication When Available
Test authenticated endpoints with different roles:

```python
from core.auth_manager import auth

def execute(target: str) -> ScanResult:
    module_name = "RBAC_Bypass_Test"
    
    # Test as admin
    admin_headers = auth.get_headers(role="admin")
    admin_response = requests.get(f"{target}/api/admin", headers=admin_headers)
    
    # Test as user
    user_headers = auth.get_headers(role="user")
    user_response = requests.get(f"{target}/api/admin", headers=user_headers)
    
    # If user can access admin endpoint, we found a bug!
    if user_response.status_code == 200 and admin_response.status_code == 200:
        return ScanResult(
            is_vulnerable=True,
            module_name=module_name,
            severity=Severity.CRITICAL,
            description="User role can access admin endpoints (RBAC bypass)"
        )
```

---

## Testing Your Module

### Manual Testing

1. **Test against dummy_server.py** (local test target):
   ```bash
   # Terminal 1: Start vulnerable server
   python dummy_server.py
   
   # Terminal 2: Configure target
   # Edit target.py to point to http://127.0.0.1:8000
   
   # Terminal 3: Run orchestrator
   python orchestrator.py
   ```

2. **Check logs** to see your module being executed:
   ```
   [INFO] Loaded Scope: 1 Target(s)
   [INFO] Arsenal: 5 Active Module(s)
   [INFO] Initiating deep sweep of attacks/...
   [INFO] Loaded attack module: 'my_custom_exploit.py' ✓
   ```

### Unit Testing

Add tests for your module in `tests/`:

```python
# tests/test_my_custom_exploit.py
import pytest
from attacks.my_custom_exploit import execute
from core.models import Severity

def test_vulnerable_target():
    """Test against a known vulnerable URL"""
    result = execute("http://vulnerable-server.local")
    assert result.is_vulnerable == True
    assert result.severity == Severity.CRITICAL

def test_secure_target():
    """Test against a known secure URL"""
    result = execute("http://secure-server.local")
    assert result.is_vulnerable == False

def test_timeout_handling():
    """Test graceful timeout handling"""
    result = execute("http://slow-server.local")
    # Should not crash, should return clean result
    assert result.module_name == "My_Custom_Exploit"
    assert isinstance(result.execution_time_ms, float)
```

Run tests with pytest:
```bash
pip install pytest
pytest tests/test_my_custom_exploit.py -v
```

---

## Troubleshooting

### Module Not Loading

**Problem:** Your module doesn't appear in the arsenal list.

**Solution:** Check these:
1. Is it in the `attacks/` folder?
2. Does it have an `execute(target: str)` function?
3. Does the function return a `ScanResult` object?
4. Check logs for validation errors:
   ```bash
   python -c "from core.auto_discovery import get_attack_modules; print(get_attack_modules())"
   ```

### Syntax Errors

**Problem:** `SyntaxError: invalid syntax` in your module.

**Solution:** 
- Use a Python linter: `pip install pylint && pylint attacks/my_module.py`
- Check indentation (Python requires consistent 4-space tabs)
- Verify imports are correct

### Rate Limiting Issues

**Problem:** Orchestrator gets stuck waiting between requests.

**Solution:**
- Check if you're hitting WAF (HTTP 429/503)
- Increase `RATE_LIMITER_BASE_RPS` in config.py
- Reduce the number of requests per module

### Module Crashes

**Problem:** Orchestrator halts when your module executes.

**Solution:**
1. Set `CONTINUE_ON_MODULE_ERROR = False` in config.py to catch errors early
2. Add full traceback logging: `LOG_FULL_TRACEBACK = True`
3. Wrap suspicious code in try-except blocks

---

## Code Review Checklist

Before submitting your module, verify:

- [ ] Function signature: `def execute(target: str) -> ScanResult:`
- [ ] Always returns `ScanResult` object
- [ ] Uses `limiter.wait()` before HTTP requests
- [ ] Handles 429/503 with `limiter.trigger_backoff()`
- [ ] Catches specific exceptions (not generic `Exception`)
- [ ] Uses `config.REQUEST_TIMEOUT_SECONDS` for timeouts
- [ ] Includes proper logging (debug, info, warning, error)
- [ ] Module name matches filename
- [ ] Metadata is populated with useful context
- [ ] Works with authenticated requests if needed
- [ ] Tested against dummy_server.py

---

## Questions?

- Check existing modules in `attacks/` for examples
- Review the template: `attacks/template_scan.py`
- Read the main README for framework overview
- Check logs with `LOG_LEVEL = "DEBUG"` in config.py

Happy hunting! 🎯
