# 🎯 Stealth Hunter - Setup & Usage Guide

>Version: v0.1.0

A modular reconnaissance and security testing framework.
Quick start guide for getting Stealth Hunter up and running.

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/sci752/coding_project_6_stealth_hunter.git
cd coding_project_6_stealth_hunter
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
Create a `.env` file in the root directory with your settings:

```bash
# Authentication tokens (optional)
HUNTER_ADMIN_JWT="your_admin_token_here"
HUNTER_USER_JWT="your_user_token_here"
HUNTER_API_KEY="your_api_key_here"

# Rate limiting
HUNTER_RATE_LIMIT_RPS=2.0
HUNTER_TIMEOUT=5

# Logging
HUNTER_LOG_LEVEL=INFO
```

See `config.py` for all available options.

---

## 🚀 Quick Start (Local Testing)

### Test with Dummy Server

**Terminal 1: Start vulnerable server**
```bash
python dummy_server.py
```

**Terminal 2: Run orchestrator**
```bash
python orchestrator.py
```

The framework will scan `http://127.0.0.1:8000` (configured in `target.py`) and generate evidence reports.

---

## 🎯 Live Bounty Hunting

### 1. Configure Targets

**Option A: Single Target**
Edit `target.py`:
```python
TARGET_URL = "https://target-company.com"
```

**Option B: Multiple Targets**
Create `scope.txt` with one URL per line:
```
https://api.target.com
https://admin.target.com
https://target.com/app
```

### 2. Add Authentication (if needed)
Edit `.env` with valid test credentials:
```
HUNTER_ADMIN_JWT="eyJhbGc..."
HUNTER_USER_JWT="eyJhbGc..."
```

### 3. Start Scan
```bash
python orchestrator.py
```

The framework will:
- Load targets from `scope.txt` or `target.py`
- Discover attack modules in `attacks/` directory
- Execute each module against each target
- Generate JSON evidence reports when vulnerabilities are found
- Stop on first vulnerability (configurable in `config.py`)

---

## 🧩 Adding Custom Attack Modules

### Quick Steps

1. Copy template:
   ```bash
   cp attacks/template_scan.py attacks/my_custom_scan.py
   ```

2. Edit `my_custom_scan.py` with your detection logic

3. Run orchestrator - your module is auto-discovered!

### Module Template

```python
import time
import requests
from core.models import ScanResult, Severity
from rate_limiter import limiter
import config

def execute(target: str) -> ScanResult:
    module_name = "My_Custom_Module"
    
    try:
        # Wait for rate limit
        limiter.wait()
        
        # Make request
        response = requests.get(
            target,
            timeout=config.REQUEST_TIMEOUT_SECONDS
        )
        
        # Check for vulnerability
        if response.status_code == 200 and "vulnerable" in response.text:
            return ScanResult(
                is_vulnerable=True,
                module_name=module_name,
                severity=Severity.HIGH,
                description="Vulnerability found",
                evidence=response.text[:200]
            )
        
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Target is secure"
        )
        
    except requests.exceptions.RequestException as e:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Request failed: {e}"
        )
```

For detailed guide, see `CONTRIBUTING.md`.

---

## 🧪 Running Tests

### Install Test Dependencies
```bash
pip install pytest pytest-cov
```

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
pytest tests/test_rate_limiter.py -v
pytest tests/test_auto_discovery.py -v
pytest tests/test_scope_manager.py -v
```

### Run Tests with Coverage
```bash
pytest --cov=. tests/
```

---

## ⚙️ Configuration

Edit `config.py` to customize behavior:

```python
# How fast to scan (requests per second)
RATE_LIMITER_BASE_RPS = 2.0

# Stop on first vuln or continue scanning?
HALT_ON_FIRST_VULNERABILITY = True

# Request timeout
REQUEST_TIMEOUT_SECONDS = 5

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL = "INFO"
```

All settings can be overridden via `.env` file:
```
HUNTER_RATE_LIMIT_RPS=5.0
HUNTER_TIMEOUT=10
HUNTER_LOG_LEVEL=DEBUG
```

---

## 📊 Understanding Output

### Console Output
```
[INFO] Loaded Scope: 1 Target(s)
[INFO] Arsenal: 4 Active Module(s)
[>] Delay: 0.5s | Executing: SQL_Injection_Login
[!!!] HIGH VULNERABILITY CONFIRMED [!!!]
[*] Evidence saved to: confirmed_vuln_1704067200.json
```

### Evidence Reports
Generated as JSON files: `confirmed_vuln_[timestamp].json`

```json
{
    "timestamp": "2024-03-04T12:30:45.123456Z",
    "target": "https://example.com",
    "module": "SQL_Injection_Login",
    "severity": "CRITICAL",
    "description": "SQL injection in login endpoint",
    "evidence": "HTTP/1.1 200 OK...",
    "execution_time_ms": 125.5,
    "metadata": {
        "endpoint": "/api/login",
        "parameter": "username"
    }
}
```

---

## 🔐 Security Best Practices

1. **Never commit `.env` to Git** - it's in `.gitignore`
2. **Use test credentials only** - create dedicated test accounts
3. **Get written authorization** - verify scope before scanning
4. **Start slow** - use low RPS (1.0) to avoid detection
5. **Monitor for WAF blocks** - orchestrator auto-throttles on 429/503
6. **Keep evidence private** - reports contain sensitive data

---

## 🐛 Troubleshooting

### Module Not Loading
Check logs for validation errors:
```bash
HUNTER_LOG_LEVEL=DEBUG python orchestrator.py
```

Module must have: `def execute(target: str) -> ScanResult:`

### Rate Limited (429/503 errors)
Lower the RPS in `config.py`:
```python
HUNTER_RATE_LIMIT_RPS = 1.0  # Slower = less likely to trigger WAF
```

### Tests Failing
Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
pip install pytest pytest-cov
```

### Connection Errors
- Verify target URL is correct
- Check if target is online and accessible
- Try increasing timeout: `HUNTER_TIMEOUT=15`

---

## 📚 Documentation

- **CONTRIBUTING.md** - Detailed guide for adding custom modules
- **config.py** - All configuration options with explanations
- **attacks/template_scan.py** - Module template with best practices

---

## ⚠️ Disclaimer

This framework is for **authorized security testing only**. You are solely responsible for your actions. Never point this tool at a target without explicit written permission.

---

## 📝 License

MIT License - see LICENSE.md for details

---

## 🤝 Contributing

Found a bug or want to improve Stealth Hunter? See CONTRIBUTING.md for guidelines.

Happy hunting! 🎯
```
                              THANK YOU GENTLEMEN 
```
