# 🎯 Stealth Hunter: Enterprise Bug Bounty Orchestrator

>Stealth Hunter is a modular vulnerability orchestration framework designed for professional bug bounty hunters. It shifts away from noisy, scattergun scanning and focuses on **precision, WAF evasion, and automated evidence generation**.

⚠️ **DISCLAIMER:** 
>This framework is built strictly for **educational purposes and authorized bug bounty hunting**. You are solely responsible for your actions. Never point this tool at a target you do not have explicit permission to test.

---

## 🚀 Enterprise Architecture

Standard scanners break when they hit zero-trust environments or aggressive firewalls. Stealth Hunter is engineered differently:

* **Plug-and-Play Arsenal (`core/auto_discovery.py`):** A dynamic discovery engine hot-loads any Python script dropped into the `/attacks/` folder. No core modification is required to add new exploits.
* **Strict Data Contracts (`core/models.py`):** All modules must return a Pydantic `ScanResult` object, ensuring flawless JSON evidence reports for HackerOne/Bugcrowd submissions.
* **Adaptive Rate Limiting (`rate_limiter.py`):** A global gatekeeper equipped with Token Bucket logic, Jitter-Injected Evasion, and AIMD backoff. If an attack module triggers a WAF (HTTP 429/503), the entire orchestrator safely throttles itself.
* **Zero-Trust Auth Manager (`core/auth_manager.py`):** Capable of holding multiple session states simultaneously (e.g., Admin JWT vs. User JWT) to automate the discovery of IDORs and RBAC bypasses.
* **Heavy Artillery Integration (`attacks/nuclei_wrapper.py`):** Wraps industry-standard tools like Nuclei via subprocesses, mapping their CLI output directly into the framework's execution loop.

---

## 🛠️ Installation & Setup

>1. Prerequisites
* **Python 3.8+**
* **Nuclei:** Must be installed and accessible in your system's PATH for the `nuclei_wrapper.py` module to function. ([Nuclei Installation Guide](https://docs.projectdiscovery.io/tools/nuclei/install))

>2. Clone the Repository
```bash

git clone [https://github.com/sci752/coding_project_6_stealth_hunter.git](https://github.com/sci752/coding_project_6_stealth_hunter.git)
cd coding_project_6_stealth_hunter

```
>3. Install Dependencies
```
pip install fastapi uvicorn requests pydantic
```

>4. Configure Authentication (.env File)
To test for Business Logic and Privilege Escalation flaws (like the included rbac_bypass.py module), you must configure your session tokens.
Create a file named .env in the root directory and add your authorized testing credentials:
```
/stealth_hunter/.env

Used for testing zero-trust and tenant isolation
HUNTER_ADMIN_JWT="eyJhbG..."
HUNTER_USER_JWT="eyJhbG..."

Used for standard authenticated API scans
HUNTER_API_KEY="sk_test_12345"
```

(Note: The .gitignore prevents this file from being uploaded, keeping your credentials secure).
# 🎯 Calibration (Safe Local Testing)
Before hunting in the wild, test the kill-switch locally to ensure your environment is configured correctly.
 * Spin up the Target Server: In your first terminal, launch the intentionally vulnerable API:
   python dummy_server.py

 * Configure the Target: Open target.py and ensure the URL points to the local server:
   TARGET_URL = "[http://127.0.0.1:8000](http://127.0.0.1:8000)"

 * Engage the Orchestrator: In a second terminal, launch the framework:
   python orchestrator.py

The framework will detect the intentional local vulnerabilities, generate a confirmed_vuln_[timestamp].json evidence report, and instantly halt.

# ⚔️ Usage (Live Bounty Hunting)
Stealth Hunter supports mass scope ingestion for wide-net reconnaissance operations.
 * Ingest Scope: Generate a massive list of target subdomains using your favorite recon tool (Sublist3r, Amass, httpx, etc.). Save the raw output as scope.txt in the root directory.
   * If scope.txt is missing, the orchestrator will safely fall back to the single TARGET_URL defined in target.py.
 * Verify Authorization: Ensure your .env tokens match the current bug bounty target.
 * Execute the Hunt:
   python orchestrator.py

# 🧩 Building Custom Attack Modules
Want to write a custom GraphQL exploit or a specific CVE check?
 * Duplicate attacks/template_scan.py.
 * Rename the file and modify the detection logic block.
 * The auto_discovery engine will automatically pick it up on the next run. Your custom module will instantly inherit the global WAF rate limiter and Pydantic telemetry.

# 📜 License
This project is licensed under the MIT License - see the LICENSE.md file for details.


```
                              THANK YOU GENTLEMEN 
```
