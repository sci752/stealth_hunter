# 🎯 Stealth Hunter: Enterprise Bug Bounty Orchestrator

Stealth Hunter is a highly advanced, modular vulnerability orchestration framework designed for professional bug bounty hunters. It shifts away from noisy, scattergun scanning and focuses on **precision, WAF evasion, and automated evidence generation**.



⚠️ **DISCLAIMER:** This framework is built strictly for **educational purposes and authorized bug bounty hunting**. You are solely responsible for your actions. Never point this tool at a target you do not have explicit permission to test.

## 🚀 Architecture

Standard scanners break when they hit zero-trust environments or aggressive firewalls. Stealth Hunter is engineered differently:

* **Plug-and-Play Arsenal:** A dynamic `auto_discovery` engine hot-loads any Python script dropped into the `/attacks/` folder. No core modification required.
* **Strict Data Contracts:** All modules must return a Pydantic `ScanResult` object, ensuring flawless JSON evidence reports for HackerOne/Bugcrowd submissions.
* **Adaptive Rate Limiting:** A global gatekeeper equipped with Token Bucket logic, Jitter-Injected Evasion, and AIMD (Additive Increase/Multiplicative Decrease) backoff. If an attack module triggers a WAF (429/503), the entire orchestrator safely throttles itself.
* **Zero-Trust Auth Manager:** Capable of holding multiple session states simultaneously (e.g., Admin JWT vs. User JWT) to automate the discovery of IDORs and RBAC bypasses.
* **Heavy Artillery Integration:** Wraps industry-standard tools like Nuclei via subprocesses, mapping their CLI output directly into the framework's execution loop.

## 🛠️ Installation & Calibration

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/stealth_hunter.git](https://github.com/yourusername/stealth_hunter.git)
   cd stealth_hunter

 * Install dependencies:
   pip install fastapi uvicorn requests pydantic

 * Run the Calibration Test (Safe Local Sandbox):
   Before hunting in the wild, test the kill-switch locally. Spin up the dummy server in one terminal:
   python dummy_server.py

   In a second terminal, launch the orchestrator:
   python orchestrator.py

   The framework will detect the intentional local vulnerabilities, generate a confirmed_vuln_[timestamp].json report, and instantly halt.
   
>⚔️ Usage (Live Hunting)
Stealth Hunter supports mass scope ingestion for wide recon operations.
 * Generate a massive list of target subdomains using your favorite recon tool (Sublist3r, Amass, httpx, etc.).
 * Save the output as scope.txt in the root directory.
 * Configure your API keys and JWTs in your .env file.
 * Execute the hunt:
   python orchestrator.py

>🧩 Building Custom Attack Modules
To write a custom exploit, drop a new Python file into /attacks/. Use the provided template_scan.py to ensure your module adheres to the Pydantic data contract and inherits the global rate limiter telemetry.

>📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
