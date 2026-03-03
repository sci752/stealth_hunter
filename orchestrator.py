import sys
import json
import time
from datetime import datetime
from rate_limiter import limiter
from core.auto_discovery import get_attack_modules
from core.scope_manager import load_mass_scope
from core.auth_manager import auth

def load_targets() -> list:
    """
    Enterprise Target Ingestion.
    Attempts to load mass scopes from scope.txt first, falling back to target.py.
    """
    # 1. Attempt Mass Ingestion via Scope Manager
    mass_targets = load_mass_scope("scope.txt")
    if mass_targets:
        return mass_targets
        
    # 2. Fallback to Local Configuration (target.py)
    try:
        import target as config
        targets = []
        
        # Support for an array of targets
        if hasattr(config, 'TARGET_URLS') and isinstance(config.TARGET_URLS, list):
            targets.extend(config.TARGET_URLS)
        
        # Support for a single target string
        if hasattr(config, 'TARGET_URL') and isinstance(config.TARGET_URL, str):
            if config.TARGET_URL not in targets:
                targets.append(config.TARGET_URL)
                
        if not targets:
            print("[!] Critical Error: No valid targets found in scope.txt or target.py.")
            sys.exit(1)
            
        return targets
        
    except ImportError:
        print("[!] Critical Error: Neither scope.txt nor target.py found in the root directory.")
        sys.exit(1)

def generate_evidence_report(target: str, result) -> str:
    """Generates a structured JSON report when a vulnerability is confirmed."""
    report_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "module": result.module_name,
        "severity": result.severity.value,
        "description": result.description,
        "evidence": result.evidence,
        "execution_time_ms": result.execution_time_ms,
        "metadata": result.metadata
    }
    
    # Creates a unique filename based on the timestamp
    filename = f"confirmed_vuln_{int(time.time())}.json"
    
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)
        
    return filename

def run_enterprise_hunt():
    print("""
    ================================================
       STEALTH HUNTER : ENTERPRISE ORCHESTRATOR
    ================================================
    """)
    
    # Pre-Flight Checks
    auth.check_auth_status()  # Check if we are running unauthenticated or as Admin/User
    targets = load_targets()
    modules = get_attack_modules("attacks")
    
    if not modules:
        print("[!] Fatal: No valid attack templates discovered. Halting.")
        sys.exit(1)
        
    print(f"[*] Loaded Scope: {len(targets)} Target(s)")
    print(f"[*] Arsenal:      {len(modules)} Active Module(s)\n")

    try:
        # Loop through every target in your massive scope
        for target_url in targets:
            print(f"========== ENGAGING TARGET: {target_url} ==========")
            
            # Loop through every attack module for the current target
            for attack_func in modules:
                
                # 1. The Global Gatekeeper (Anti-Ban mechanism)
                limiter.wait()
                
                # 2. Fetch real-time telemetry from the rate limiter
                rate_status = limiter.status()
                delay_str = f"{rate_status['delay_seconds']}s"
                waf_flag = "[THROTTLED] " if rate_status['is_throttled'] else ""
                
                module_name = attack_func.__module__.split('.')[-1]
                
                # HUD Output: Shows delay, WAF status, and current module
                status_line = f"[>] {waf_flag}Delay: {delay_str} | Executing: {module_name}"
                print(status_line.ljust(75), end="\r")
                
                try:
                    # 3. Execute the isolated module
                    result = attack_func(target_url)
                    
                    # 4. The Short-Circuit & Reporting Logic
                    if result.is_vulnerable:
                        print(f"\n\n[!!!] {result.severity.value} VULNERABILITY CONFIRMED [!!!]")
                        print(f"Target:    {target_url}")
                        print(f"Module:    {result.module_name}")
                        print(f"Details:   {result.description}")
                        
                        # Generate the automated JSON report
                        report_file = generate_evidence_report(target_url, result)
                        print(f"[*] Evidence saved to local file: {report_file}\n")
                        
                        print("[*] ORCHESTRATOR HALT: Mission accomplished. Terminating matrix.")
                        sys.exit(0)
                        
                except Exception as module_error:
                    # Fault Tolerance: A broken module won't crash the whole scanner
                    print(f"\n[!] Warning: Module '{module_name}' crashed -> {module_error}")
                    continue 

            print(f"\n[+] Target {target_url} scan complete. System secure against current arsenal.\n")

    except KeyboardInterrupt:
        # Graceful degradation on manual exit (Ctrl+C)
        print("\n\n[!] Keyboard Interrupt detected. Spinning down orchestrator safely...")
        sys.exit(0)

if __name__ == "__main__":
    run_enterprise_hunt()
            
