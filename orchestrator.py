import sys
import os
import json
import time
import logging
import uuid
import requests
from datetime import datetime, timezone
from rate_limiter import limiter
from core.auto_discovery import get_attack_modules
from core.scope_manager import load_mass_scope, is_valid_url
from core.auth_manager import auth
import config

# ============================================================================
# LOGGING SETUP
# NOTE: basicConfig must only be called ONCE, here at the entry point.
# Submodules (auto_discovery, auth_manager, etc.) must NOT call basicConfig.
# ============================================================================
_handlers = [logging.StreamHandler()]
if config.LOG_FILE:
    _handlers.append(logging.FileHandler(config.LOG_FILE))

logging.basicConfig(
    level=logging.getLevelName(config.LOG_LEVEL),
    format=config.LOG_FORMAT,
    handlers=_handlers,
)
logger = logging.getLogger("Orchestrator")


def load_targets() -> list:
    """
    Target Ingestion.
    Attempts to load targets from scope.txt first, falling back to target.py.
    """
    logger.info("Initiating target ingestion...")

    # 1. Attempt mass ingestion via scope.txt
    mass_targets = load_mass_scope(config.SCOPE_FILE)
    if mass_targets:
        logger.info(f"Loaded {len(mass_targets)} targets from {config.SCOPE_FILE}")
        return mass_targets

    # 2. Fallback to target.py
    try:
        import target as target_module
        targets = []

        if hasattr(target_module, "TARGET_URLS") and isinstance(target_module.TARGET_URLS, list):
            targets.extend(target_module.TARGET_URLS)

        if hasattr(target_module, "TARGET_URL") and isinstance(target_module.TARGET_URL, str):
            if target_module.TARGET_URL not in targets:
                targets.append(target_module.TARGET_URL)

        if not targets:
            logger.critical("No valid targets found in scope.txt or target.py.")
            sys.exit(1)

        logger.info(f"Loaded {len(targets)} target(s) from target.py")
        return targets

    except ImportError as e:
        logger.critical(f"Neither scope.txt nor target.py found: {e}")
        sys.exit(1)


def generate_evidence_report(target: str, result) -> str:
    """
    Generates a structured JSON evidence report when a vulnerability is confirmed.

    Args:
        target (str): The target URL that was found vulnerable.
        result (ScanResult): The ScanResult returned by the attack module.

    Returns:
        str: The filepath of the saved report, or None on failure.
    """
    try:
        # FIX: Ensure the evidence output directory exists before writing.
        # If EVIDENCE_OUTPUT_DIR is set to a subdirectory, it must be created.
        os.makedirs(config.EVIDENCE_OUTPUT_DIR, exist_ok=True)

        timestamp = (
            int(time.time() * 1_000_000)
            if config.USE_MICROSECOND_TIMESTAMPS
            else int(time.time())
        )
        uuid_suffix = f"_{uuid.uuid4().hex[:8]}" if config.USE_UUID_IN_FILENAME else ""
        filename = f"confirmed_vuln_{timestamp}{uuid_suffix}.json"
        filepath = os.path.join(config.EVIDENCE_OUTPUT_DIR, filename)

        report_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "module": result.module_name,
            "severity": result.severity.value if hasattr(result.severity, "value") else result.severity,
            "description": result.description,
            "evidence": result.evidence,
            "execution_time_ms": result.execution_time_ms,
            "metadata": result.metadata,
        }

        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=4)

        logger.info(f"Evidence report saved: {filepath}")
        return filepath

    except IOError as e:
        logger.error(f"Failed to write evidence report: {e}")
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error generating evidence report: {e}",
            exc_info=config.LOG_FULL_TRACEBACK,
        )
        return None


def run_enterprise_hunt():
    """Main orchestration loop for vulnerability scanning."""
    logger.info("""
    ================================================
       STEALTH HUNTER : ENTERPRISE ORCHESTRATOR
    ================================================
    """)

    # Pre-Flight Checks
    try:
        auth.check_auth_status()
        targets = load_targets()

        if config.VALIDATE_TARGET_URLS:
            # FIX: Use is_valid_url from scope_manager (was duplicated here before)
            targets = [t for t in targets if is_valid_url(t)]
            if not targets:
                logger.critical("No valid targets after URL validation.")
                sys.exit(1)

        modules = get_attack_modules(config.ATTACKS_DIRECTORY)

        if not modules:
            logger.critical("No valid attack modules discovered. Halting.")
            sys.exit(1)

        logger.info(f"Loaded Scope: {len(targets)} Target(s)")
        logger.info(f"Arsenal: {len(modules)} Active Module(s)")

    except Exception as e:
        logger.critical(f"Pre-flight check failed: {e}", exc_info=config.LOG_FULL_TRACEBACK)
        sys.exit(1)

    try:
        for target_url in targets:
            logger.info(f"========== ENGAGING TARGET: {target_url} ==========")

            for attack_func in modules:

                # 1. The Global Gatekeeper (Anti-Ban mechanism)
                limiter.wait()

                # 2. Fetch real-time telemetry from the rate limiter
                rate_status = limiter.status()
                delay_str = f"{rate_status['delay_seconds']}s"
                waf_flag = "[THROTTLED] " if rate_status["is_throttled"] else ""
                module_name = attack_func.__module__.split(".")[-1]

                logger.info(f"[>] {waf_flag}Delay: {delay_str} | Executing: {module_name}")

                try:
                    # 3. Execute the isolated module
                    result = attack_func(target_url)

                    # 4. Short-Circuit & Reporting Logic
                    if result.is_vulnerable:
                        sev = (
                            result.severity.value
                            if hasattr(result.severity, "value")
                            else result.severity
                        )
                        logger.critical(f"[!!!] {sev} VULNERABILITY CONFIRMED [!!!]")
                        logger.critical(f"Target: {target_url}")
                        logger.critical(f"Module: {result.module_name}")
                        logger.critical(f"Details: {result.description}")

                        if config.AUTO_SAVE_EVIDENCE:
                            report_file = generate_evidence_report(target_url, result)
                            if report_file:
                                logger.info(f"Evidence saved to: {report_file}")

                        if config.HALT_ON_FIRST_VULNERABILITY:
                            logger.info("ORCHESTRATOR HALT: Mission accomplished.")
                            sys.exit(0)
                        else:
                            logger.info("Continuing scan (HALT_ON_FIRST_VULNERABILITY=False)")

                # FIX: requests is now imported at the top of this file.
                # Previously this except block caused a NameError crash at runtime.
                except requests.exceptions.RequestException as network_error:
                    logger.warning(f"Network error in module '{module_name}': {network_error}")
                    continue

                except AttributeError as attr_error:
                    logger.warning(f"Attribute error in module '{module_name}': {attr_error}")
                    if config.LOG_FULL_TRACEBACK:
                        logger.debug("Traceback:", exc_info=True)
                    continue

                except Exception as module_error:
                    logger.warning(f"Module '{module_name}' failed: {module_error}")
                    if config.LOG_FULL_TRACEBACK:
                        logger.debug("Full traceback:", exc_info=True)

                    if not config.CONTINUE_ON_MODULE_ERROR:
                        logger.critical("Halting due to module error (CONTINUE_ON_MODULE_ERROR=False)")
                        sys.exit(1)
                    continue

            logger.info(f"Target {target_url} scan complete. Secure against current arsenal.")

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt detected. Spinning down orchestrator safely...")
        sys.exit(0)
    except Exception as e:
        logger.critical(
            f"Unexpected error in orchestrator loop: {e}",
            exc_info=config.LOG_FULL_TRACEBACK,
        )
        sys.exit(1)


if __name__ == "__main__":
    run_enterprise_hunt()
