import time
import json
import subprocess
import logging
from core.models import ScanResult, Severity

logger = logging.getLogger("NucleiWrapper")

# Nuclei scan timeout per target (seconds). 5 minutes is a safe default.
_NUCLEI_TIMEOUT = 300


def execute(target: str) -> ScanResult:
    """
    Subprocess Wrapper for ProjectDiscovery's Nuclei.
    Executes Nuclei in silent JSON-lines mode and maps HIGH/CRITICAL findings
    to the orchestrator's ScanResult contract.

    Requires `nuclei` to be installed and available on PATH.
    """
    module_name = "Nuclei_Subprocess_Wrapper"
    start_time = time.time()

    # -u: target URL, -silent: suppress banner, -jsonl: structured JSON output
    command = ["nuclei", "-u", target, "-silent", "-jsonl"]

    process = None
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        stdout, stderr = process.communicate(timeout=_NUCLEI_TIMEOUT)
        execution_time = round((time.time() - start_time) * 1000, 2)

        if not stdout.strip():
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                description="Nuclei scan completed. No vulnerabilities detected.",
                execution_time_ms=execution_time,
            )

        # Parse JSON output line by line — only surface HIGH/CRITICAL findings
        for line in stdout.strip().split("\n"):
            try:
                finding = json.loads(line)
                nuclei_severity = finding.get("info", {}).get("severity", "").upper()

                if nuclei_severity in ("HIGH", "CRITICAL"):
                    template_id = finding.get("template-id", "Unknown")
                    vuln_name = finding.get("info", {}).get("name", "Unnamed Vulnerability")

                    return ScanResult(
                        is_vulnerable=True,
                        module_name=f"{module_name} ({template_id})",
                        severity=Severity.CRITICAL if nuclei_severity == "CRITICAL" else Severity.HIGH,
                        description=f"Nuclei confirmed a high-severity finding: {vuln_name}",
                        evidence=json.dumps(finding, indent=2),
                        execution_time_ms=execution_time,
                        metadata={"tool": "nuclei", "template": template_id},
                    )

            except json.JSONDecodeError:
                logger.debug(f"Non-JSON line from Nuclei: {line!r}")
                continue

        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Nuclei completed. Only Low/Info findings detected; suppressed.",
            execution_time_ms=execution_time,
        )

    except subprocess.TimeoutExpired:
        # Ensure the process is fully terminated before returning
        if process is not None:
            process.kill()
            process.communicate()  # Drain pipes to prevent zombie process
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Nuclei subprocess timed out after {_NUCLEI_TIMEOUT // 60} minutes.",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )

    except FileNotFoundError:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Nuclei not found on PATH. Install from https://github.com/projectdiscovery/nuclei",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )

    except Exception as e:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Subprocess execution failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )

