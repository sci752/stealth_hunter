import time
import json
import subprocess
from core.models import ScanResult, Severity
from rate_limiter import limiter

def execute(target: str) -> ScanResult:
    """
    Enterprise Subprocess Wrapper for ProjectDiscovery's Nuclei.
    Executes Nuclei in silent JSON mode and maps critical findings to the orchestrator.
    """
    module_name = "Nuclei_Subprocess_Wrapper"
    start_time = time.time()
    
    # We run Nuclei silently, asking it to output JSON lines
    # -u specifies the target, -silent suppresses the banner, -jsonl gives structured data
    command = ["nuclei", "-u", target, "-silent", "-jsonl"]
    
    try:
        # Execute the tool and capture the terminal output
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        stdout, stderr = process.communicate(timeout=300) # 5-minute timeout per target
        execution_time = round((time.time() - start_time) * 1000, 2)
        
        # If Nuclei found nothing, stdout will be empty
        if not stdout.strip():
            return ScanResult(
                is_vulnerable=False,
                module_name=module_name,
                description="Nuclei scan completed. No vulnerabilities detected across active templates.",
                execution_time_ms=execution_time
            )
            
        # Parse the JSON output line by line
        for line in stdout.strip().split('\n'):
            try:
                finding = json.loads(line)
                
                # We only want to trigger the kill switch for High or Critical bugs
                # We ignore "info" level findings like missing headers to keep the scanner quiet
                nuclei_severity = finding.get("info", {}).get("severity", "").upper()
                
                if nuclei_severity in ["HIGH", "CRITICAL"]:
                    template_id = finding.get("template-id", "Unknown")
                    vuln_name = finding.get("info", {}).get("name", "Unnamed Vulnerability")
                    
                    return ScanResult(
                        is_vulnerable=True,
                        module_name=f"{module_name} ({template_id})",
                        severity=Severity.CRITICAL if nuclei_severity == "CRITICAL" else Severity.HIGH,
                        description=f"Nuclei automated engine confirmed a high-severity finding: {vuln_name}",
                        evidence=json.dumps(finding, indent=2), # Store the full raw JSON as evidence
                        execution_time_ms=execution_time,
                        metadata={"tool": "nuclei", "template": template_id}
                    )
            except json.JSONDecodeError:
                continue
                
        # If we reach here, Nuclei found things, but they were low/info severity
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Nuclei completed. Only Low/Info level findings detected; suppressing output.",
            execution_time_ms=execution_time
        )

    except subprocess.TimeoutExpired:
        process.kill()
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description="Nuclei subprocess timed out after 5 minutes.",
            execution_time_ms=round((time.time() - start_time) * 1000, 2)
        )
    except Exception as e:
        return ScanResult(
            is_vulnerable=False,
            module_name=module_name,
            description=f"Subprocess execution failed: {str(e)}",
            execution_time_ms=round((time.time() - start_time) * 1000, 2)
                  )
      
