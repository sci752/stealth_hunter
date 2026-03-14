
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum
from datetime import datetime, timezone


class Severity(str, Enum):
    """
    Standardized Risk Levels for Enterprise Reporting.

    Levels (from highest to lowest):
    - CRITICAL: Immediate exploitation possible, high impact (e.g., RCE, full auth bypass)
    - HIGH: Significant risk, requires specific conditions (e.g., SQLi, XXE, IDOR)
    - MEDIUM: Moderate risk, may require user interaction (e.g., XSS, CSRF)
    - LOW: Minor risk, limited impact (e.g., information disclosure, weak encryption)
    - INFO: Informational finding, no direct security impact (e.g., banner grab, version)
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


def _utc_now() -> datetime:
    """
    Returns the current UTC time as a timezone-aware datetime.
    FIX: datetime.utcnow() is deprecated since Python 3.12 and returns a naive
    datetime. datetime.now(timezone.utc) is the correct modern replacement.
    """
    return datetime.now(timezone.utc)


class ScanResult(BaseModel):
    """
    The Enterprise Data Contract.
    Every module in /attacks/ MUST return this object.

    This ensures consistent structure for:
    - Orchestrator decision-making (halt vs continue)
    - Evidence report generation
    - Logging and monitoring
    - JSON serialization for bug bounty platforms

    Example:
        from core.models import ScanResult, Severity

        result = ScanResult(
            is_vulnerable=True,
            module_name="SQL_Injection",
            severity=Severity.CRITICAL,
            description="SQL injection found in login endpoint",
            evidence="Response: admin@example.com' OR 1=1; --",
            execution_time_ms=125.5
        )
    """

    # Core logic fields
    is_vulnerable: bool = Field(
        ...,
        description="Flag to trigger the orchestrator's short-circuit/stop logic. "
                    "True = vulnerability confirmed, False = target is secure against this module.",
    )

    module_name: str = Field(
        ...,
        description="The unique identifier of the attack module (e.g., 'SQL_Injection_Login'). "
                    "Used in logging and JSON reports for tracking which module found the bug.",
    )

    # Reporting fields
    severity: Severity = Field(
        default=Severity.INFO,
        description="Risk level of the vulnerability (CRITICAL, HIGH, MEDIUM, LOW, INFO).",
    )

    description: str = Field(
        ...,
        description="Technical explanation of the vulnerability found. "
                    "Should be clear enough for bug bounty platform submission.",
    )

    # Evidence fields
    evidence: Optional[str] = Field(
        None,
        description="Raw proof of concept. HTTP response snippet, database query result, etc.",
    )

    payload_used: Optional[str] = Field(
        None,
        description="The specific string or vector that triggered the bug.",
    )

    # Metadata for advanced tracking
    timestamp: datetime = Field(
        default_factory=_utc_now,
        description="When the scan was executed (UTC, timezone-aware). Auto-set to current time.",
    )

    execution_time_ms: float = Field(
        0.0,
        description="Time taken by the module to execute in milliseconds. "
                    "Only measure request time, not setup.",
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Custom data specific to each attack type. "
                    "Example: {'endpoint': '/api/login', 'parameter': 'username'}",
    )

    model_config = {
        "use_enum_values": True,
        "json_schema_extra": {
            "example": {
                "is_vulnerable": True,
                "module_name": "SQL_Injection_Login",
                "severity": "CRITICAL",
                "description": "SQL injection found in /api/login via username parameter.",
                "evidence": "HTTP/1.1 200 OK\n\n{\"authenticated\": true, \"role\": \"admin\"}",
                "payload_used": "' OR 1=1; --",
                "execution_time_ms": 125.5,
                "metadata": {
                    "endpoint": "/api/login",
                    "parameter": "username",
                    "attack_type": "Classic SQL Injection",
                },
            }
        },
    }

    def to_json_report(self) -> str:
        """
        Serialize the result to JSON format suitable for bug bounty platforms.

        Returns:
            str: JSON-formatted string ready for HackerOne/Bugcrowd submission.
        """
        return self.model_dump_json(indent=4, exclude_none=False)

    def is_critical(self) -> bool:
        """Check if this is a critical severity vulnerability."""
        return self.severity == Severity.CRITICAL

    def is_high_or_above(self) -> bool:
        """Check if this is HIGH severity or above."""
        return self.severity in [Severity.CRITICAL, Severity.HIGH]
