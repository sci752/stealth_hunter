from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    """Standardized Risk Levels for Enterprise Reporting."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class ScanResult(BaseModel):
    """
    The Enterprise Data Contract.
    Every module in /attacks/ MUST return this object.
    """
    # Core logic fields
    is_vulnerable: bool = Field(..., description="Flag to trigger the short-circuit/stop logic")
    module_name: str = Field(..., description="The unique identifier of the attack module")
    
    # Reporting fields
    severity: Severity = Field(default=Severity.INFO)
    description: str = Field(..., description="Technical explanation of the vulnerability found")
    
    # Evidence fields
    evidence: Optional[str] = Field(None, description="Raw HTTP response snippet or proof of concept")
    payload_used: Optional[str] = Field(None, description="The specific string or vector that triggered the bug")
    
    # Metadata for advanced tracking
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    execution_time_ms: float = Field(0.0, description="Time taken by the module to execute")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom data for specific attack types")

    class Config:
        use_enum_values = True
        json_schema_extra = {
            "example": {
                "is_vulnerable": True,
                "module_name": "SQL_Injection_Login",
                "severity": "CRITICAL",
                "description": "Bypass found on /api/login via 'OR 1=1' payload.",
                "evidence": "HTTP/1.1 200 OK ... Set-Cookie: admin_session=..."
            }
        }
      
