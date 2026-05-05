"""
Data models for security findings.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    """Finding categories."""
    OVER_PERMISSIONED = "Over-Permissioned"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    TRUST_POLICY_RISK = "Trust Policy Risk"
    STALE_CREDENTIALS = "Stale Credentials"
    UNUSED_PERMISSIONS = "Unused Permissions"
    RISKY_BEHAVIOR = "Risky Behavior"


class Finding(BaseModel):
    """Represents a single security finding."""
    
    severity: Severity = Field(..., description="Severity level")
    category: Category = Field(..., description="Finding category")
    identity: str = Field(..., description="Identity ARN or name")
    identity_type: Optional[str] = Field(None, description="User, Role, or Group")
    finding_title: str = Field(..., description="Brief title of the finding")
    finding_description: str = Field(..., description="Detailed description")
    attack_path: List[str] = Field(
        default_factory=list, description="Chain of identities/permissions for privilege escalation"
    )
    impact: str = Field(..., description="Potential impact of this finding")
    recommendation: str = Field(..., description="Remediation recommendations")
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list, description="Supporting evidence (policies, CloudTrail logs, etc)"
    )
    tags: List[str] = Field(default_factory=list, description="Tags for filtering")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "severity": "HIGH",
                "category": "Privilege Escalation",
                "identity": "arn:aws:iam::111122223333:user/alice",
                "identity_type": "User",
                "finding_title": "iam:PassRole + lambda:CreateFunction",
                "finding_description": "User alice has iam:PassRole and lambda:CreateFunction permissions",
                "attack_path": [
                    "arn:aws:iam::111122223333:user/alice",
                    "DevOpsPolicy",
                    "iam:PassRole",
                    "lambda:CreateFunction",
                    "arn:aws:iam::111122223333:role/AdminExecutionRole"
                ],
                "impact": "User may create Lambda functions running with admin role permissions",
                "recommendation": "Restrict iam:PassRole to specific role ARNs; require admin approval for Lambda creation"
            }
        }


class ScanMetadata(BaseModel):
    """Metadata about a scan run."""
    
    timestamp: str = Field(..., description="Scan timestamp (ISO 8601)")
    total_identities: int = Field(..., description="Total identities analyzed")
    total_policies: int = Field(..., description="Total policies analyzed")
    total_findings: int = Field(..., description="Total findings generated")
    findings_by_severity: Dict[str, int] = Field(
        ..., description="Count of findings by severity"
    )
    findings_by_category: Dict[str, int] = Field(
        ..., description="Count of findings by category"
    )
    version: str = Field(default="0.1.0", description="Analyzer version")


class ScanResult(BaseModel):
    """Complete results from a scan."""
    
    metadata: ScanMetadata = Field(..., description="Scan metadata")
    findings: List[Finding] = Field(..., description="List of findings")

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        self.metadata.total_findings += 1
        self.metadata.findings_by_severity[finding.severity.value] = (
            self.metadata.findings_by_severity.get(finding.severity.value, 0) + 1
        )
        self.metadata.findings_by_category[finding.category.value] = (
            self.metadata.findings_by_category.get(finding.category.value, 0) + 1
        )

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "metadata": {
                    "timestamp": "2026-05-05T10:30:00Z",
                    "total_identities": 25,
                    "total_policies": 42,
                    "total_findings": 15,
                    "findings_by_severity": {"CRITICAL": 1, "HIGH": 5, "MEDIUM": 7, "LOW": 2},
                    "findings_by_category": {"Privilege Escalation": 4, "Over-Permissioned": 8}
                },
                "findings": []
            }
        }
