"""
Data models for IAM policies.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PolicyType(str, Enum):
    """Types of IAM policies."""
    MANAGED = "Managed"
    INLINE = "Inline"
    TRUST = "Trust"


class Statement(BaseModel):
    """Represents a single policy statement."""
    
    effect: str = Field(..., description="Allow or Deny", pattern="^(Allow|Deny)$")
    actions: List[str] = Field(..., description="Actions (Action)")
    resources: List[str] = Field(..., description="Resources (Resource)")
    principals: Optional[List[str]] = Field(None, description="Principals (for trust policies)")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Conditions")

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "effect": "Allow",
                "actions": ["iam:PassRole", "lambda:CreateFunction"],
                "resources": ["*"],
                "conditions": None
            }
        }


class Policy(BaseModel):
    """Represents an IAM policy."""
    
    arn: Optional[str] = Field(None, description="Policy ARN (managed policies)")
    name: str = Field(..., description="Policy name")
    policy_type: PolicyType = Field(..., description="Type of policy")
    statements: List[Statement] = Field(..., description="Policy statements")
    attached_to: List[str] = Field(
        default_factory=list, description="ARNs of identities this policy is attached to"
    )
    created_date: Optional[str] = Field(None, description="Creation date")
    updated_date: Optional[str] = Field(None, description="Last update date")
    is_service_managed: bool = Field(False, description="Is AWS service managed")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "name": "DevOpsPolicy",
                "policy_type": "Managed",
                "statements": [
                    {
                        "effect": "Allow",
                        "actions": ["iam:PassRole", "lambda:CreateFunction"],
                        "resources": ["*"]
                    }
                ],
                "attached_to": ["arn:aws:iam::111122223333:user/alice"]
            }
        }

    def __hash__(self):
        """Make policy hashable for graph operations."""
        return hash(self.name + str(self.policy_type))

    def __eq__(self, other):
        """Check equality by name and type."""
        if isinstance(other, Policy):
            return self.name == other.name and self.policy_type == other.policy_type
        return False
