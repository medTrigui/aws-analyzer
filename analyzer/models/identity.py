"""
Data models for IAM identities (users, roles, groups).
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IdentityType(str, Enum):
    """Types of IAM identities."""
    USER = "User"
    ROLE = "Role"
    GROUP = "Group"


class Identity(BaseModel):
    """Represents an IAM identity (user, role, or group)."""
    
    arn: str = Field(..., description="Amazon Resource Name")
    name: str = Field(..., description="Identity name")
    identity_type: IdentityType = Field(..., description="Type of identity")
    created_date: Optional[str] = Field(None, description="Creation date")
    attached_policies: List[str] = Field(default_factory=list, description="Attached policy ARNs")
    inline_policies: List[str] = Field(default_factory=list, description="Inline policy names")
    group_memberships: List[str] = Field(default_factory=list, description="Group ARNs for users")
    assume_role_policy: Optional[Dict[str, Any]] = Field(
        None, description="Trust policy for roles"
    )
    max_session_duration: Optional[int] = Field(
        None, description="Max session duration in seconds (roles)"
    )
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    class Config:
        """Pydantic config."""
        str_strip_whitespace = True
        json_schema_extra = {
            "example": {
                "arn": "arn:aws:iam::111122223333:user/alice",
                "name": "alice",
                "identity_type": "User",
                "created_date": "2024-01-01T00:00:00Z",
                "attached_policies": ["arn:aws:iam::111122223333:policy/UserPolicy"],
                "inline_policies": ["inline-policy-1"],
                "group_memberships": [],
                "tags": {"team": "engineering"}
            }
        }

    def __hash__(self):
        """Make identity hashable for graph operations."""
        return hash(self.arn)

    def __eq__(self, other):
        """Check equality by ARN."""
        if isinstance(other, Identity):
            return self.arn == other.arn
        return False
