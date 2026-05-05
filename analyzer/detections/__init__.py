"""
Detection engines package for IAM analyzer.
"""

from .overpermissioned import OverPermissionedDetector
from .privilege_escalation import PrivilegeEscalationDetector, UnusedPermissionsDetector
from .service_account_behavior import ServiceAccountBehaviorDetector
from .stale_keys import StaleCredentialsDetector
from .trust_policy_risks import TrustPolicyDetector

__all__ = [
    "OverPermissionedDetector",
    "TrustPolicyDetector",
    "StaleCredentialsDetector",
    "PrivilegeEscalationDetector",
    "UnusedPermissionsDetector",
    "ServiceAccountBehaviorDetector",
]
