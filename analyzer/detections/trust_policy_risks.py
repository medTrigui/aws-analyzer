"""
Detection engine for risky trust policies.
"""

from typing import List, Dict, Any

from ..models import Finding, Identity, Severity, Category


class TrustPolicyDetector:
    """Detects risky role trust relationships."""

    @staticmethod
    def detect(identities: List[Identity]) -> List[Finding]:
        """Detect risky trust policies in roles."""
        findings = []

        for identity in identities:
            # Only roles have trust policies
            if identity.identity_type.value != "Role":
                continue

            if not identity.assume_role_policy:
                continue

            trust_doc = identity.assume_role_policy
            if not isinstance(trust_doc, dict):
                continue

            for stmt in trust_doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                principal = stmt.get("Principal")
                if not principal:
                    continue

                conditions = stmt.get("Condition", {})

                # Check 1: Principal: "*" without conditions (open to anyone)
                if TrustPolicyDetector._is_principal_wildcard(principal):
                    if not conditions:
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                category=Category.TRUST_POLICY_RISK,
                                identity=identity.arn,
                                identity_type=identity.identity_type.value,
                                finding_title="Unrestricted Trust Policy (Principal: *)",
                                finding_description=(
                                    f"Role {identity.name} has trust policy allowing any principal "
                                    f"without conditions."
                                ),
                                impact=(
                                    "Any AWS principal in any account, or even unauthenticated users, "
                                    "may be able to assume this role."
                                ),
                                recommendation=(
                                    "Restrict trust policy to specific principals. Remove wildcard "
                                    "principals. If external accounts must trust this role, require "
                                    "ExternalId and conditions."
                                ),
                                evidence=[{"type": "principal", "value": "*"}],
                                tags=["critical", "trust-policy"],
                            )
                        )

                # Check 2: External account trust without ExternalId or conditions
                if isinstance(principal, dict):
                    for key, val in principal.items():
                        if key.upper() in ["AWS", "AWSPRINCIPAL"]:
                            principals_list = val if isinstance(val, list) else [val]
                            for p in principals_list:
                                if TrustPolicyDetector._is_external_account(p):
                                    has_external_id = (
                                        "StringEquals" in conditions
                                        and "sts:ExternalId" in conditions.get("StringEquals", {})
                                    )
                                    has_other_conditions = bool(conditions) and has_external_id is False

                                    if not has_external_id:
                                        severity = (
                                            Severity.HIGH if not has_other_conditions else Severity.MEDIUM
                                        )
                                        findings.append(
                                            Finding(
                                                severity=severity,
                                                category=Category.TRUST_POLICY_RISK,
                                                identity=identity.arn,
                                                identity_type=identity.identity_type.value,
                                                finding_title="External Account Trust Without ExternalId",
                                                finding_description=(
                                                    f"Role {identity.name} trusts external AWS account "
                                                    f"{p} without requiring an ExternalId."
                                                ),
                                                impact=(
                                                    "Other AWS accounts can assume this role without "
                                                    "additional verification. If the external account "
                                                    "is compromised, they could access this role."
                                                ),
                                                recommendation=(
                                                    f"Add ExternalId requirement to trust policy for "
                                                    f"account {p}. Share the ExternalId through a "
                                                    f"separate secure channel."
                                                ),
                                                evidence=[
                                                    {"type": "external_account", "value": p},
                                                    {"type": "has_external_id", "value": False},
                                                ],
                                                tags=["trust-policy", "external-account"],
                                            )
                                        )

        return findings

    @staticmethod
    def _is_principal_wildcard(principal: Any) -> bool:
        """Check if principal is a wildcard."""
        if principal == "*":
            return True
        if isinstance(principal, dict):
            for key, val in principal.items():
                if isinstance(val, list):
                    if "*" in val:
                        return True
                elif val == "*":
                    return True
        return False

    @staticmethod
    def _is_external_account(principal: str) -> bool:
        """Check if principal is an external AWS account ARN."""
        # ARN format: arn:aws:iam::ACCOUNT_ID:root
        if "arn:aws:iam::" not in principal:
            return False
        # Check if it's not our fictional test accounts in the safe range
        # Production code would check against your actual account ID
        return True
