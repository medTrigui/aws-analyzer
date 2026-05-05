"""
Detection engine for stale credentials.
"""

from typing import List

from ..ingest import CredentialReportLoader
from ..models import Finding, Severity, Category


class StaleCredentialsDetector:
    """Detects stale and risky credentials."""

    @staticmethod
    def detect_from_credential_report(
        credential_report_records: List[dict],
        days_threshold: int = 90
    ) -> List[Finding]:
        """Detect stale credentials from credential report."""
        findings = []

        # Find stale access keys
        stale = CredentialReportLoader.find_stale_access_keys(
            credential_report_records, days_threshold
        )
        for stale_cred in stale:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=Category.STALE_CREDENTIALS,
                    identity=stale_cred["user"],
                    finding_title=f"Stale {stale_cred['type'].replace('_', ' ').title()}",
                    finding_description=(
                        f"User {stale_cred['user']} has {stale_cred['type'].replace('_', ' ')} "
                        f"inactive for {stale_cred['days_inactive']} days."
                    ),
                    impact=(
                        "Unused credentials increase the risk of undetected compromise. "
                        "Stale keys may belong to unused accounts or former employees."
                    ),
                    recommendation=(
                        f"Rotate or delete the {stale_cred['type'].replace('_', ' ')}. "
                        "Consider disabling accounts not actively used."
                    ),
                    evidence=[
                        {"type": "last_used", "value": stale_cred["last_used"]},
                        {"type": "days_inactive", "value": stale_cred["days_inactive"]},
                    ],
                    tags=["stale-credentials"],
                )
            )

        # Find MFA issues
        mfa_issues = CredentialReportLoader.find_mfa_issues(credential_report_records)
        for issue in mfa_issues:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category=Category.STALE_CREDENTIALS,
                    identity=issue["user"],
                    finding_title="Console Access Without MFA",
                    finding_description=(
                        f"User {issue['user']} has console password enabled but no MFA device "
                        "configured."
                    ),
                    impact=(
                        "If credentials are compromised, attackers have full console access "
                        "without additional authentication."
                    ),
                    recommendation=(
                        f"Require MFA for all human users. Disable console access for service "
                        "accounts and use only access keys with programmatic access."
                    ),
                    evidence=[{"type": "mfa_status", "value": "disabled"}],
                    tags=["mfa", "access-control"],
                )
            )

        # Find multiple active access keys
        multi_keys = CredentialReportLoader.find_multiple_active_keys(credential_report_records)
        for user_keys in multi_keys:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category=Category.STALE_CREDENTIALS,
                    identity=user_keys["user"],
                    finding_title="Multiple Active Access Keys",
                    finding_description=(
                        f"User {user_keys['user']} has {len(user_keys['keys'])} active access keys."
                    ),
                    impact=(
                        "Multiple active keys increase the attack surface. If one key is "
                        "compromised, reduce blast radius by limiting active keys."
                    ),
                    recommendation=(
                        "Rotate access keys regularly. Keep only one active key per user. "
                        "Deactivate old keys before deleting them."
                    ),
                    evidence=[{"type": "active_keys", "value": user_keys["keys"]}],
                    tags=["key-rotation"],
                )
            )

        return findings
