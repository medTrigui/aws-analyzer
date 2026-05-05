"""
Detection engine for risky service account behavior.
"""

from typing import List, Dict

from ..models import Finding, Severity, Category


class ServiceAccountBehaviorDetector:
    """Detects risky patterns in service account activity."""

    @staticmethod
    def detect(
        cloudtrail_events: List[Dict],
        identity_arns: List[str]
    ) -> List[Finding]:
        """
        Detect suspicious service account behavior from CloudTrail.
        """
        findings = []

        # Count API calls and errors per principal
        api_calls_by_principal = {}
        denied_by_principal = {}
        iam_actions_by_principal = {}

        for event in cloudtrail_events:
            principal = event.get("userIdentity", {}).get("arn", "unknown")
            event_name = event.get("eventName", "")

            if principal not in api_calls_by_principal:
                api_calls_by_principal[principal] = []
                denied_by_principal[principal] = 0
                iam_actions_by_principal[principal] = []

            api_calls_by_principal[principal].append(event_name)

            # Track denied actions
            if event.get("errorCode") == "AccessDenied":
                denied_by_principal[principal] += 1

            # Track IAM modification actions
            if event_name.startswith("Iam") or event_name.startswith("Sts"):
                iam_actions_by_principal[principal].append(event_name)

        # Detect patterns
        for principal in identity_arns:
            # Check 1: High AccessDenied rate (indicates permission issues or attack)
            denied_count = denied_by_principal.get(principal, 0)
            total_calls = len(api_calls_by_principal.get(principal, []))

            if total_calls > 0:
                denied_rate = denied_count / total_calls
                if denied_rate > 0.3 and denied_count > 10:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category=Category.RISKY_BEHAVIOR,
                            identity=principal,
                            finding_title="High AccessDenied Event Rate",
                            finding_description=(
                                f"Principal {principal} has a high rate of AccessDenied errors "
                                f"({denied_count}/{total_calls})."
                            ),
                            impact=(
                                "High error rates could indicate permission issues, misconfigurations, "
                                "or potential exploitation attempts."
                            ),
                            recommendation=(
                                "Review recent activity and CloudTrail logs for this principal. "
                                "Verify that permissions are correctly configured."
                            ),
                            evidence=[
                                {"type": "denied_count", "value": denied_count},
                                {"type": "total_calls", "value": total_calls},
                            ],
                            tags=["unusual-behavior", "access-denied"],
                        )
                    )

            # Check 2: Service account performing IAM modifications
            iam_actions = iam_actions_by_principal.get(principal, [])
            dangerous_iam = {
                "CreateUser", "CreateRole", "AttachUserPolicy", "AttachRolePolicy",
                "PutUserPolicy", "PutRolePolicy", "CreateAccessKey", "UpdateAssumeRolePolicy"
            }

            dangerous_actions = [a for a in iam_actions if a in dangerous_iam]
            if dangerous_actions:
                # Check if this looks like a service account (role rather than user)
                if ":role/" in principal.lower():
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=Category.RISKY_BEHAVIOR,
                            identity=principal,
                            finding_title="Service Role Performing IAM Modifications",
                            finding_description=(
                                f"Service role {principal} is performing IAM modification actions: "
                                f"{', '.join(sorted(set(dangerous_actions)))}"
                            ),
                            impact=(
                                "Service accounts should not perform IAM modifications. This could "
                                "indicate a compromised role or overly permissive services."
                            ),
                            recommendation=(
                                "Review why this service role needs IAM modification permissions. "
                                "Restrict to specific required actions and resources."
                            ),
                            evidence=[
                                {"type": "iam_action", "value": action}
                                for action in sorted(set(dangerous_actions))
                            ],
                            tags=["service-account", "iam-modification"],
                        )
                    )

        return findings
