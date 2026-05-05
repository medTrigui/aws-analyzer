"""
Detection engines for privilege escalation paths and unused permissions.
"""

from typing import List, Dict, Set

from ..models import Finding, Identity, Policy, Severity, Category


class PrivilegeEscalationDetector:
    """Detects privilege escalation paths using attack graph."""

    @staticmethod
    def detect(identities: List[Identity], policies: List[Policy]) -> List[Finding]:
        """
        Detect privilege escalation paths.
        
        This is a simplified version. Phase 2 will include full graph traversal.
        For MVP, we detect known patterns.
        """
        findings = []

        # Build policy map
        policy_map = {}
        for policy in policies:
            policy_map[policy.name] = policy
            if policy.arn:
                policy_map[policy.arn] = policy

        for identity in identities:
            # Get all permissions
            all_actions = set()
            all_resources = set()

            for policy_arn in identity.attached_policies:
                if policy_arn in policy_map:
                    p = policy_map[policy_arn]
                    for stmt in p.statements:
                        if stmt.effect == "Allow":
                            all_actions.update(stmt.actions)
                            all_resources.update(stmt.resources)

            for policy_name in identity.inline_policies:
                if policy_name in policy_map:
                    p = policy_map[policy_name]
                    for stmt in p.statements:
                        if stmt.effect == "Allow":
                            all_actions.update(stmt.actions)
                            all_resources.update(stmt.resources)

            # Check known privilege escalation patterns
            patterns = [
                (
                    {"iam:PassRole", "lambda:CreateFunction"},
                    "Lambda Function with Elevated Role",
                    "iam:PassRole + lambda:CreateFunction"
                ),
                (
                    {"iam:PassRole", "ec2:RunInstances"},
                    "EC2 Instance with Elevated Role",
                    "iam:PassRole + ec2:RunInstances"
                ),
                (
                    {"iam:PutUserPolicy", "iam:GetUser"},
                    "Direct User Policy Modification",
                    "iam:PutUserPolicy"
                ),
                (
                    {"iam:AttachUserPolicy", "iam:GetUser"},
                    "Attach Policy to User",
                    "iam:AttachUserPolicy"
                ),
                (
                    {"iam:CreateAccessKey", "iam:GetUser"},
                    "Create Access Key for User",
                    "iam:CreateAccessKey"
                ),
            ]

            for pattern_actions, pattern_name, pattern_desc in patterns:
                if pattern_actions.issubset(all_actions):
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=Category.PRIVILEGE_ESCALATION,
                            identity=identity.arn,
                            identity_type=identity.identity_type.value,
                            finding_title=f"Potential Privilege Escalation: {pattern_name}",
                            finding_description=(
                                f"{identity.identity_type.value} {identity.name} has permissions "
                                f"({pattern_desc}) that could enable privilege escalation."
                            ),
                            attack_path=[
                                identity.arn,
                                "IAM Permission",
                                pattern_desc,
                                "[Elevated Role/Resource]",
                            ],
                            impact=(
                                f"This identity could potentially escalate privileges by "
                                f"using {pattern_desc}."
                            ),
                            recommendation=(
                                f"Restrict {', '.join(pattern_actions)} or add conditions "
                                f"limiting resource ARNs and actions."
                            ),
                            evidence=[
                                {"type": "permission", "value": action}
                                for action in pattern_actions
                            ],
                            tags=["privilege-escalation"],
                        )
                    )

        return findings


class UnusedPermissionsDetector:
    """Detects permissions granted but not used."""

    @staticmethod
    def detect(
        identities: List[Identity],
        policies: List[Policy],
        cloudtrail_api_calls: Dict[str, List[str]]
    ) -> List[Finding]:
        """
        Detect unused permissions by comparing granted vs. observed actions.
        """
        findings = []

        # Build policy map
        policy_map = {}
        for policy in policies:
            policy_map[policy.name] = policy
            if policy.arn:
                policy_map[policy.arn] = policy

        for identity in identities:
            # Get granted actions
            granted_actions = set()

            for policy_arn in identity.attached_policies:
                if policy_arn in policy_map:
                    p = policy_map[policy_arn]
                    for stmt in p.statements:
                        if stmt.effect == "Allow":
                            granted_actions.update(stmt.actions)

            for policy_name in identity.inline_policies:
                if policy_name in policy_map:
                    p = policy_map[policy_name]
                    for stmt in p.statements:
                        if stmt.effect == "Allow":
                            granted_actions.update(stmt.actions)

            # Get observed actions from CloudTrail
            observed_actions = set(cloudtrail_api_calls.get(identity.arn, []))

            # Find unused permissions
            unused = granted_actions - observed_actions

            if unused and len(unused) >= 3:  # Only flag if multiple unused permissions
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        category=Category.UNUSED_PERMISSIONS,
                        identity=identity.arn,
                        identity_type=identity.identity_type.value,
                        finding_title="Potentially Unused Permissions",
                        finding_description=(
                            f"{identity.identity_type.value} {identity.name} has permissions not "
                            f"observed in CloudTrail activity."
                        ),
                        impact=(
                            "Grants permissions that are not actively used increase the attack surface "
                            "and complicate audits."
                        ),
                        recommendation=(
                            "Review unused permissions and remove them if not needed. "
                            "Note: CloudTrail history is limited; absence of evidence is not proof "
                            "that a permission is unused."
                        ),
                        evidence=[
                            {"type": "unused_action", "value": action}
                            for action in sorted(list(unused))[:5]  # Show up to 5
                        ],
                        tags=["unused-permissions"],
                    )
                )

        return findings
