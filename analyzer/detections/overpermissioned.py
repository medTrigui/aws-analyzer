"""
Detection engine for over-permissioned identities.
"""

from typing import List

from ..models import Finding, Identity, Policy, Severity, Category


class OverPermissionedDetector:
    """Detects identities with excessive permissions."""

    # High-risk permissions that indicate privilege escalation risk
    PRIVILEGE_ESCALATION_PERMS = {
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole",
    }

    # Dangerous combinations that enable privilege escalation
    DANGEROUS_COMBOS = [
        {"iam:PassRole", "lambda:CreateFunction"},
        {"iam:PassRole", "ec2:RunInstances"},
        {"iam:PassRole", "ecs:CreateTaskSet"},
        {"iam:PassRole", "codebuild:CreateProject"},
        {"iam:PassRole", "glue:CreateJobDefinition"},
        {"iam:CreatePolicyVersion", "iam:GetPolicyVersion"},  # Can modify policies
    ]

    # Administrative service permissions that are dangerous
    ADMIN_PERMISSIONS = {
        "iam:*",
        "ec2:*",
        "s3:*",
        "lambda:*",
        "cloudformation:*",
        "secretsmanager:*",
        "kms:*",
        "rds-db:*",
        "dynamodb:*",
        "redshift:*",
    }

    @staticmethod
    def detect(identities: List[Identity], policies: List[Policy]) -> List[Finding]:
        """Detect over-permissioned identities."""
        findings = []

        # Build a map of policy ARNs/names to policy objects
        policy_map = {}
        for policy in policies:
            policy_map[policy.name] = policy
            if policy.arn:
                policy_map[policy.arn] = policy

        for identity in identities:
            # Get all policies attached to this identity
            attached_policies = []
            for policy_arn in identity.attached_policies:
                if policy_arn in policy_map:
                    attached_policies.append(policy_map[policy_arn])

            for policy_name in identity.inline_policies:
                if policy_name in policy_map:
                    attached_policies.append(policy_map[policy_name])

            # Check for over-permissioned access
            all_actions = set()
            all_resources = set()

            for policy in attached_policies:
                for stmt in policy.statements:
                    if stmt.effect == "Allow":
                        all_actions.update(stmt.actions)
                        all_resources.update(stmt.resources)

            # Finding 1: Wildcard everything (Action: * and Resource: *)
            if "*" in all_actions and "*" in all_resources:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category=Category.OVER_PERMISSIONED,
                        identity=identity.arn,
                        identity_type=identity.identity_type.value,
                        finding_title="Wildcard Admin Access (Action: *, Resource: *)",
                        finding_description=(
                            f"{identity.identity_type.value} {identity.name} has unrestricted "
                            "permissions to all AWS actions on all resources."
                        ),
                        impact=(
                            "This identity has full administrative access to all AWS resources "
                            "and can perform any action."
                        ),
                        recommendation=(
                            "Apply principle of least privilege. Replace with specific actions "
                            "and resource ARNs required for job functions."
                        ),
                        evidence=[
                            {"type": "policy_action", "value": "*"},
                            {"type": "policy_resource", "value": "*"},
                        ],
                        tags=["critical", "over-permissioned"],
                    )
                )

            # Finding 2: Admin service permissions
            admin_perms = all_actions & OverPermissionedDetector.ADMIN_PERMISSIONS
            if admin_perms:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category=Category.OVER_PERMISSIONED,
                        identity=identity.arn,
                        identity_type=identity.identity_type.value,
                        finding_title=f"Administrative Service Permissions",
                        finding_description=(
                            f"{identity.identity_type.value} {identity.name} has administrative "
                            f"permissions: {', '.join(sorted(admin_perms))}"
                        ),
                        impact=(
                            "This identity has extensive permissions to critical AWS services "
                            "and could potentially compromise security."
                        ),
                        recommendation=(
                            "Review and restrict these permissions. Use service control policies "
                            "(SCPs) to limit risky actions."
                        ),
                        evidence=[{"type": "admin_permission", "value": perm} for perm in admin_perms],
                        tags=["high-risk", "admin-service"],
                    )
                )

            # Finding 3: Dangerous permission combinations
            for combo in OverPermissionedDetector.DANGEROUS_COMBOS:
                if combo.issubset(all_actions):
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            category=Category.OVER_PERMISSIONED,
                            identity=identity.arn,
                            identity_type=identity.identity_type.value,
                            finding_title=f"Dangerous Permission Combination",
                            finding_description=(
                                f"{identity.identity_type.value} {identity.name} has dangerous "
                                f"permission combination: {' + '.join(sorted(combo))}"
                            ),
                            impact=(
                                f"These permissions together enable privilege escalation. "
                                f"For example, {' + '.join(combo)} allows creating resources "
                                f"with elevated permissions."
                            ),
                            recommendation=(
                                "Separate these permissions across different roles or add "
                                "restrictive conditions (e.g., IP restrictions, resource ARNs)."
                            ),
                            evidence=[{"type": "permission_combo", "value": perm} for perm in combo],
                            tags=["privilege-escalation", "combo-risk"],
                        )
                    )

            # Finding 4: Other escalation permissions
            escalation_perms = all_actions & OverPermissionedDetector.PRIVILEGE_ESCALATION_PERMS
            if escalation_perms and not any(
                # Skip if already reported as combo finding
                combo.issubset(all_actions) for combo in OverPermissionedDetector.DANGEROUS_COMBOS
            ):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category=Category.OVER_PERMISSIONED,
                        identity=identity.arn,
                        identity_type=identity.identity_type.value,
                        finding_title="Escalation-Enabling Permissions",
                        finding_description=(
                            f"{identity.identity_type.value} {identity.name} has permissions "
                            f"that could enable privilege escalation: {', '.join(sorted(escalation_perms))}"
                        ),
                        impact=(
                            "These permissions could be combined with other actions to escalate "
                            "privileges, though no immediate exploit path was identified."
                        ),
                        recommendation=(
                            "Review the necessity of these permissions. Add restrictive conditions "
                            "such as resource constraints or IP/time-based restrictions."
                        ),
                        evidence=[{"type": "escalation_perm", "value": perm} for perm in escalation_perms],
                        tags=["escalation-risk"],
                    )
                )

        return findings
