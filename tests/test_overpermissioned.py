"""
Unit tests for over-permissioned identity detector.
"""

import pytest

from analyzer.detections import OverPermissionedDetector
from analyzer.models import Identity, IdentityType, Policy, PolicyType, Statement


@pytest.fixture
def sample_policies():
    """Create sample policies for testing."""
    # Admin policy
    admin_policy = Policy(
        name="AdminPolicy",
        policy_type=PolicyType.MANAGED,
        statements=[
            Statement(effect="Allow", actions=["*"], resources=["*"])
        ],
    )

    # DevOps policy with privilege escalation risk
    devops_policy = Policy(
        name="DevOpsPolicy",
        policy_type=PolicyType.MANAGED,
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:PassRole", "lambda:CreateFunction"],
                resources=["*"]
            )
        ],
    )

    # Safe policy
    safe_policy = Policy(
        name="S3ReadPolicy",
        policy_type=PolicyType.MANAGED,
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=["arn:aws:s3:::bucket/*"]
            )
        ],
    )

    return {
        "admin": admin_policy,
        "devops": devops_policy,
        "safe": safe_policy,
    }


@pytest.fixture
def sample_identities(sample_policies):
    """Create sample identities for testing."""
    alice = Identity(
        arn="arn:aws:iam::111122223333:user/alice",
        name="alice",
        identity_type=IdentityType.USER,
        attached_policies=["AdminPolicy"],
    )

    bob = Identity(
        arn="arn:aws:iam::111122223333:user/bob",
        name="bob",
        identity_type=IdentityType.USER,
        attached_policies=["DevOpsPolicy"],
    )

    charlie = Identity(
        arn="arn:aws:iam::111122223333:user/charlie",
        name="charlie",
        identity_type=IdentityType.USER,
        attached_policies=["S3ReadPolicy"],
    )

    return [alice, bob, charlie]


class TestOverPermissionedDetector:
    """Tests for OverPermissionedDetector."""

    def test_detects_wildcard_admin(self, sample_identities, sample_policies):
        """Test detection of wildcard admin access."""
        findings = OverPermissionedDetector.detect(
            sample_identities,
            [sample_policies["admin"], sample_policies["devops"], sample_policies["safe"]]
        )

        # Should find alice with admin access
        admin_findings = [f for f in findings if "alice" in f.identity]
        assert len(admin_findings) > 0
        assert any(f.finding_title == "Wildcard Admin Access (Action: *, Resource: *)" for f in admin_findings)

    def test_detects_privilege_escalation_combo(self, sample_identities, sample_policies):
        """Test detection of privilege escalation combinations."""
        findings = OverPermissionedDetector.detect(
            sample_identities,
            [sample_policies["admin"], sample_policies["devops"], sample_policies["safe"]]
        )

        # Should find bob with dangerous combo
        devops_findings = [f for f in findings if "bob" in f.identity]
        assert len(devops_findings) > 0
        assert any("iam:PassRole" in f.finding_title or "lambda" in f.finding_title for f in devops_findings)

    def test_does_not_flag_safe_permissions(self, sample_identities, sample_policies):
        """Test that safe permissions are not flagged."""
        findings = OverPermissionedDetector.detect(
            sample_identities,
            [sample_policies["admin"], sample_policies["devops"], sample_policies["safe"]]
        )

        # Should not find findings for charlie with safe policy
        charlie_findings = [f for f in findings if "charlie" in f.identity]
        assert len(charlie_findings) == 0


class TestOverPermissionedDetectorEdgeCases:
    """Edge case tests for OverPermissionedDetector."""

    def test_empty_identity_list(self):
        """Test with empty identity list."""
        findings = OverPermissionedDetector.detect([], [])
        assert len(findings) == 0

    def test_identity_without_policies(self):
        """Test identity with no attached policies."""
        identity = Identity(
            arn="arn:aws:iam::111122223333:user/unprivileged",
            name="unprivileged",
            identity_type=IdentityType.USER,
            attached_policies=[],
            inline_policies=[],
        )

        findings = OverPermissionedDetector.detect([identity], [])
        assert len(findings) == 0
