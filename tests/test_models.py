"""
Tests for data models.
"""

import pytest

from analyzer.models import (
    Category,
    Finding,
    Identity,
    IdentityType,
    Policy,
    PolicyType,
    ScanMetadata,
    ScanResult,
    Severity,
    Statement,
)


class TestIdentityModel:
    """Tests for Identity model."""

    def test_identity_creation(self):
        """Test creating an identity."""
        identity = Identity(
            arn="arn:aws:iam::111122223333:user/test",
            name="test",
            identity_type=IdentityType.USER,
        )

        assert identity.arn == "arn:aws:iam::111122223333:user/test"
        assert identity.name == "test"
        assert identity.identity_type == IdentityType.USER

    def test_identity_hash(self):
        """Test that identities can be hashed."""
        identity1 = Identity(
            arn="arn:aws:iam::111122223333:user/test",
            name="test",
            identity_type=IdentityType.USER,
        )
        identity2 = Identity(
            arn="arn:aws:iam::111122223333:user/test",
            name="test",
            identity_type=IdentityType.USER,
        )

        assert hash(identity1) == hash(identity2)

    def test_identity_equality(self):
        """Test identity equality by ARN."""
        identity1 = Identity(
            arn="arn:aws:iam::111122223333:user/test",
            name="test",
            identity_type=IdentityType.USER,
        )
        identity2 = Identity(
            arn="arn:aws:iam::111122223333:user/test",
            name="test_renamed",  # Different name
            identity_type=IdentityType.USER,
        )

        assert identity1 == identity2  # Should be equal by ARN


class TestPolicyModel:
    """Tests for Policy model."""

    def test_policy_creation(self):
        """Test creating a policy."""
        stmt = Statement(
            effect="Allow",
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::bucket/*"]
        )

        policy = Policy(
            name="TestPolicy",
            policy_type=PolicyType.MANAGED,
            statements=[stmt]
        )

        assert policy.name == "TestPolicy"
        assert len(policy.statements) == 1

    def test_policy_with_multiple_statements(self):
        """Test policy with multiple statements."""
        statements = [
            Statement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=["arn:aws:s3:::bucket/*"]
            ),
            Statement(
                effect="Deny",
                actions=["s3:DeleteObject"],
                resources=["*"]
            )
        ]

        policy = Policy(
            name="MultiStmtPolicy",
            policy_type=PolicyType.INLINE,
            statements=statements
        )

        assert len(policy.statements) == 2
        assert policy.statements[0].effect == "Allow"
        assert policy.statements[1].effect == "Deny"


class TestFindingModel:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            severity=Severity.HIGH,
            category=Category.PRIVILEGE_ESCALATION,
            identity="arn:aws:iam::111122223333:user/alice",
            identity_type="User",
            finding_title="Test Finding",
            finding_description="This is a test finding",
            impact="Potential impact",
            recommendation="Do something",
        )

        assert finding.severity == Severity.HIGH
        assert finding.category == Category.PRIVILEGE_ESCALATION
        assert finding.finding_title == "Test Finding"

    def test_finding_with_attack_path(self):
        """Test finding with attack path."""
        finding = Finding(
            severity=Severity.CRITICAL,
            category=Category.PRIVILEGE_ESCALATION,
            identity="arn:aws:iam::111122223333:user/alice",
            finding_title="Escalation Path",
            finding_description="Test",
            impact="Test",
            recommendation="Test",
            attack_path=[
                "alice",
                "policy",
                "iam:PassRole",
                "lambda:CreateFunction",
                "AdminRole"
            ]
        )

        assert len(finding.attack_path) == 5
        assert finding.attack_path[0] == "alice"


class TestScanResultModel:
    """Tests for ScanResult model."""

    def test_scan_result_creation(self):
        """Test creating scan result."""
        metadata = ScanMetadata(
            timestamp="2024-05-03T10:00:00Z",
            total_identities=5,
            total_policies=10,
            total_findings=0,
            findings_by_severity={},
            findings_by_category={},
        )

        result = ScanResult(metadata=metadata, findings=[])

        assert result.metadata.total_identities == 5
        assert result.metadata.total_policies == 10
        assert len(result.findings) == 0

    def test_add_finding(self):
        """Test adding finding to scan result."""
        metadata = ScanMetadata(
            timestamp="2024-05-03T10:00:00Z",
            total_identities=1,
            total_policies=1,
            total_findings=0,
            findings_by_severity={},
            findings_by_category={},
        )

        result = ScanResult(metadata=metadata, findings=[])

        finding = Finding(
            severity=Severity.HIGH,
            category=Category.OVER_PERMISSIONED,
            identity="test",
            finding_title="Test",
            finding_description="Test",
            impact="Test",
            recommendation="Test",
        )

        result.add_finding(finding)

        assert len(result.findings) == 1
        assert result.metadata.total_findings == 1
        assert result.metadata.findings_by_severity["HIGH"] == 1
        assert result.metadata.findings_by_category["Over-Permissioned"] == 1
