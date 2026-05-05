"""
Unit tests for trust policy detector.
"""

import pytest

from analyzer.detections import TrustPolicyDetector
from analyzer.models import Identity, IdentityType


@pytest.fixture
def sample_roles():
    """Create sample roles for testing."""
    # Role with wildcard principal
    wildcard_role = Identity(
        arn="arn:aws:iam::111122223333:role/WildcardRole",
        name="WildcardRole",
        identity_type=IdentityType.ROLE,
        assume_role_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    )

    # Role trusting external account without ExternalId
    risky_external = Identity(
        arn="arn:aws:iam::111122223333:role/ExternalAccessRole",
        name="ExternalAccessRole",
        identity_type=IdentityType.ROLE,
        assume_role_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::444455556666:root"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    )

    # Safe role with ExternalId
    safe_external = Identity(
        arn="arn:aws:iam::111122223333:role/SafeExternalRole",
        name="SafeExternalRole",
        identity_type=IdentityType.ROLE,
        assume_role_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::444455556666:root"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "unique-external-id-12345"
                        }
                    }
                }
            ]
        }
    )

    return {
        "wildcard": wildcard_role,
        "risky_external": risky_external,
        "safe_external": safe_external,
    }


class TestTrustPolicyDetector:
    """Tests for TrustPolicyDetector."""

    def test_detects_wildcard_principal(self, sample_roles):
        """Test detection of wildcard principal without conditions."""
        findings = TrustPolicyDetector.detect([sample_roles["wildcard"]])

        assert len(findings) > 0
        assert any(
            "unrestricted" in f.finding_title.lower()
            for f in findings
        )

    def test_detects_external_without_external_id(self, sample_roles):
        """Test detection of external account trust without ExternalId."""
        findings = TrustPolicyDetector.detect([sample_roles["risky_external"]])

        assert len(findings) > 0
        assert any(
            "ExternalId" in f.finding_title
            for f in findings
        )

    def test_does_not_flag_safe_external_trust(self, sample_roles):
        """Test that properly configured external trust is not flagged."""
        findings = TrustPolicyDetector.detect([sample_roles["safe_external"]])

        # Should have few or no findings for safe configuration
        assert len(findings) == 0

    def test_user_without_trust_policy(self):
        """Test that users (which don't have trust policies) don't cause errors."""
        user = Identity(
            arn="arn:aws:iam::111122223333:user/alice",
            name="alice",
            identity_type=IdentityType.USER,
        )

        findings = TrustPolicyDetector.detect([user])
        assert len(findings) == 0

    def test_empty_role_list(self):
        """Test with empty role list."""
        findings = TrustPolicyDetector.detect([])
        assert len(findings) == 0
