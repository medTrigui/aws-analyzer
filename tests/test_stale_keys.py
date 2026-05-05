"""
Unit tests for stale credentials detector.
"""

import pytest

from analyzer.detections import StaleCredentialsDetector


@pytest.fixture
def sample_credential_report():
    """Create sample credential report records."""
    return [
        {
            "user": "alice",
            "arn": "arn:aws:iam::111122223333:user/alice",
            "user_creation_time": "2024-01-15T10:30:00+00:00",
            "password_enabled": "true",
            "password_last_changed": "2024-04-01T10:30:00+00:00",
            "mfa_active": "false",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": "2024-01-15T10:30:00+00:00",
            "access_key_1_last_used_date": "2024-05-03T14:22:00+00:00",
            "access_key_2_active": "false",
            "access_key_2_last_used_date": "N/A",
        },
        {
            "user": "bob",
            "arn": "arn:aws:iam::111122223333:user/bob",
            "user_creation_time": "2024-02-20T14:15:00+00:00",
            "password_enabled": "true",
            "password_last_changed": "2024-03-01T14:15:00+00:00",
            "mfa_active": "false",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": "2024-02-20T14:15:00+00:00",
            "access_key_1_last_used_date": "2023-12-10T16:40:00+00:00",  # Stale
            "access_key_2_active": "true",
            "access_key_2_last_rotated": "2024-03-15T10:00:00+00:00",
            "access_key_2_last_used_date": "2024-04-20T09:10:00+00:00",
        },
        {
            "user": "charlie",
            "arn": "arn:aws:iam::111122223333:user/charlie",
            "user_creation_time": "2024-03-10T09:45:00+00:00",
            "password_enabled": "true",
            "password_last_changed": "2024-04-01T09:45:00+00:00",
            "mfa_active": "true",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": "2024-03-10T09:45:00+00:00",
            "access_key_1_last_used_date": "N/A",  # Never used
            "access_key_2_active": "false",
            "access_key_2_last_used_date": "N/A",
        }
    ]


class TestStaleCredentialsDetector:
    """Tests for StaleCredentialsDetector."""

    def test_detects_mfa_missing_on_console_access(self, sample_credential_report):
        """Test detection of console access without MFA."""
        findings = StaleCredentialsDetector.detect_from_credential_report(sample_credential_report)

        # alice and bob should be flagged (no MFA)
        mfa_findings = [f for f in findings if "MFA" in f.finding_title]
        assert len(mfa_findings) >= 2

    def test_detects_stale_access_keys(self, sample_credential_report):
        """Test detection of stale access keys."""
        findings = StaleCredentialsDetector.detect_from_credential_report(sample_credential_report)

        # bob's access_key_1 should be stale
        stale_findings = [f for f in findings if "Stale" in f.finding_title]
        assert len(stale_findings) > 0

    def test_detects_multiple_active_keys(self, sample_credential_report):
        """Test detection of multiple active access keys."""
        findings = StaleCredentialsDetector.detect_from_credential_report(sample_credential_report)

        # bob has 2 active keys
        multi_key_findings = [f for f in findings if "Multiple" in f.finding_title]
        assert len(multi_key_findings) > 0

    def test_empty_credential_report(self):
        """Test with empty credential report."""
        findings = StaleCredentialsDetector.detect_from_credential_report([])
        # Should have no findings for empty report
        assert isinstance(findings, list)

    def test_respects_threshold_parameter(self, sample_credential_report):
        """Test that days_threshold parameter is respected."""
        # With a very high threshold, should find fewer stale credentials
        findings_90 = StaleCredentialsDetector.detect_from_credential_report(
            sample_credential_report, days_threshold=90
        )
        findings_200 = StaleCredentialsDetector.detect_from_credential_report(
            sample_credential_report, days_threshold=200
        )

        # Should have fewer stale findings with higher threshold
        stale_90 = [f for f in findings_90 if "Stale" in f.finding_title]
        stale_200 = [f for f in findings_200 if "Stale" in f.finding_title]

        assert len(stale_90) >= len(stale_200)
