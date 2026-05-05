"""
Tests for the main analyzer.
"""

from pathlib import Path
import json

import pytest

from analyzer.analyzer import IAMAnalyzer


@pytest.fixture
def sample_data_dir(tmp_path):
    """Create a temporary directory with sample IAM data."""
    # Create minimal sample data
    users = {"Users": []}
    roles = {"Roles": []}
    policies = {"Policies": []}

    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "roles.json").write_text(json.dumps(roles))
    (tmp_path / "managed_policies.json").write_text(json.dumps(policies))

    return tmp_path


class TestIAMAnalyzer:
    """Tests for IAMAnalyzer."""

    def test_scan_with_minimal_data(self, sample_data_dir, tmp_path):
        """Test scanning with minimal data."""
        analyzer = IAMAnalyzer(verbose=False)
        output_dir = tmp_path / "output"

        result = analyzer.scan(
            input_dir=sample_data_dir,
            output_dir=output_dir,
            json_report=True,
            markdown_report=True,
            html_report=True,
        )

        # Should have metadata
        assert result.metadata is not None
        assert result.metadata.total_findings >= 0

    def test_report_generation(self, sample_data_dir, tmp_path):
        """Test that reports are generated."""
        analyzer = IAMAnalyzer(verbose=False)
        output_dir = tmp_path / "output"

        analyzer.scan(
            input_dir=sample_data_dir,
            output_dir=output_dir,
            json_report=True,
            markdown_report=True,
            html_report=True,
        )

        # Check that files were created
        assert (output_dir / "findings.json").exists()
        assert (output_dir / "findings.md").exists()
        assert (output_dir / "findings.html").exists()

    def test_json_report_valid(self, sample_data_dir, tmp_path):
        """Test that JSON report is valid."""
        analyzer = IAMAnalyzer(verbose=False)
        output_dir = tmp_path / "output"

        analyzer.scan(
            input_dir=sample_data_dir,
            output_dir=output_dir,
            json_report=True,
            markdown_report=False,
            html_report=False,
        )

        # Load and parse JSON
        with open(output_dir / "findings.json") as f:
            data = json.load(f)

        assert "metadata" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_selective_report_generation(self, sample_data_dir, tmp_path):
        """Test generating only selected reports."""
        analyzer = IAMAnalyzer(verbose=False)
        output_dir = tmp_path / "output"

        analyzer.scan(
            input_dir=sample_data_dir,
            output_dir=output_dir,
            json_report=True,
            markdown_report=False,
            html_report=False,
        )

        assert (output_dir / "findings.json").exists()
        assert not (output_dir / "findings.md").exists()
        assert not (output_dir / "findings.html").exists()
