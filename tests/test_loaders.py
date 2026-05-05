"""
Unit tests for data loaders.
"""

import json
from pathlib import Path

import pytest

from analyzer.ingest import IAMLoader


@pytest.fixture
def sample_data_dir(tmp_path):
    """Create temporary directory with sample data."""
    users_data = {
        "Users": [
            {
                "Arn": "arn:aws:iam::111122223333:user/test",
                "UserName": "test",
                "CreateDate": "2024-01-01T00:00:00Z"
            }
        ]
    }

    roles_data = {
        "Roles": [
            {
                "Arn": "arn:aws:iam::111122223333:role/TestRole",
                "RoleName": "TestRole",
                "CreateDate": "2024-01-01T00:00:00Z",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": []
                }
            }
        ]
    }

    policies_data = {
        "Policies": [
            {
                "Arn": "arn:aws:iam::111122223333:policy/TestPolicy",
                "PolicyName": "TestPolicy",
                "CreateDate": "2024-01-01T00:00:00Z",
                "UpdateDate": "2024-01-01T00:00:00Z",
                "AttachmentCount": 0,
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*"
                        }
                    ]
                }
            }
        ]
    }

    users_path = tmp_path / "users.json"
    roles_path = tmp_path / "roles.json"
    policies_path = tmp_path / "managed_policies.json"

    with open(users_path, "w") as f:
        json.dump(users_data, f)

    with open(roles_path, "w") as f:
        json.dump(roles_data, f)

    with open(policies_path, "w") as f:
        json.dump(policies_data, f)

    return tmp_path


class TestIAMLoader:
    """Tests for IAMLoader."""

    def test_load_users(self, sample_data_dir):
        """Test loading users."""
        users = IAMLoader.load_users(sample_data_dir / "users.json")

        assert len(users) == 1
        assert users[0].name == "test"
        assert users[0].identity_type.value == "User"

    def test_load_roles(self, sample_data_dir):
        """Test loading roles."""
        roles = IAMLoader.load_roles(sample_data_dir / "roles.json")

        assert len(roles) == 1
        assert roles[0].name == "TestRole"
        assert roles[0].identity_type.value == "Role"

    def test_load_managed_policies(self, sample_data_dir):
        """Test loading managed policies."""
        policies = IAMLoader.load_managed_policies(sample_data_dir / "managed_policies.json")

        assert len(policies) == 1
        assert policies[0].name == "TestPolicy"
        assert len(policies[0].statements) == 1

    def test_load_all_from_directory(self, sample_data_dir):
        """Test loading all data from directory."""
        identities, policies = IAMLoader.load_all_from_directory(sample_data_dir)

        assert len(identities) == 2  # 1 user + 1 role
        assert len(policies) == 1

    def test_missing_files(self, tmp_path):
        """Test behavior with missing files."""
        # Should not raise error, just return empty lists for missing files
        identities, policies = IAMLoader.load_all_from_directory(tmp_path)

        assert identities == []
        assert policies == []

    def test_invalid_json(self, tmp_path):
        """Test behavior with invalid JSON."""
        invalid_file = tmp_path / "users.json"
        with open(invalid_file, "w") as f:
            f.write("invalid json {")

        with pytest.raises(ValueError):
            IAMLoader.load_users(invalid_file)
