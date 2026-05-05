"""
Data ingestion package for IAM analyzer.
"""

from .cloudtrail_loader import CloudTrailLoader, CredentialReportLoader
from .iam_loader import IAMLoader

__all__ = [
    "IAMLoader",
    "CloudTrailLoader",
    "CredentialReportLoader",
]
