"""
Loaders for CloudTrail and credential report data.
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class CloudTrailLoader:
    """Loader for CloudTrail event logs."""

    @staticmethod
    def load_events(filepath: Path) -> List[Dict[str, Any]]:
        """Load CloudTrail events from JSON."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            events = data.get("Events", [])
            return events
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load CloudTrail events from {filepath}: {e}")

    @staticmethod
    def extract_api_calls(events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Extract API calls by principal/identity.
        
        Returns dict of {principal_arn: [api_call_1, api_call_2, ...]}
        """
        api_calls: Dict[str, List[str]] = {}
        
        for event in events:
            principal = event.get("userIdentity", {}).get("arn", "unknown")
            event_name = event.get("eventName", "Unknown")
            
            if principal not in api_calls:
                api_calls[principal] = []
            
            api_calls[principal].append(event_name)
        
        return api_calls

    @staticmethod
    def extract_denied_actions(events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count AccessDenied events by principal."""
        denied: Dict[str, int] = {}
        
        for event in events:
            if event.get("errorCode") == "AccessDenied":
                principal = event.get("userIdentity", {}).get("arn", "unknown")
                denied[principal] = denied.get(principal, 0) + 1
        
        return denied


class CredentialReportLoader:
    """Loader for IAM credential report CSV exports."""

    @staticmethod
    def load_report(filepath: Path) -> List[Dict[str, Any]]:
        """Load credential report from CSV."""
        try:
            records = []
            with open(filepath, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(row)
            return records
        except (FileNotFoundError, csv.Error) as e:
            raise ValueError(f"Failed to load credential report from {filepath}: {e}")

    @staticmethod
    def find_stale_access_keys(
        records: List[Dict[str, Any]], 
        days_threshold: int = 90
    ) -> List[Dict[str, Any]]:
        """
        Identify credentials that haven't been used recently.
        
        Args:
            records: Credential report records
            days_threshold: Days of inactivity to flag
            
        Returns:
            List of records with stale credentials
        """
        from datetime import datetime, timedelta
        
        stale_credentials = []
        threshold_date = datetime.utcnow() - timedelta(days=days_threshold)
        
        for record in records:
            user = record.get("user", "")
            
            # Check access key 1
            ak1_last_used = record.get("access_key_1_last_used_date")
            if ak1_last_used and ak1_last_used != "N/A":
                try:
                    ak1_date = datetime.fromisoformat(ak1_last_used.replace("Z", "+00:00"))
                    if ak1_date < threshold_date:
                        stale_credentials.append({
                            "user": user,
                            "type": "access_key_1",
                            "last_used": ak1_last_used,
                            "days_inactive": (datetime.utcnow() - ak1_date).days
                        })
                except (ValueError, AttributeError):
                    pass
            
            # Check access key 2
            ak2_last_used = record.get("access_key_2_last_used_date")
            if ak2_last_used and ak2_last_used != "N/A":
                try:
                    ak2_date = datetime.fromisoformat(ak2_last_used.replace("Z", "+00:00"))
                    if ak2_date < threshold_date:
                        stale_credentials.append({
                            "user": user,
                            "type": "access_key_2",
                            "last_used": ak2_last_used,
                            "days_inactive": (datetime.utcnow() - ak2_date).days
                        })
                except (ValueError, AttributeError):
                    pass
        
        return stale_credentials

    @staticmethod
    def find_mfa_issues(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find users with console access but no MFA."""
        mfa_issues = []
        
        for record in records:
            has_console = record.get("password_enabled", "false").lower() == "true"
            has_mfa = record.get("mfa_active", "false").lower() == "true"
            
            if has_console and not has_mfa:
                mfa_issues.append({
                    "user": record.get("user", ""),
                    "issue": "Console access enabled without MFA"
                })
        
        return mfa_issues

    @staticmethod
    def find_multiple_active_keys(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find users with multiple active access keys."""
        multi_key_users = []
        
        for record in records:
            ak1_active = record.get("access_key_1_active", "false").lower() == "true"
            ak2_active = record.get("access_key_2_active", "false").lower() == "true"
            
            if ak1_active and ak2_active:
                multi_key_users.append({
                    "user": record.get("user", ""),
                    "issue": "Multiple active access keys",
                    "keys": ["access_key_1", "access_key_2"]
                })
        
        return multi_key_users
