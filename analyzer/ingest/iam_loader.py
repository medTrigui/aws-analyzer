"""
Data loaders for IAM configuration (JSON exports).
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from ..models import Identity, IdentityType, Policy, PolicyType, Statement


class IAMLoader:
    """Loader for IAM configuration data from AWS exports."""

    @staticmethod
    def load_users(filepath: Path) -> List[Identity]:
        """Load users from exported JSON."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            users = []
            user_list = data.get("Users", [])
            
            for user in user_list:
                identity = Identity(
                    arn=user.get("Arn", ""),
                    name=user.get("UserName", ""),
                    identity_type=IdentityType.USER,
                    created_date=user.get("CreateDate"),
                    tags=_extract_tags(user.get("Tags", [])),
                    metadata={"original_data": user}
                )
                users.append(identity)
            
            return users
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load users from {filepath}: {e}")

    @staticmethod
    def load_roles(filepath: Path) -> List[Identity]:
        """Load roles from exported JSON."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            roles = []
            role_list = data.get("Roles", [])
            
            for role in role_list:
                identity = Identity(
                    arn=role.get("Arn", ""),
                    name=role.get("RoleName", ""),
                    identity_type=IdentityType.ROLE,
                    created_date=role.get("CreateDate"),
                    assume_role_policy=role.get("AssumeRolePolicyDocument"),
                    max_session_duration=role.get("MaxSessionDuration"),
                    tags=_extract_tags(role.get("Tags", [])),
                    metadata={"original_data": role}
                )
                roles.append(identity)
            
            return roles
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load roles from {filepath}: {e}")

    @staticmethod
    def load_groups(filepath: Path) -> List[Identity]:
        """Load groups from exported JSON."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            groups = []
            group_list = data.get("Groups", [])
            
            for group in group_list:
                identity = Identity(
                    arn=group.get("Arn", ""),
                    name=group.get("GroupName", ""),
                    identity_type=IdentityType.GROUP,
                    created_date=group.get("CreateDate"),
                    metadata={"original_data": group}
                )
                groups.append(identity)
            
            return groups
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load groups from {filepath}: {e}")

    @staticmethod
    def load_managed_policies(filepath: Path) -> List[Policy]:
        """Load managed policies from exported JSON."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            policies = []
            policy_list = data.get("Policies", [])
            
            for policy in policy_list:
                policy_doc = policy.get("DefaultVersionId", {})
                statements = _parse_policy_document(policy.get("PolicyDocument", {}))
                
                p = Policy(
                    arn=policy.get("Arn", ""),
                    name=policy.get("PolicyName", ""),
                    policy_type=PolicyType.MANAGED,
                    statements=statements,
                    created_date=policy.get("CreateDate"),
                    updated_date=policy.get("UpdateDate"),
                    is_service_managed=policy.get("AttachmentCount", 0) > 0,
                    metadata={"original_data": policy}
                )
                policies.append(p)
            
            return policies
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load managed policies from {filepath}: {e}")

    @staticmethod
    def load_inline_policies(filepath: Path) -> List[Policy]:
        """Load inline policies from exported JSON."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            policies = []
            inline_policies = data.get("InlinePolicies", [])
            
            for policy in inline_policies:
                statements = _parse_policy_document(policy.get("PolicyDocument", {}))
                
                p = Policy(
                    name=policy.get("PolicyName", ""),
                    policy_type=PolicyType.INLINE,
                    statements=statements,
                    attached_to=[policy.get("AttachedTo", "")],
                    metadata={"original_data": policy}
                )
                policies.append(p)
            
            return policies
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load inline policies from {filepath}: {e}")

    @staticmethod
    def load_all_from_directory(directory: Path) -> tuple[List[Identity], List[Policy]]:
        """Load all identities and policies from a directory."""
        users = []
        roles = []
        groups = []
        managed_policies = []
        inline_policies = []
        
        # Load identities
        user_file = directory / "users.json"
        if user_file.exists():
            users = IAMLoader.load_users(user_file)
        
        role_file = directory / "roles.json"
        if role_file.exists():
            roles = IAMLoader.load_roles(role_file)
        
        group_file = directory / "groups.json"
        if group_file.exists():
            groups = IAMLoader.load_groups(group_file)
        
        # Load policies
        managed_file = directory / "managed_policies.json"
        if managed_file.exists():
            managed_policies = IAMLoader.load_managed_policies(managed_file)
        
        inline_file = directory / "inline_policies.json"
        if inline_file.exists():
            inline_policies = IAMLoader.load_inline_policies(inline_file)
        
        identities = users + roles + groups
        policies = managed_policies + inline_policies
        
        return identities, policies


def _extract_tags(tag_list: List[Dict[str, str]]) -> Dict[str, str]:
    """Convert tag list to dict."""
    tags = {}
    for tag in tag_list:
        tags[tag.get("Key", "")] = tag.get("Value", "")
    return tags


def _parse_policy_document(doc: Dict[str, Any]) -> List[Statement]:
    """Parse IAM policy document into Statement objects."""
    statements = []
    
    for stmt in doc.get("Statement", []):
        # Normalize actions and resources to lists
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        
        principals = stmt.get("Principal", [])
        if isinstance(principals, str):
            principals = [principals]
        elif isinstance(principals, dict):
            # Handle {"AWS": "arn:..."} or {"AWS": ["arn:...", ...]}
            principals = []
            for key, val in principals.items():
                if isinstance(val, list):
                    principals.extend(val)
                else:
                    principals.append(val)
        
        statement = Statement(
            effect=stmt.get("Effect", "Allow"),
            actions=actions,
            resources=resources,
            principals=principals if principals else None,
            conditions=stmt.get("Condition")
        )
        statements.append(statement)
    
    return statements
