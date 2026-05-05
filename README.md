# Cloud IAM Attack Path Analyzer for AWS

A Python-based AWS security tool that analyzes IAM identities, policies, trust relationships, access keys, and CloudTrail activity to identify privilege escalation paths, over-permissioned roles, stale credentials, unused access, and risky service-account behavior.

## Overview

This project is a **defensive cloud security tool** designed to help security teams identify risky IAM configurations and potential privilege escalation paths in AWS environments.

It analyzes IAM users, roles, groups, policies, trust relationships, credential reports, and CloudTrail events to produce **prioritized findings with attack-path context and remediation guidance**.

## Key Capabilities

- **Over-Permissioned Identity Detection**: Flag users, roles, and groups with excessive permissions (Action: "*", Resource: "*", or dangerous combinations)
- **Privilege Escalation Path Analysis**: Visualize IAM privilege escalation chains as an attack graph
- **Trust Policy Risk Assessment**: Identify risky trust relationships with external accounts or overly broad principals
- **Stale Credential Detection**: Flag inactive access keys, missing MFA, and old credentials
- **Unused Permission Analysis**: Compare granted permissions against CloudTrail activity
- **Risky Service Account Behavior**: Detect suspicious patterns in service account activity

## Distinguishing from AWS Native Tools

This project **complements** native AWS IAM analysis (IAM Access Analyzer, unused-access findings) by:

- **Correlating IAM configuration with CloudTrail behavior** to identify unused permissions in real-world contexts
- **Visualizing privilege escalation paths** as attack graphs for intuitive understanding
- **Providing portable, offline analysis** without requiring live AWS credentials
- **Offering customizable detection rules** for specific organizational security postures

## Technology Stack

- **Python 3.9+** - Core language
- **pydantic** - Data validation and models
- **networkx** - Attack graph analysis
- **rich** - Terminal formatting
- **typer** - CLI framework
- **pytest** - Testing
- **jinja2** - Report templating
- **pyvis** - Interactive graph visualization

## Project Phases

### Phase 1: Offline Analyzer (MVP) - Current
- ✅ Standalone CLI tool for analyzing exported AWS IAM data
- ✅ No AWS credentials required
- ✅ Output: JSON findings, Markdown reports, HTML attack graphs
- ✅ Detections: Over-permissioned identities, trust policy risks, stale keys, privilege escalation paths

### Phase 2: Scheduled Analysis (Planned)
- AWS SDK integration for automated data collection
- Scheduled analysis runs
- Historical findings storage and trends
- Alert integrations (Slack, email)

### Phase 3: Interactive Dashboard (Planned)
- Streamlit web interface
- Real-time graph visualization
- Custom filter and search
- Remediation workflow tracking

### Phase 4: Enterprise Features (Planned)
- Multi-account analysis
- Custom detection rule engine
- RBAC for team collaboration
- API for third-party integrations

---

## Quick Start

### Prerequisites

- Python 3.9 or higher
- pip or poetry

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-analyzer.git
cd aws-analyzer

# Install dependencies
pip install -r requirements.txt
```

### Usage

#### Analyze IAM Data

```bash
# Run analyzer on sample data
python -m analyzer scan --input-dir data/sample --output-dir reports/

# Specify output format
python -m analyzer scan --input-dir data/sample --json --markdown --html
```

#### Example Output

```
[HIGH] Potential Privilege Escalation Path
├─ Identity: DevOpsUser
├─ Attack Path: DevOpsUser → DevOpsPolicy → iam:PassRole + lambda:CreateFunction → AdminExecutionRole
├─ Impact: User may execute code with administrative role permissions
└─ Recommendation: Restrict iam:PassRole to approved role ARNs and limit Lambda creation permissions
```

---

## Input Data Format

The analyzer accepts the following standardized AWS export formats:

```
data/
├── users.json              # IAM users and their properties
├── roles.json              # IAM roles and their properties
├── groups.json             # IAM groups and members
├── managed_policies.json   # AWS managed and customer managed policies
├── inline_policies.json    # Inline policies attached to identities
├── trust_policies.json     # Role trust (assume role) policies
├── credential_report.csv   # IAM credential report (access key/password status)
└── cloudtrail_events.json  # CloudTrail API call logs
```

### Exporting Data from AWS

Use provided scripts in `/tools/` or export manually via AWS Console:

```bash
# Automated export (requires AWS credentials)
python tools/export_iam_data.py --region us-east-1 --output-dir data/aws-export/
```

---

## Output Reports

### JSON Report (`findings.json`)

Machine-readable findings with full metadata:

```json
{
  "scan_metadata": {
    "timestamp": "2026-05-05T10:30:00Z",
    "total_findings": 42,
    "severity_distribution": {
      "CRITICAL": 2,
      "HIGH": 15,
      "MEDIUM": 20,
      "LOW": 5
    }
  },
  "findings": [
    {
      "severity": "HIGH",
      "category": "Privilege Escalation",
      "identity": "DevOpsUser",
      "identity_type": "User",
      "finding": "User has iam:PassRole and lambda:CreateFunction permissions",
      "attack_path": [
        "DevOpsUser",
        "DevOpsPolicy",
        "iam:PassRole",
        "lambda:CreateFunction",
        "AdminExecutionRole"
      ],
      "impact": "The identity may be able to create a Lambda function that runs with a higher-privileged role.",
      "recommendation": "Restrict iam:PassRole to specific approved role ARNs and limit Lambda creation permissions.",
      "evidence": []
    }
  ]
}
```

### Markdown Report (`findings.md`)

Human-readable executive summary and detailed findings.

### HTML Report (`attack_graph.html`)

Interactive visualization of privilege escalation paths using PyVis.

---

## Detection Rules

### 1. Over-Permissioned Identities

Flags identities with:
- `"Action": "*"` and `"Resource": "*"`
- Administrative permissions (iam:*, ec2:*, lambda:*)
- Dangerous permission combinations (iam:PassRole + lambda:CreateFunction)
- Policy modification permissions without restrictions

**Severity**: HIGH/CRITICAL

### 2. Privilege Escalation Paths

Models IAM relationships as a directed graph and identifies chains where a lower-privileged identity can escalate to higher-privileged access.

**Example**: User with `iam:PassRole` + `lambda:CreateFunction` can create Lambda with admin role

**Severity**: HIGH/CRITICAL

### 3. Risky Trust Policies

Flags role trust policies with:
- `"Principal": "*"` without conditions
- External AWS accounts without `ExternalId` or conditions
- Broad principal patterns without resource constraints

**Severity**: HIGH

### 4. Stale Access Keys

Flags credentials that pose security risks:
- Active access keys unused for 90+ days
- Access keys older than 90 days without rotation
- Users with 2+ active access keys
- Active passwords with MFA disabled
- Existing root access keys

**Severity**: MEDIUM/HIGH

### 5. Unused Permissions

Compares IAM policy permissions against CloudTrail activity. Flags permissions granted but not observed in CloudTrail over analyzed period.

**Note**: CloudTrail History availability varies; absence of evidence is not proof of non-use. Flags as "potentially unused."

**Severity**: LOW/MEDIUM

### 6. Risky Service Account Behavior

Detects suspicious patterns in service account CloudTrail activity:
- Access from unusual regions
- First-time use of sensitive APIs
- IAM modification calls from automation roles
- High AccessDenied event frequency
- Service accounts calling iam:CreateUser or iam:AttachRolePolicy

**Severity**: MEDIUM/HIGH

---

## Architecture

```
analyzer/
├── __init__.py
├── cli.py                          # CLI entry point (typer)
├── ingest/                         # Data loading
│   ├── iam_loader.py
│   ├── cloudtrail_loader.py
│   └── credential_report_loader.py
├── models/                         # Data models (pydantic)
│   ├── identity.py
│   ├── policy.py
│   └── finding.py
├── detections/                     # Detection engines
│   ├── overpermissioned.py
│   ├── privilege_escalation.py
│   ├── trust_policy_risks.py
│   ├── stale_keys.py
│   ├── unused_permissions.py
│   └── service_account_behavior.py
├── graph/                          # Graph analysis
│   ├── build_graph.py
│   └── attack_paths.py
└── reporting/                      # Output generation
    ├── markdown_report.py
    ├── json_report.py
    └── html_graph.py
```

---

## Development

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=analyzer

# Run specific test module
pytest tests/test_overpermissioned.py
```

### Code Quality

```bash
# Format code
black analyzer/

# Type checking
mypy analyzer/

# Linting
flake8 analyzer/
```

### Building

```bash
# Build distribution
python -m build

# Install in development mode
pip install -e ".[dev]"
```

---

## Safety & Compliance

### Important Guidelines

⚠️ **This tool is intended for defensive security analysis in authorized AWS environments only.**

#### Do Not Store in Repository:
- Real AWS account IDs
- Real ARNs from your organization
- Real CloudTrail logs
- Real access keys or credentials
- Real usernames, emails, or IP addresses
- Real internal role names or resource names

#### Sample Data Guidelines:
- Use synthetic examples like `arn:aws:iam::111122223333:role/AdminExecutionRole`
- Use placeholder identities: `DevOpsUser`, `SecurityAuditRole`, `ExampleVendorRole`
- Use placeholder account IDs: `111122223333`, `444455556666`

#### Proper Data Handling:
- Review exported data before committing
- Use `.gitignore` to exclude `data/`, `reports/`, and `*.csv` files
- Always anonymize real findings before sharing
- Store real data in secure, encrypted locations outside the repository

See [SECURITY.md](SECURITY.md) for detailed security policies.

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/yourusername/aws-analyzer.git
cd aws-analyzer
pip install -e ".[dev]"
pytest
```

---

## Roadmap

- [ ] **Phase 1.1**: Core detections and offline analysis
- [ ] **Phase 1.2**: HTML/interactive graph reports
- [ ] **Phase 2**: AWS SDK integration for automated collection
- [ ] **Phase 2.1**: Scheduled scanning and historical trends
- [ ] **Phase 3**: Streamlit dashboard and real-time monitoring
- [ ] **Phase 4**: Enterprise features (multi-account, custom rules, API)

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Support

For issues, questions, or feature requests, please open a GitHub issue or contact the development team.

---

## Disclaimer

This tool is provided as-is for security research and authorized defensive analysis. Users are responsible for:

- Obtaining proper authorization before analyzing AWS environments
- Complying with AWS terms of service and their organization's policies
- Handling sensitive information appropriately
- Keeping sample data synthetic and avoiding real credentials

AWS and the AWS logo are trademarks of Amazon Web Services, Inc.