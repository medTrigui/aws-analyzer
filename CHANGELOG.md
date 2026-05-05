# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-05

### Added - Phase 1: Offline Analyzer (MVP)

#### Core Features
- ✅ Offline IAM data analysis without requiring AWS credentials
- ✅ Support for importing AWS IAM exports (JSON format)
- ✅ Support for IAM credential reports (CSV format)
- ✅ Support for CloudTrail event logs (JSON format)

#### Detection Engines
- ✅ **Over-Permissioned Identity Detection**
  - Wildcard Actions and Resources (*:*)
  - Administrative service permissions
  - Dangerous permission combinations
  - Escalation-enabling permissions

- ✅ **Trust Policy Risk Analysis**
  - Unrestricted principals (Principal: *)
  - External account trusts without ExternalId
  - Missing conditions on risky trusts

- ✅ **Stale Credentials Detection**
  - Inactive access keys (90+ days)
  - Console access without MFA
  - Multiple active access keys
  - Old access key rotation

- ✅ **Privilege Escalation Path Detection**
  - iam:PassRole + lambda:CreateFunction
  - iam:PassRole + ec2:RunInstances
  - Direct user policy modification patterns
  - Access key creation patterns

- ✅ **Unused Permissions Analysis**
  - Permission grants not observed in CloudTrail
  - CloudTrail-based usage analysis
  - Potentially unused permission flagging

- ✅ **Service Account Behavior Analysis**
  - High AccessDenied event rates
  - IAM modifications from service roles
  - Service account activity anomalies

#### Reporting
- ✅ JSON report generation with full metadata
- ✅ Markdown report with executive summary
- ✅ HTML report with visual formatting
- ✅ Finding severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- ✅ Finding categorization and tagging

#### CLI Interface
- ✅ Typer-based command-line interface
- ✅ Flexible report output options
- ✅ Progress indicators with rich formatting
- ✅ Module execution (`python -m analyzer`)

#### Data Models
- ✅ Pydantic models for type safety
- ✅ IAM Identity model (User, Role, Group)
- ✅ IAM Policy model with statements
- ✅ Security Finding model
- ✅ Scan Result with metadata

#### Data Ingest
- ✅ IAM Loader for users, roles, groups, policies
- ✅ CloudTrail event loader
- ✅ Credential report CSV parser
- ✅ Policy document parsing

#### Testing
- ✅ Comprehensive unit tests
- ✅ Model tests
- ✅ Loader tests
- ✅ Detection engine tests
- ✅ Integration tests
- ✅ pytest configuration

#### Documentation
- ✅ Professional README with phases
- ✅ Security guidelines (SECURITY.md)
- ✅ Contributing guidelines (CONTRIBUTING.md)
- ✅ Docstrings on all public APIs
- ✅ Type hints throughout codebase

#### DevOps & CI/CD
- ✅ GitHub Actions test workflow
- ✅ Python 3.9+ compatibility
- ✅ Code quality checks (black, flake8, mypy)
- ✅ .gitignore with AWS data protection
- ✅ pyproject.toml with modern Python packaging

#### Sample Data
- ✅ Synthetic sample users with realistic scenarios
- ✅ Sample roles with trust policies
- ✅ Sample policies showing risks
- ✅ Example credential reports
- ✅ Example CloudTrail events

### Future Roadmap (Planned for Phase 2+)

#### Phase 2: AWS Integration
- [ ] boto3 integration for live AWS data collection
- [ ] Scheduled scanning
- [ ] Historical findings storage
- [ ] Slack/email alerting
- [ ] Multi-account analysis

#### Phase 3: Dashboard
- [ ] Streamlit interactive dashboard
- [ ] Real-time visualization
- [ ] Custom filtering and search
- [ ] Remediation tracking

#### Phase 4: Enterprise
- [ ] Custom detection rule engine
- [ ] RBAC for team collaboration
- [ ] API for third-party integrations
- [ ] Database backend

---

**Notes:**
- Phase 1 focused on safe, offline analysis without requiring real AWS credentials
- All data models follow Pydantic best practices
- Full test coverage for critical paths
- Professional CI/CD pipeline ready for production
