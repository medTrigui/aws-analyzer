# CONTRIBUTING.md - Contribution Guidelines

Welcome to the Cloud IAM Attack Path Analyzer! We're excited to have contributions from the community.

## Code of Conduct

This project is committed to providing a welcoming and inclusive environment. All contributors are expected to:
- Be respectful and constructive
- Focus on the code and ideas, not individuals
- Report problematic behavior privately to maintainers

## Getting Started

### Development Setup

```bash
# Clone and navigate to the project
git clone https://github.com/yourusername/aws-analyzer.git
cd aws-analyzer

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Verify setup
pytest
```

### Project Structure

```
analyzer/              # Main package
├── models/           # Data models (Pydantic)
├── ingest/          # Data loaders
├── detections/      # Detection engines
├── reporting/       # Report generators
├── cli.py           # Command-line interface
└── analyzer.py      # Main orchestrator

tests/               # Unit and integration tests
data/sample/        # Sample synthetic data
docs/              # Documentation
```

## How to Contribute

### 1. Find or Create an Issue

- Check [open issues](https://github.com/yourusername/aws-analyzer/issues)
- Create a new issue describing your feature or bug fix
- Discuss with maintainers before starting work on large changes

### 2. Fork and Branch

```bash
# Create a feature branch
git checkout -b feature/descriptive-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### 3. Development Guidelines

#### Code Style
- **Python version**: 3.9+
- **Formatter**: Black (`black analyzer/`)
- **Linter**: Flake8 (`flake8 analyzer/`)
- **Type checking**: MyPy (`mypy analyzer/`)
- **Import sorting**: isort (`isort analyzer/`)

#### Before Committing
```bash
# Format code
black analyzer/ tests/

# Sort imports
isort analyzer/ tests/

# Run type checking
mypy analyzer/

# Run linter
flake8 analyzer/ tests/

# Run tests
pytest
```

#### Commit Messages
- Use clear, descriptive messages
- Reference issue numbers: `Fix #123: Description`
- First line ≤ 50 characters
- Detailed explanation in body if needed

Example:
```
Fix #42: Detect iam:PassRole + ec2:RunInstances combination

Added detection for the privilege escalation pattern where a user
has both iam:PassRole and ec2:RunInstances permissions, allowing
them to create EC2 instances with elevated IAM roles.

Tests added for the new detection pattern.
```

### 4. Testing

#### Write Tests First (TDD)
1. Create test in `tests/test_*.py`
2. Implement feature
3. Verify tests pass

#### Test Coverage
- Aim for >80% coverage  
- Test happy path and error cases
- Use meaningful assertion messages

```python
def test_detects_privilege_escalation(sample_data):
    """Test detection of iam:PassRole + lambda:CreateFunction pattern."""
    findings = OverPermissionedDetector.detect(sample_data.identities, ...)
    assert any(f.category == Category.PRIVILEGE_ESCALATION for f in findings)
```

#### Run Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=analyzer

# Run specific test
pytest tests/test_overpermissioned.py::TestOverPermissionedDetector::test_detects_wildcard_admin
```

### 5. Documentation

#### Update README if:
- Adding new features or modes
- Changing input/output formats
- Adding new detection types

#### Code Documentation
- Docstrings for all public functions/classes
- Type hints on function signatures
- Comments for complex logic

```python
def detect(
    identities: List[Identity],
    policies: List[Policy]
) -> List[Finding]:
    """
    Detect over-permissioned identities.
    
    Args:
        identities: List of IAM identities to analyze
        policies: List of IAM policies to check
        
    Returns:
        List of security findings
        
    Raises:
        ValueError: If input data is malformed
    """
```

### 6. Security Considerations

- **Never commit real AWS data** (use synthetic samples)
- **Never hardcode credentials** or secrets
- **Check for sensitive data** before committing:
  ```bash
  git diff --cached  # Review staged changes
  ```
- **Report security issues privately** to maintainers

See [SECURITY.md](SECURITY.md) for detailed guidelines.

### 7. Create a Pull Request

1. Push your branch to your fork
2. Create a PR with:
   - Clear title referencing the issue
   - Description of changes
   - Link to related issues
   - Test coverage summary

PR Title Example:
```
Feature: Detect trust policies with external accounts without ExternalId (#123)
```

PR Description Example:
```
## Changes
- Add TrustPolicyDetector to detect risky trust relationships
- Identify external account trusts without ExternalId requirement
- Flag Principal: * without conditions

## Testing
- Added test_trust_policies.py with 5 test cases
- 100% code coverage for trust policy detection
- Tested with sample data in data/sample/roles.json

## Checklist
- [x] Tests added/updated
- [x] Documentation updated
- [x] No real AWS data committed
- [x] Code formatted with black
- [x] Type hints added
```

## Review Process

### What Maintainers Look For
- Code quality and style consistency
- Test coverage for new features
- No security issues or data leaks
- Clear, maintainable implementation
- Updated documentation

### What Reviewers Will Ask
- "Can this be simplified?"
- "Is there a test for failure cases?"
- "Does this follow the architecture?"
- "Is this well documented?"

### Getting Your PR Merged
1. Address all review comments
2. Re-request review once changes are made
3. Merge typically happens within 1-2 weeks of approval

## Building Distributions

### Local Testing
```bash
# Install in editable mode
pip install -e .

# Run CLI
aws-analyzer scan --input-dir data/sample --output-dir reports/
```

### Creating Release
(Maintainers only)
```bash
# Build package
python -m build

# Upload to TestPyPI (for testing)
twine upload --repository testpypi dist/*

# Upload to PyPI (production)
twine upload dist/*
```

## Areas for Contribution

### High Priority
- [ ] Graph-based privilege escalation path analysis (networkx)
- [ ] CloudTrail behavior analysis improvements
- [ ] HTML/Streamlit dashboard
- [ ] AWS SDK integration for live data collection
- [ ] Custom detection rule engine

### Medium Priority
- [ ] Additional detection patterns
- [ ] Performance optimization
- [ ] Database storage for findings history
- [ ] Slack/email alert integrations
- [ ] API for third-party tools

### Documentation
- [ ] Tutorial walkthroughs
- [ ] Video demonstrations
- [ ] Remediation playbooks
- [ ] Contributing guides for different skill levels

## Questions?

- Ask in issue comments
- Check existing discussions
- Email maintainers
- Open a discussion thread

---

Thank you for contributing! Together we're building better cloud security tools.
