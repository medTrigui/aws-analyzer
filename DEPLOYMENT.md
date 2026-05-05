# DEPLOYMENT.md - Deployment & Usage Guide

[![Contributions](https://img.shields.io/badge/contributions-welcome-orange.svg)](CONTRIBUTING.md)

## Quick Start (5 minutes)

### 1. Install

```bash
git clone https://github.com/yourusername/aws-analyzer.git
cd aws-analyzer
pip install -e .
```

### 2. Prepare Data

Export AWS IAM configuration and CloudTrail logs:

```bash
# Option A: Automated export (requires AWS credentials)
python tools/export_iam_data.py --region us-east-1 --output-dir data/exports/

# Option B: Manual export via AWS Console
# Place the downloaded files in: data/my-exports/
```

### 3. Run Analysis

```bash
# Run analysis
python -m analyzer scan --input-dir data/exports --output-dir reports/

# View the report
cat reports/findings.md
```

---

## Installation Options

### Option 1: Development Install

```bash
git clone https://github.com/yourusername/aws-analyzer.git
cd aws-analyzer

# Virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### Option 2: Production Install

```bash
pip install aws-analyzer
```

### Option 3: Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
RUN pip install aws-analyzer

ENTRYPOINT ["python", "-m", "analyzer"]
```

---

## Data Preparation

### Exporting AWS IAM Data

**Via AWS CLI:**

```bash
# Create export directory
mkdir -p data/aws-exports

# Export users
aws iam get-users > data/aws-exports/users.json

# Export roles
aws iam list-roles > data/aws-exports/roles.json

# Export groups
aws iam list-groups > data/aws-exports/groups.json

# Export managed policies
aws iam list-policies --scope All > data/aws-exports/managed_policies.json

# Export credential report
aws iam get-credential-report --output text > data/aws-exports/credential_report.csv

# Export CloudTrail events (last 90 days)
aws cloudtrail lookup-events --max-items 1000 > data/aws-exports/cloudtrail_events.json
```

**Via AWS Console:**

1. **Users & Roles**: IAM → Users/Roles → (select each) → Export as JSON
2. **Policies**: IAM → Policies → Export list
3. **Credential Report**: IAM → Credential Report → Generate/Download
4. **CloudTrail**: CloudTrail → Event History → Export to S3

### File Format Requirements

```
data/exports/
├── users.json              # From: aws iam get-users
├── roles.json              # From: aws iam list-roles
├── groups.json             # From: aws iam list-groups
├── managed_policies.json   # From: aws iam list-policies
├── inline_policies.json    # From: aws iam list-user-policies (manual)
├── credential_report.csv   # From: aws iam get-credential-report
└── cloudtrail_events.json  # From: aws cloudtrail lookup-events
```

---

## Usage Examples

### Basic Scan

```bash
python -m analyzer scan \
  --input-dir data/exports \
  --output-dir reports/
```

### Custom Output Formats

```bash
# JSON only
python -m analyzer scan \
  --input-dir data/exports \
  --output-dir reports/ \
  --json \
  --no-markdown \
  --no-html

# Markdown only
python -m analyzer scan \
  --input-dir data/exports \
  --output-dir reports/ \
  --markdown \
  --no-json \
  --no-html
```

### Verbose Output

```bash
python -m analyzer scan \
  --input-dir data/exports \
  --output-dir reports/ \
  --verbose
```

### Using Sample Data

```bash
# Analyze built-in sample data
python -m analyzer scan \
  --input-dir data/sample \
  --output-dir reports/sample-analysis/
```

---

## Understanding Reports

### JSON Report (`findings.json`)

Machine-readable format for programmatic consumption:

```json
{
  "metadata": {
    "timestamp": "2026-05-05T10:30:00Z",
    "total_identities": 42,
    "total_findings": 25,
    "findings_by_severity": {
      "CRITICAL": 2,
      "HIGH": 8,
      "MEDIUM": 12,
      "LOW": 3
    }
  },
  "findings": [...]
}
```

**Use Cases:**
- Integration with SIEM systems
- Automated remediation workflows
- Custom dashboards

### Markdown Report (`findings.md`)

Human-readable summary for security teams:

- Executive summary
- Finding distribution by severity/category
- Detailed finding descriptions
- Impact assessments
- Remediation recommendations

**Use Cases:**
- Security reviews
- Management reporting
- Compliance documentation

### HTML Report (`findings.html`)

Visual report with interactive elements:

- Summary statistics
- Severity level indicators
- Color-coded findings
- Responsive design

**Use Cases:**
- Executive presentations
- Stakeholder communication
- Archive reference

---

## Integration

### SIEM Integration (Splunk Example)

```bash
#!/bin/bash
# scheduled-scan.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="reports/$TIMESTAMP"

# Run scan
python -m analyzer scan \
  --input-dir data/exports \
  --output-dir "$OUTPUT_DIR"

# Send to Splunk
curl -X POST \
  -H "Authorization: Splunk $(echo $SPLUNK_TOKEN | base64)" \
  -d @"$OUTPUT_DIR/findings.json" \
  https://splunk-hec.example.com:8088/services/collector
```

### GitHub Actions (CI/CD)

See [.github/workflows/tests.yml](.github/workflows/tests.yml) for existing test workflow.

Add scanning workflow:

```yaml
name: IAM Security Scan

on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly scan

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install analyzer
        run: pip install -e .
      
      - name: Export IAM data
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_KEY }}
        run: |
          mkdir -p data/exports
          aws iam get-users > data/exports/users.json
          # ... more exports
      
      - name: Run security scan
        run: |
          python -m analyzer scan \
            --input-dir data/exports \
            --output-dir reports/
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: iam-findings
          path: reports/
```

### Slack Notifications

```bash
#!/bin/bash
# notify-slack.sh

python -m analyzer scan \
  --input-dir data/exports \
  --output-dir reports/

# Parse findings
CRITICAL=$(jq '.metadata.findings_by_severity.CRITICAL // 0' reports/findings.json)
HIGH=$(jq '.metadata.findings_by_severity.HIGH // 0' reports/findings.json)

# Send to Slack
curl -X POST \
  -H 'Content-type: application/json' \
  --data "{
    \"text\": \":warning: IAM Security Scan Results\",
    \"attachments\": [{
      \"color\": \"danger\",
      \"fields\": [
        {\"title\": \"Critical\", \"value\": \"$CRITICAL\", \"short\": true},
        {\"title\": \"High\", \"value\": \"$HIGH\", \"short\": true}
      ]
    }]
  }" \
  $SLACK_WEBHOOK_URL
```

---

## Performance

### Benchmarks

On test data (8 identities, 5 policies, 4 CloudTrail events):
- Load IAM data: ~10ms
- Run detections: ~50ms
- Generate reports: ~100ms
- **Total: ~160ms**

### Optimization Tips

- **Large environments** (1000+ identities):
  - Run detections in parallel
  - Filter by identity type (users only, for example)
  - Sample CloudTrail events

- **Frequent scans**:
  - Cache policy parsing
  - Incremental analysis
  - Store historical results in database

---

## Troubleshooting

### Issue: "File not found" errors

**Solution**: Ensure all required files exist in input directory:

```bash
ls -la data/exports/
# Should show: users.json, roles.json, managed_policies.json, etc.
```

### Issue: "Invalid JSON" errors

**Solution**: Validate JSON files:

```bash
python -m json.tool data/exports/users.json > /dev/null && echo "Valid"
```

### Issue: Memory issues with large datasets

**Solution**: Process in batches or use streaming:

```python
# In analyzer/ingest/iam_loader.py
# Add streaming support for large files
```

### Issue: Export script fails

**Solution**: Check AWS credentials and permissions:

```bash
aws sts get-caller-identity
aws iam get-user  # Requires iam:GetUser permission
```

---

## Advanced Configuration

### Custom Detection Rules (Phase 2)

```python
# rules/custom_rules.py
from analyzer.models import Finding, Severity, Category

def detect_custom_pattern(identities, policies):
    findings = []
    # Your custom logic
    return findings
```

### Database Backend (Phase 2)

```python
# analyzer/db/models.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Store findings in PostgreSQL
engine = create_engine('postgresql://user:pass@localhost/analyzer')
```

### Streamlit Dashboard (Phase 3)

```bash
streamlit run dashboard/app.py
```

---

## Maintenance

### Updates

```bash
# Check for updates
pip install --upgrade aws-analyzer

# Check version
python -m analyzer version
```

### Cleaning Old Reports

```bash
# Remove reports older than 30 days
find reports/ -mtime +30 -delete
```

### Log Rotation

```bash
# If logging is implemented
logrotate -f /etc/logrotate.d/aws-analyzer
```

---

## Support & Resources

- **Documentation**: [README.md](README.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/aws-analyzer/issues)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security**: [SECURITY.md](SECURITY.md)

---

**Last Updated:** May 2026
**Version:** 0.1.0 (Phase 1 MVP)
