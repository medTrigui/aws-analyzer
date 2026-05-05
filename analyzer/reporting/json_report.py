"""
Report generation (JSON, Markdown, HTML).
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict

from jinja2 import Template

from ..models import ScanResult, Severity


class JSONReporter:
    """Generate JSON reports."""

    @staticmethod
    def generate(scan_result: ScanResult, output_path: Path) -> None:
        """Generate JSON report."""
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report_data = {
            "metadata": scan_result.metadata.model_dump(),
            "findings": [f.model_dump() for f in scan_result.findings],
        }

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)


class MarkdownReporter:
    """Generate Markdown reports."""

    # Severity order for sorting
    SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    @staticmethod
    def generate(scan_result: ScanResult, output_path: Path) -> None:
        """Generate Markdown report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []

        # Header
        lines.append("# Cloud IAM Attack Path Analyzer - Security Report\n")
        lines.append(f"**Report Generated:** {scan_result.metadata.timestamp}\n")

        # Executive Summary
        lines.append("## Executive Summary\n")
        lines.append(
            f"This report contains security findings from analyzing {scan_result.metadata.total_identities} "
            f"IAM identities and {scan_result.metadata.total_policies} policies.\n"
        )
        lines.append(f"**Total Findings:** {scan_result.metadata.total_findings}\n\n")

        # Findings by Severity
        lines.append("### Findings by Severity\n")
        for severity, count in sorted(
            scan_result.metadata.findings_by_severity.items(),
            key=lambda x: MarkdownReporter.SEVERITY_ORDER.get(Severity(x[0]), 999)
        ):
            lines.append(f"- **{severity}**: {count}\n")
        lines.append("")

        # Findings by Category
        lines.append("### Findings by Category\n")
        for category, count in sorted(scan_result.metadata.findings_by_category.items()):
            lines.append(f"- **{category}**: {count}\n")
        lines.append("")

        # Detailed Findings
        lines.append("---\n")
        lines.append("## Detailed Findings\n\n")

        # Sort findings by severity
        sorted_findings = sorted(
            scan_result.findings,
            key=lambda f: MarkdownReporter.SEVERITY_ORDER.get(f.severity, 999)
        )

        for i, finding in enumerate(sorted_findings, 1):
            lines.append(f"### {i}. [{finding.severity.value}] {finding.finding_title}\n")
            lines.append(f"**Identity:** {finding.identity}\n\n")
            lines.append(f"**Category:** {finding.category.value}\n\n")
            lines.append(f"**Description:** {finding.finding_description}\n\n")

            if finding.attack_path:
                lines.append("**Attack Path:**\n")
                for path_elem in finding.attack_path:
                    lines.append(f"  → {path_elem}\n")
                lines.append("\n")

            lines.append(f"**Impact:** {finding.impact}\n\n")
            lines.append(f"**Recommendation:** {finding.recommendation}\n\n")

            if finding.evidence:
                lines.append("**Evidence:**\n")
                for evidence in finding.evidence:
                    lines.append(
                        f"  - {evidence.get('type', 'unknown')}: {evidence.get('value', '')}\n"
                    )
                lines.append("\n")

            lines.append("---\n\n")

        with open(output_path, "w") as f:
            f.writelines(lines)


class HTMLReporter:
    """Generate interactive HTML reports with graphs."""

    TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>IAM Security Report</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet" type="text/css" />
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1, h2 { color: #333; }
            .summary {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .stat-card {
                background: #f9f9f9;
                padding: 20px;
                border-left: 4px solid #007bff;
                border-radius: 4px;
            }
            .stat-card.critical { border-left-color: #dc3545; }
            .stat-card.high { border-left-color: #fd7e14; }
            .stat-card.medium { border-left-color: #ffc107; }
            .stat-card.low { border-left-color: #28a745; }
            .stat-value {
                font-size: 32px;
                font-weight: bold;
                color: #333;
            }
            .stat-label {
                font-size: 14px;
                color: #666;
                margin-top: 10px;
            }
            #graph {
                width: 100%;
                height: 600px;
                border: 1px solid #ddd;
                border-radius: 4px;
                margin: 20px 0;
                background: #fafafa;
            }
            .finding {
                margin: 20px 0;
                padding: 15px;
                border-left: 4px solid #ddd;
                background: #fafafa;
                border-radius: 4px;
            }
            .finding.critical { border-left-color: #dc3545; background: #fff5f5; }
            .finding.high { border-left-color: #fd7e14; background: #fffbf0; }
            .finding.medium { border-left-color: #ffc107; background: #fffef0; }
            .finding.low { border-left-color: #28a745; background: #f5fff5; }
            .finding-title {
                font-size: 16px;
                font-weight: bold;
                margin: 0 0 10px 0;
            }
            .finding-detail {
                font-size: 14px;
                color: #666;
                margin: 5px 0;
            }
            .severity-badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: bold;
                margin-right: 10px;
            }
            .severity-critical { background: #dc3545; color: white; }
            .severity-high { background: #fd7e14; color: white; }
            .severity-medium { background: #ffc107; color: #333; }
            .severity-low { background: #28a745; color: white; }
            .timestamp {
                color: #999;
                font-size: 12px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Cloud IAM Attack Path Analyzer Report</h1>
            <p class="timestamp">Report Generated: {{ timestamp }}</p>

            <h2>Summary</h2>
            <div class="summary">
                <div class="stat-card">
                    <div class="stat-value">{{ total_findings }}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-value">{{ findings_critical }}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-value">{{ findings_high }}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-value">{{ findings_medium }}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-value">{{ findings_low }}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>

            <h2>Findings</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.severity.value.lower() }}">
                <div class="finding-title">
                    <span class="severity-badge severity-{{ finding.severity.value.lower() }}">
                        {{ finding.severity.value }}
                    </span>
                    {{ finding.finding_title }}
                </div>
                <div class="finding-detail"><strong>Identity:</strong> {{ finding.identity }}</div>
                <div class="finding-detail"><strong>Type:</strong> {{ finding.identity_type }}</div>
                <div class="finding-detail"><strong>Category:</strong> {{ finding.category.value }}</div>
                <div class="finding-detail"><strong>Description:</strong> {{ finding.finding_description }}</div>
                <div class="finding-detail"><strong>Impact:</strong> {{ finding.impact }}</div>
                <div class="finding-detail"><strong>Recommendation:</strong> {{ finding.recommendation }}</div>
            </div>
            {% endfor %}

            <div class="timestamp">
                <p>Analyzed {{ total_identities }} identities and {{ total_policies }} policies.</p>
            </div>
        </div>
    </body>
    </html>
    """

    @staticmethod
    def generate(scan_result: ScanResult, output_path: Path) -> None:
        """Generate HTML report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        template = Template(HTMLReporter.TEMPLATE)

        severity_counts = scan_result.metadata.findings_by_severity
        html_content = template.render(
            timestamp=scan_result.metadata.timestamp,
            total_findings=scan_result.metadata.total_findings,
            findings_critical=severity_counts.get("CRITICAL", 0),
            findings_high=severity_counts.get("HIGH", 0),
            findings_medium=severity_counts.get("MEDIUM", 0),
            findings_low=severity_counts.get("LOW", 0),
            findings=scan_result.findings,
            total_identities=scan_result.metadata.total_identities,
            total_policies=scan_result.metadata.total_policies,
        )

        with open(output_path, "w") as f:
            f.write(html_content)
