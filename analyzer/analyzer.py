"""
Main analyzer engine - orchestrates all detection and reporting.
"""

from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console

from .detections import (
    OverPermissionedDetector,
    PrivilegeEscalationDetector,
    ServiceAccountBehaviorDetector,
    StaleCredentialsDetector,
    TrustPolicyDetector,
    UnusedPermissionsDetector,
)
from .ingest import CloudTrailLoader, CredentialReportLoader, IAMLoader
from .models import Identity, Policy, ScanMetadata, ScanResult
from .reporting import HTMLReporter, JSONReporter, MarkdownReporter


class IAMAnalyzer:
    """Main analyzer orchestrating all detections."""

    def __init__(self, verbose: bool = False):
        """Initialize analyzer."""
        self.console = Console()
        self.verbose = verbose

    def scan(
        self,
        input_dir: Path,
        output_dir: Path,
        json_report: bool = True,
        markdown_report: bool = True,
        html_report: bool = True,
    ) -> ScanResult:
        """
        Scan IAM data from input directory and generate reports.
        
        Args:
            input_dir: Directory containing IAM export files
            output_dir: Directory to write reports
            json_report: Generate JSON report
            markdown_report: Generate Markdown report
            html_report: Generate HTML report
            
        Returns:
            ScanResult with all findings
        """
        self.console.print("[bold blue]Cloud IAM Attack Path Analyzer[/bold blue]")
        self.console.print(f"Input: {input_dir}")
        self.console.print(f"Output: {output_dir}\n")

        # Load data
        self.console.print("[cyan]Loading IAM configuration...[/cyan]")
        identities, policies = IAMLoader.load_all_from_directory(input_dir)
        self.console.print(
            f"  ✓ Loaded {len(identities)} identities and {len(policies)} policies"
        )

        # Load credential report if exists
        credential_records = []
        cred_report_path = input_dir / "credential_report.csv"
        if cred_report_path.exists():
            self.console.print("[cyan]Loading credential report...[/cyan]")
            try:
                credential_records = CredentialReportLoader.load_report(cred_report_path)
                self.console.print(f"  ✓ Loaded credential report for {len(credential_records)} users")
            except Exception as e:
                self.console.print(f"  ⚠ Failed to load credential report: {e}")

        # Load CloudTrail events if exists
        cloudtrail_events = []
        cloudtrail_api_calls = {}
        cloudtrail_path = input_dir / "cloudtrail_events.json"
        if cloudtrail_path.exists():
            self.console.print("[cyan]Loading CloudTrail events...[/cyan]")
            try:
                cloudtrail_events = CloudTrailLoader.load_events(cloudtrail_path)
                cloudtrail_api_calls = CloudTrailLoader.extract_api_calls(cloudtrail_events)
                self.console.print(
                    f"  ✓ Loaded {len(cloudtrail_events)} CloudTrail events"
                )
            except Exception as e:
                self.console.print(f"  ⚠ Failed to load CloudTrail events: {e}")

        # Run detections
        self.console.print("\n[cyan]Running security detections...[/cyan]")
        all_findings = []

        # Detection 1: Over-permissioned identities
        self.console.print("  → Analyzing for over-permissioned identities...")
        findings = OverPermissionedDetector.detect(identities, policies)
        all_findings.extend(findings)
        self.console.print(f"    Found {len(findings)} findings")

        # Detection 2: Trust policy risks
        self.console.print("  → Analyzing trust policies...")
        findings = TrustPolicyDetector.detect(identities)
        all_findings.extend(findings)
        self.console.print(f"    Found {len(findings)} findings")

        # Detection 3: Stale credentials
        if credential_records:
            self.console.print("  → Checking for stale credentials...")
            findings = StaleCredentialsDetector.detect_from_credential_report(credential_records)
            all_findings.extend(findings)
            self.console.print(f"    Found {len(findings)} findings")

        # Detection 4: Privilege escalation paths
        self.console.print("  → Detecting privilege escalation paths...")
        findings = PrivilegeEscalationDetector.detect(identities, policies)
        all_findings.extend(findings)
        self.console.print(f"    Found {len(findings)} findings")

        # Detection 5: Unused permissions
        if cloudtrail_api_calls:
            self.console.print("  → Analyzing for unused permissions...")
            findings = UnusedPermissionsDetector.detect(
                identities, policies, cloudtrail_api_calls
            )
            all_findings.extend(findings)
            self.console.print(f"    Found {len(findings)} findings")

        # Detection 6: Risky service account behavior
        if cloudtrail_events:
            self.console.print("  → Analyzing service account behavior...")
            identity_arns = [i.arn for i in identities]
            findings = ServiceAccountBehaviorDetector.detect(cloudtrail_events, identity_arns)
            all_findings.extend(findings)
            self.console.print(f"    Found {len(findings)} findings")

        # Create scan results
        self.console.print("\n[cyan]Generating reports...[/cyan]")
        scan_result = self._create_scan_result(
            all_findings, len(identities), len(policies)
        )

        # Generate reports
        output_dir.mkdir(parents=True, exist_ok=True)

        if json_report:
            json_path = output_dir / "findings.json"
            JSONReporter.generate(scan_result, json_path)
            self.console.print(f"  ✓ JSON report: {json_path}")

        if markdown_report:
            md_path = output_dir / "findings.md"
            MarkdownReporter.generate(scan_result, md_path)
            self.console.print(f"  ✓ Markdown report: {md_path}")

        if html_report:
            html_path = output_dir / "findings.html"
            HTMLReporter.generate(scan_result, html_path)
            self.console.print(f"  ✓ HTML report: {html_path}")

        # Summary
        self.console.print("\n[bold green]✓ Scan complete![/bold green]")
        self.console.print(f"\nFindings Summary:")
        for severity, count in scan_result.metadata.findings_by_severity.items():
            self.console.print(f"  {severity}: {count}")

        return scan_result

    @staticmethod
    def _create_scan_result(
        findings: List, total_identities: int, total_policies: int
    ) -> ScanResult:
        """Create ScanResult from findings."""
        # Count by severity and category
        findings_by_severity = {}
        findings_by_category = {}

        for finding in findings:
            sev = finding.severity.value
            cat = finding.category.value

            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
            findings_by_category[cat] = findings_by_category.get(cat, 0) + 1

        metadata = ScanMetadata(
            timestamp=datetime.utcnow().isoformat() + "Z",
            total_identities=total_identities,
            total_policies=total_policies,
            total_findings=len(findings),
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
        )

        return ScanResult(metadata=metadata, findings=findings)
