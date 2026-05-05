"""
CLI interface for IAM Analyzer.
"""

from pathlib import Path

import typer
from rich.console import Console

from .analyzer import IAMAnalyzer

app = typer.Typer(
    name="aws-analyzer",
    help="Cloud IAM Attack Path Analyzer for AWS",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    input_dir: Path = typer.Option(
        "data/sample",
        "--input-dir",
        "-i",
        help="Directory containing IAM export files (JSON/CSV)",
    ),
    output_dir: Path = typer.Option(
        "reports",
        "--output-dir",
        "-o",
        help="Directory to write reports",
    ),
    json_flag: bool = typer.Option(
        True,
        "--json",
        help="Generate JSON report",
    ),
    markdown_flag: bool = typer.Option(
        True,
        "--markdown",
        help="Generate Markdown report",
    ),
    html_flag: bool = typer.Option(
        True,
        "--html",
        help="Generate HTML report",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose output",
    ),
) -> None:
    """
    Scan AWS IAM configuration for security risks.
    
    Example:
        python -m analyzer scan --input-dir data/sample --output-dir reports/
    """
    try:
        analyzer = IAMAnalyzer(verbose=verbose)
        analyzer.scan(
            input_dir=input_dir,
            output_dir=output_dir,
            json_report=json_flag,
            markdown_report=markdown_flag,
            html_report=html_flag,
        )
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    console.print("[bold]Cloud IAM Attack Path Analyzer[/bold]")
    console.print("Version: 0.1.0")
    console.print("Phase: 1 - Offline Analyzer (MVP)")


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
