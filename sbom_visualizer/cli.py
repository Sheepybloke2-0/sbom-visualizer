"""
CLI interface for SBOM Visualizer.

Provides command-line tools for analyzing, verifying, and visualizing SBOM files.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

import click

from .config import settings
from .container import container
from .exceptions import (
    SBOMAnalysisError,
    SBOMFileError,
    SBOMParseError,
    SBOMVerificationError,
)
from .services.sbom_service import SBOMService
from .utils.logger import setup_logging
from .utils.output_formatter import OutputFormatter


@click.group()
@click.option("--verbose", is_flag=True, help="Increase the log level to DEBUG.")
@click.option("--quiet", is_flag=True, help="Decrease the log level to WARN.")
@click.version_option(version=settings.version, prog_name=settings.app_name)
def cli(verbose: bool, quiet: bool) -> None:
    """
    SBOM Visualizer - AI-powered SBOM analysis and visualization tool.

    Supports SPDX 3.0, CycloneDX 1.5, and SWID formats.
    """
    # Setup logging based on verbosity
    if verbose:
        setup_logging(logging.DEBUG)
    elif quiet:
        setup_logging(logging.WARNING)
    else:
        setup_logging(logging.INFO)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Specify the output filename.",
)
@click.option(
    "-t",
    "--type",
    "output_type",
    type=click.Choice(["text", "json", "markdown", "html"], case_sensitive=False),
    default="text",
    help="Output type.",
)
def analyze(file: Path, output: Optional[Path], output_type: str) -> None:
    """
    Analyze an SBOM file and generate a detailed report.

    Default report is human-readable text formatted for a CLI.
    """
    try:
        # Use service layer for business logic
        service = container.sbom_service()
        sbom_data = service.parse_sbom(file)
        analysis_result = service.analyze_sbom(sbom_data)

        # Format and output the result
        formatter = container.output_formatter()
        formatted_output = formatter.format(analysis_result, output_type)

        if output:
            output.write_text(formatted_output)
            click.echo(f"Analysis report saved to {output}")
        else:
            click.echo(formatted_output)

    except SBOMFileError as e:
        click.echo(f"File error: {e.message}", err=True)
        sys.exit(1)
    except SBOMParseError as e:
        click.echo(f"Parse error: {e.message}", err=True)
        sys.exit(1)
    except SBOMAnalysisError as e:
        click.echo(f"Analysis error: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error analyzing SBOM: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
def verify(file: Path) -> None:
    """
    Verify an SBOM file.

    Reports any potential issues with the SBOM format, license issues, and dependency completeness.
    """
    try:
        # Use service layer for business logic
        service = container.sbom_service()
        sbom_data = service.parse_sbom(file)
        verification_result = service.verify_sbom(sbom_data)

        # Display verification results
        if verification_result.is_valid:
            click.echo("✅ SBOM verification passed!")
        else:
            click.echo("❌ SBOM verification failed!")

        for issue in verification_result.issues:
            click.echo(f"  - {issue}")

    except SBOMFileError as e:
        click.echo(f"File error: {e.message}", err=True)
        sys.exit(1)
    except SBOMParseError as e:
        click.echo(f"Parse error: {e.message}", err=True)
        sys.exit(1)
    except SBOMVerificationError as e:
        click.echo(f"Verification error: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error verifying SBOM: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Specify the output filename.",
)
@click.option(
    "-t",
    "--type",
    "output_type",
    type=click.Choice(["text", "json", "markdown", "html"], case_sensitive=False),
    default="text",
    help="Output type.",
)
def dep(file: Path, output: Optional[Path], output_type: str) -> None:
    """
    Show the dependency tree for an SBOM.

    Default output is a human-readable tree formatted for a CLI.
    Tree shows package name and version and is interactive for larger SBOMs.
    """
    try:
        # Use service layer for business logic
        service = container.sbom_service()
        sbom_data = service.parse_sbom(file)
        tree_data = service.get_dependency_tree(sbom_data)

        # Format and output the result
        formatter = container.output_formatter()
        formatted_output = formatter.format(tree_data, output_type)

        if output:
            output.write_text(formatted_output)
            click.echo(f"Dependency tree saved to {output}")
        else:
            click.echo(formatted_output)

    except SBOMFileError as e:
        click.echo(f"File error: {e.message}", err=True)
        sys.exit(1)
    except SBOMParseError as e:
        click.echo(f"Parse error: {e.message}", err=True)
        sys.exit(1)
    except SBOMAnalysisError as e:
        click.echo(f"Analysis error: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error generating dependency tree: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.argument("package_name", type=str)
def check_pkg(file: Path, package_name: str) -> None:
    """
    Get detailed information about a package in the SBOM.

    Also supports fuzzy matching for the package name.
    """
    try:
        # Use service layer for business logic
        service = container.sbom_service()
        sbom_data = service.parse_sbom(file)
        package_info = service.get_package_info(sbom_data, package_name)

        if package_info:
            click.echo(f"📦 Package: {package_info.name}")
            click.echo(f"   Version: {package_info.version}")
            click.echo(f"   License: {package_info.license}")
            click.echo(f"   Description: {package_info.description}")
            if package_info.dependencies:
                click.echo(f"   Dependencies: {len(package_info.dependencies)}")
        else:
            click.echo(f"❌ Package '{package_name}' not found in SBOM")

    except SBOMFileError as e:
        click.echo(f"File error: {e.message}", err=True)
        sys.exit(1)
    except SBOMParseError as e:
        click.echo(f"Parse error: {e.message}", err=True)
        sys.exit(1)
    except SBOMAnalysisError as e:
        click.echo(f"Analysis error: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error checking package: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Specify the output filename.",
)
@click.option(
    "-t",
    "--type",
    "output_type",
    type=click.Choice(["text", "json", "markdown", "html"], case_sensitive=False),
    default="text",
    help="Output type.",
)
def scan(file: Path, output: Optional[Path], output_type: str) -> None:
    """
    Scan the SBOM for potential CVEs.

    Checks packages against the latest list from CVE.org.
    This will be implemented as part of Stage 4.
    """
    try:
        # Use service layer for business logic
        service = container.sbom_service()
        sbom_data = service.parse_sbom(file)

        # For now, just show a message about Stage 4 implementation
        click.echo("🔍 CVE scanning is planned for Stage 4 (AI Integration)")
        click.echo("This feature will be available in a future release.")
        click.echo(f"📦 Found {len(sbom_data.packages)} packages to scan")

    except SBOMFileError as e:
        click.echo(f"File error: {e.message}", err=True)
        sys.exit(1)
    except SBOMParseError as e:
        click.echo(f"Parse error: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error scanning SBOM: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
