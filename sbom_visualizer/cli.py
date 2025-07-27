"""
Command-line interface for SBOM Visualizer.

Provides CLI commands for analyzing, verifying, and visualizing SBOM files.
"""

import logging
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

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version=settings.version, prog_name=settings.app_name)
def cli():
    """SBOM Visualizer - Analyze and visualize Software Bill of Materials."""
    pass


@cli.command()
@click.argument("file_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json", "markdown", "html"]),
    default="text",
    help="Output format for analysis results",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(path_type=Path),
    help="Output file path (optional)",
)
def analyze(file_path: Path, output: str, output_file: Optional[Path]):
    """Analyze an SBOM file and provide detailed insights."""
    try:
        # Get services from container
        sbom_service = container.sbom_service()
        output_formatter = container.output_formatter()

        # Parse and analyze SBOM
        sbom_data = sbom_service.parse_sbom(file_path)
        analysis_result = sbom_service.analyze_sbom(sbom_data)

        # Format output
        formatted_output = output_formatter.format(analysis_result, output)

        if output_file:
            output_file.write_text(formatted_output)
            click.echo(f"Analysis results written to {output_file}")
        else:
            click.echo(formatted_output)

    except (SBOMFileError, SBOMParseError, SBOMAnalysisError) as e:
        click.echo(f"Error analyzing SBOM: {e.message}", err=True)
        raise click.Abort()


@cli.command()
@click.argument("file_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json", "markdown", "html"]),
    default="text",
    help="Output format for verification results",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(path_type=Path),
    help="Output file path (optional)",
)
def verify(file_path: Path, output: str, output_file: Optional[Path]):
    """Verify an SBOM file for compliance and completeness."""
    try:
        # Get services from container
        sbom_service = container.sbom_service()
        output_formatter = container.output_formatter()

        # Parse and verify SBOM
        sbom_data = sbom_service.parse_sbom(file_path)
        verification_result = sbom_service.verify_sbom(sbom_data)

        # Format output
        formatted_output = output_formatter.format(verification_result, output)

        if output_file:
            output_file.write_text(formatted_output)
            click.echo(f"Verification results written to {output_file}")
        else:
            click.echo(formatted_output)

    except (SBOMFileError, SBOMParseError, SBOMVerificationError) as e:
        click.echo(f"Error verifying SBOM: {e.message}", err=True)
        raise click.Abort()


@cli.command()
@click.argument("file_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json", "markdown", "html"]),
    default="text",
    help="Output format for dependency tree",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(path_type=Path),
    help="Output file path (optional)",
)
def dep(file_path: Path, output: str, output_file: Optional[Path]):
    """Display dependency tree for an SBOM file."""
    try:
        # Get services from container
        sbom_service = container.sbom_service()
        output_formatter = container.output_formatter()

        # Parse SBOM and get dependency tree
        sbom_data = sbom_service.parse_sbom(file_path)
        dependency_tree = sbom_service.get_dependency_tree(sbom_data)

        # Format output
        formatted_output = output_formatter.format(dependency_tree, output)

        if output_file:
            output_file.write_text(formatted_output)
            click.echo(f"Dependency tree written to {output_file}")
        else:
            click.echo(formatted_output)

    except (SBOMFileError, SBOMParseError, SBOMAnalysisError) as e:
        click.echo(f"Error analyzing dependencies: {e.message}", err=True)
        raise click.Abort()


@cli.command()
@click.argument("file_path", type=click.Path(exists=True, path_type=Path))
@click.argument("package_name", type=str)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json", "markdown", "html"]),
    default="text",
    help="Output format for package information",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(path_type=Path),
    help="Output file path (optional)",
)
def check_pkg(
    file_path: Path, package_name: str, output: str, output_file: Optional[Path]
):
    """Get detailed information about a specific package in an SBOM."""
    try:
        # Get services from container
        sbom_service = container.sbom_service()
        output_formatter = container.output_formatter()

        # Parse SBOM and get package info
        sbom_data = sbom_service.parse_sbom(file_path)
        package_info = sbom_service.get_package_info(sbom_data, package_name)

        if package_info is None:
            click.echo(f"Package '{package_name}' not found in SBOM", err=True)
            raise click.Abort()

        # Format output
        formatted_output = output_formatter.format(package_info, output)

        if output_file:
            output_file.write_text(formatted_output)
            click.echo(f"Package information written to {output_file}")
        else:
            click.echo(formatted_output)

    except (SBOMFileError, SBOMParseError, SBOMAnalysisError) as e:
        click.echo(f"Error checking package: {e.message}", err=True)
        raise click.Abort()


@cli.command()
@click.argument("file_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json", "markdown", "html"]),
    default="text",
    help="Output format for scan results",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(path_type=Path),
    help="Output file path (optional)",
)
def scan(file_path: Path, output: str, output_file: Optional[Path]):
    """Perform comprehensive analysis and verification of an SBOM file."""
    try:
        # Get services from container
        sbom_service = container.sbom_service()
        output_formatter = container.output_formatter()

        # Parse, analyze, and verify SBOM
        sbom_data = sbom_service.parse_sbom(file_path)
        analysis_result, verification_result = sbom_service.analyze_and_verify(
            file_path
        )

        # Combine results for output
        combined_result = {
            "analysis": analysis_result,
            "verification": verification_result,
        }

        # Format output
        formatted_output = output_formatter.format(combined_result, output)

        if output_file:
            output_file.write_text(formatted_output)
            click.echo(f"Scan results written to {output_file}")
        else:
            click.echo(formatted_output)

    except (
        SBOMFileError,
        SBOMParseError,
        SBOMAnalysisError,
        SBOMVerificationError,
    ) as e:
        click.echo(f"Error scanning SBOM: {e.message}", err=True)
        raise click.Abort()


if __name__ == "__main__":
    cli()
