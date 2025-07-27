"""
CycloneDX parser for SBOM Visualizer.

Provides functionality to parse CycloneDX format SBOM files.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

from ...models.sbom_models import Package, SBOMData, Vulnerability

logger = logging.getLogger(__name__)


class CycloneDXParser:
    """Parser for CycloneDX format SBOM files."""

    def __init__(self):
        """Initialize the CycloneDX parser."""
        pass

    def parse(self, content: str, file_path: Path) -> SBOMData:
        """
        Parse CycloneDX JSON content into SBOMData.

        Args:
            content: JSON content of the CycloneDX file
            file_path: Path to the original file

        Returns:
            Parsed SBOM data

        Raises:
            ValueError: If parsing fails
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in CycloneDX file: {e}")

        # Validate CycloneDX format
        if "bomFormat" not in data or data["bomFormat"] != "CycloneDX":
            raise ValueError("Not a valid CycloneDX BOM file")

        # Extract metadata
        metadata = data.get("metadata", {})
        document_name = metadata.get("component", {}).get("name", "Unknown")
        document_version = metadata.get("component", {}).get("version", "Unknown")

        # Parse packages
        packages = []
        components = data.get("components", [])

        for component in components:
            package = self._parse_component(component)
            packages.append(package)

        return SBOMData(
            document_name=document_name,
            document_version=document_version,
            packages=packages,
            relationships=[],
        )

    def _parse_component(self, component: Dict[str, Any]) -> Package:
        """Parse a CycloneDX component into a Package."""
        name = component.get("name", "Unknown")
        version = component.get("version", "Unknown")
        description = component.get("description", "")

        # Parse licenses
        licenses = []
        for license_info in component.get("licenses", []):
            license_name = license_info.get("license", {}).get("name", "Unknown")
            licenses.append(license_name)

        # Parse vulnerabilities
        vulnerabilities = []
        for vuln in component.get("vulnerabilities", []):
            vuln_id = vuln.get("id", "Unknown")
            severity = vuln.get("ratings", [{}])[0].get("severity", "unknown")
            vulnerabilities.append(
                Vulnerability(
                    cve_id=vuln_id,
                    severity=severity,
                    description=vuln.get("description", ""),
                )
            )

        # Parse dependencies (simplified)
        dependencies = []

        return Package(
            name=name,
            version=version,
            description=description,
            licenses=licenses,
            vulnerabilities=vulnerabilities,
            dependencies=dependencies,
        )
