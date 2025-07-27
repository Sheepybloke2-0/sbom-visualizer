"""
SWID parser for SBOM Visualizer.

Provides functionality to parse SWID format SBOM files.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

from ...models.sbom_models import Package, SBOMData

logger = logging.getLogger(__name__)


class SWIDParser:
    """Parser for SWID format SBOM files."""

    def __init__(self):
        """Initialize the SWID parser."""
        pass

    def parse(self, content: str, file_path: Path) -> SBOMData:
        """
        Parse SWID content into SBOMData.

        Args:
            content: Content of the SWID file (JSON or XML)
            file_path: Path to the original file

        Returns:
            Parsed SBOM data

        Raises:
            ValueError: If parsing fails
        """
        try:
            # Try to parse as JSON first
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try to parse as XML (simplified)
            raise ValueError("XML parsing not yet implemented for SWID")

        # Validate SWID format
        if "softwareIdentity" not in data:
            raise ValueError("Not a valid SWID file")

        # Extract document info
        software_identity = data["softwareIdentity"]
        document_name = software_identity.get("name", "Unknown")
        document_version = software_identity.get("version", "Unknown")

        # Parse packages (SWID typically has one main software identity)
        packages = []
        package = self._parse_software_identity(software_identity)
        packages.append(package)

        return SBOMData(
            document_name=document_name,
            document_version=document_version,
            packages=packages,
            relationships=[],
        )

    def _parse_software_identity(self, software_identity: Dict[str, Any]) -> Package:
        """Parse a SWID software identity into a Package."""
        name = software_identity.get("name", "Unknown")
        version = software_identity.get("version", "Unknown")
        description = software_identity.get("summary", "")

        # Parse licenses (SWID doesn't have built-in license info)
        licenses = []

        # Parse vulnerabilities (SWID doesn't have built-in vulnerability info)
        vulnerabilities = []

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
