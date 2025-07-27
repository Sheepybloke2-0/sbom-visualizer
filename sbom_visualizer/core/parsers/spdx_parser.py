"""
SPDX parser for SBOM Visualizer.

Provides functionality to parse SPDX format SBOM files.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from ...models.sbom_models import License, Package, SBOMData, SBOMFormat

logger = logging.getLogger(__name__)


class SPDXParser:
    """Parser for SPDX format SBOM files."""

    def __init__(self):
        """Initialize the SPDX parser."""
        pass

    def parse(self, content: str, file_path: Path) -> SBOMData:
        """
        Parse SPDX JSON content into SBOMData.

        Args:
            content: JSON content of the SPDX file
            file_path: Path to the original file

        Returns:
            Parsed SBOM data

        Raises:
            ValueError: If parsing fails
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in SPDX file: {e}")

        # Validate SPDX format
        if "spdxVersion" not in data:
            raise ValueError("Not a valid SPDX file")

        # Extract document info
        document_name = data.get("documentName", "Unknown")
        document_namespace = data.get("documentNamespace", "Unknown")

        # Extract creation info
        creation_info = data.get("creationInfo", {})
        created_str = creation_info.get("created", "2024-01-01T00:00:00Z")
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        except ValueError:
            created = datetime.now()

        creators = creation_info.get("creators", [])
        creator = creators[0] if creators else "Unknown"

        # Parse packages
        packages = []
        for package_data in data.get("packages", []):
            package = self._parse_package(package_data)
            packages.append(package)

        return SBOMData(
            format=SBOMFormat.SPDX,
            version=data.get("spdxVersion", "2.3"),
            document_name=document_name,
            document_namespace=document_namespace,
            created=created,
            creator=creator,
            packages=packages,
            relationships=data.get("relationships", []),
            metadata=data,
        )

    def _parse_package(self, package_data: Dict[str, Any]) -> Package:
        """Parse an SPDX package into a Package."""
        package_id = package_data.get("SPDXID", "Unknown")
        name = package_data.get("name", "Unknown")
        version = package_data.get("versionInfo", "Unknown")
        description = package_data.get("description", "")

        # Parse licenses
        licenses = []
        license_declared = package_data.get("licenseDeclared", "NONE")
        if license_declared != "NONE":
            # Handle both string and list formats
            if isinstance(license_declared, str):
                license_refs = [license_declared]
            else:
                license_refs = license_declared

            for license_ref in license_refs:
                if license_ref != "NONE":
                    licenses.append(License(identifier=license_ref))

        # Parse vulnerabilities (SPDX doesn't have built-in vulnerability info)
        vulnerabilities = []

        # Parse dependencies (simplified)
        dependencies = []

        return Package(
            id=package_id,
            name=name,
            version=version,
            description=description,
            licenses=licenses,
            vulnerabilities=vulnerabilities,
            dependencies=dependencies,
        )
