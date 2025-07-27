"""
CycloneDX parser for SBOM Visualizer.

Provides functionality to parse CycloneDX format SBOM files.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from ...models.sbom_models import (
    Dependency,
    License,
    Package,
    SBOMData,
    SBOMFormat,
    Vulnerability,
)

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
        component_info = metadata.get("component", {})
        document_name = component_info.get("name", "Unknown")
        document_version = component_info.get("version", "Unknown")

        # Parse timestamp
        timestamp_str = metadata.get("timestamp", "2024-01-01T00:00:00Z")
        try:
            created = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            created = datetime.now()

        # Parse packages
        packages = []
        package_map = {}  # Map purl to Package object
        components = data.get("components", [])

        for component in components:
            package = self._parse_component(component)
            packages.append(package)
            if package.purl:
                package_map[package.purl] = package

        # Parse dependencies
        dependencies_data = data.get("dependencies", [])
        self._parse_dependencies(dependencies_data, package_map)

        return SBOMData(
            format=SBOMFormat.CYCLONEDX,
            version=data.get("specVersion", "1.5"),
            document_name=document_name,
            document_namespace=f"https://cyclonedx.org/bom/{document_name}-{document_version}",
            created=created,
            creator="CycloneDX Generator",
            packages=packages,
            relationships=dependencies_data,
            metadata=data,
        )

    def _parse_component(self, component: Dict[str, Any]) -> Package:
        """Parse a CycloneDX component into a Package."""
        name = component.get("name", "Unknown")
        version = component.get("version", "Unknown")
        description = component.get("description", "")
        purl = component.get("purl", "")

        # Generate ID from purl or name
        package_id = purl if purl else f"pkg:{name}@{version}"

        # Parse licenses
        licenses = []
        for license_info in component.get("licenses", []):
            license_data = license_info.get("license", {})
            license_id = license_data.get("id", "Unknown")
            licenses.append(License(identifier=license_id))

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

        # Parse dependencies (will be populated later)
        dependencies = []

        return Package(
            id=package_id,
            name=name,
            version=version,
            description=description,
            licenses=licenses,
            vulnerabilities=vulnerabilities,
            dependencies=dependencies,
            purl=purl,
        )

    def _parse_dependencies(self, dependencies_data: list, package_map: dict):
        """Parse dependencies and populate package dependencies."""
        for dep_info in dependencies_data:
            ref = dep_info.get("ref", "")
            depends_on = dep_info.get("dependsOn", [])

            # Find the source package
            source_package = package_map.get(ref)
            if source_package:
                for dep_ref in depends_on:
                    # Create dependency object
                    dependency = Dependency(
                        package_id=dep_ref,
                        package_name=(
                            dep_ref.split("@")[0].split("/")[-1]
                            if "@" in dep_ref
                            else dep_ref
                        ),
                        relationship_type="DEPENDS_ON",
                    )
                    source_package.dependencies.append(dependency)
