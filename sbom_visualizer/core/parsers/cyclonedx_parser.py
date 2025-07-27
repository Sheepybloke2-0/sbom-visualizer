"""
CycloneDX format parser.

Handles parsing of CycloneDX 1.5 format files.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

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

    def parse(self, file_path: Path) -> SBOMData:
        """
        Parse a CycloneDX file.

        Args:
            file_path: Path to the CycloneDX file

        Returns:
            Parsed SBOM data

        Raises:
            ValueError: If file cannot be parsed as CycloneDX
        """
        logger.info(f"Parsing CycloneDX file: {file_path}")

        try:
            # Read and parse the file
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
            return self._convert_cyclonedx_to_sbom_data(data)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CycloneDX JSON {file_path}: {e}")
            raise ValueError(f"Failed to parse CycloneDX JSON: {e}")
        except Exception as e:
            logger.error(f"Failed to parse CycloneDX file {file_path}: {e}")
            raise ValueError(f"Failed to parse CycloneDX file: {e}")

    def _convert_cyclonedx_to_sbom_data(self, data: Dict[str, Any]) -> SBOMData:
        """
        Convert CycloneDX data to internal SBOM data structure.

        Args:
            data: Parsed CycloneDX JSON data

        Returns:
            Converted SBOM data
        """
        # Extract metadata
        metadata = data.get("metadata", {})
        bom_format = data.get("bomFormat", "CycloneDX")
        spec_version = data.get("specVersion", "1.5")

        # Extract creation info
        created = datetime.now()  # CycloneDX doesn't always have creation time
        if "timestamp" in metadata:
            try:
                created = datetime.fromisoformat(
                    metadata["timestamp"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        creator = "Unknown"
        if "tools" in metadata and metadata["tools"]:
            tool = metadata["tools"][0]
            creator = tool.get("name", "Unknown")

        document_name = metadata.get("component", {}).get("name", "CycloneDX BOM")

        # Convert components to packages
        packages = []
        components = data.get("components", [])
        for component in components:
            package = self._convert_cyclonedx_component(component)
            packages.append(package)

        # Extract relationships
        relationships = []
        for rel in data.get("dependencies", []):
            ref = rel.get("ref", "")
            depends_on = rel.get("dependsOn", [])
            for dep in depends_on:
                relationships.append({"ref": ref, "dependsOn": dep})

        return SBOMData(
            format=SBOMFormat.CYCLONEDX,
            version=spec_version,
            document_name=document_name,
            document_namespace=None,
            created=created,
            creator=creator,
            packages=packages,
            relationships=relationships,
            metadata={
                "bomFormat": bom_format,
                "specVersion": spec_version,
                "serialNumber": metadata.get("serialNumber"),
                "version": metadata.get("version"),
            },
        )

    def _convert_cyclonedx_component(self, component: Dict[str, Any]) -> Package:
        """
        Convert CycloneDX component to internal Package model.

        Args:
            component: CycloneDX component data

        Returns:
            Converted Package object
        """
        # Extract licenses
        licenses = []
        for license_info in component.get("licenses", []):
            if "license" in license_info:
                license_data = license_info["license"]
                licenses.append(
                    License(
                        identifier=license_data.get("id"),
                        name=license_data.get("name"),
                        url=license_data.get("url"),
                    )
                )

        # Extract dependencies
        dependencies = []
        # Note: Dependencies are handled at the document level in CycloneDX

        # Extract vulnerabilities
        vulnerabilities = []
        for vuln in component.get("vulnerabilities", []):
            vulnerabilities.append(
                Vulnerability(
                    cve_id=vuln.get("id"),
                    severity=(
                        vuln.get("ratings", [{}])[0].get("severity")
                        if vuln.get("ratings")
                        else None
                    ),
                    description=vuln.get("description"),
                    affected_versions=vuln.get("affects", []),
                )
            )

        # Extract external references (PURL)
        purl = None
        for ref in component.get("externalReferences", []):
            if ref.get("type") == "purl":
                purl = ref.get("url")
                break

        return Package(
            id=component.get("bomRef", component.get("name")),
            name=component.get("name"),
            version=component.get("version"),
            description=component.get("description"),
            licenses=licenses,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            purl=purl,
            supplier=component.get("publisher"),
            homepage=(
                component.get("externalReferences", [{}])[0].get("url")
                if component.get("externalReferences")
                else None
            ),
            source_info=None,
            checksums={
                hash_obj.get("alg"): hash_obj.get("content")
                for hash_obj in component.get("hashes", [])
            },
        )
