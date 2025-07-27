"""
SPDX format parser.

Handles parsing of SPDX 3.0 format files using spdx-tools library.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ...models.sbom_models import Dependency, License, Package, SBOMData, SBOMFormat

logger = logging.getLogger(__name__)


class SPDXParser:
    """Parser for SPDX format SBOM files."""

    def parse(self, file_path: Path) -> SBOMData:
        """
        Parse an SPDX file.

        Args:
            file_path: Path to the SPDX file

        Returns:
            Parsed SBOM data

        Raises:
            ValueError: If file cannot be parsed as SPDX
        """
        logger.info(f"Parsing SPDX file: {file_path}")

        try:
            # Try to parse as JSON first
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)

            # Validate it's an SPDX file
            if "spdxVersion" not in data:
                raise ValueError(
                    "File does not contain valid SPDX data (missing spdxVersion)"
                )

            return self._convert_spdx_json_to_sbom_data(data)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SPDX JSON {file_path}: {e}")
            raise ValueError(f"Failed to parse SPDX JSON: {e}")
        except Exception as e:
            logger.error(f"Failed to parse SPDX file {file_path}: {e}")
            raise ValueError(f"Failed to parse SPDX file: {e}")

    def _convert_spdx_json_to_sbom_data(self, data: Dict[str, Any]) -> SBOMData:
        """
        Convert SPDX JSON data to internal SBOM data structure.

        Args:
            data: Parsed SPDX JSON data

        Returns:
            Converted SBOM data
        """
        # Extract basic document information
        document_name = data.get("documentName", "Unknown SPDX Document")
        creator = "Unknown"
        created = datetime.now()

        # Extract creation info
        creation_info = data.get("creationInfo", {})
        if creation_info:
            creators = creation_info.get("creators", [])
            if creators:
                creator = creators[0]

            # Try to parse creation date
            created_str = creation_info.get("created")
            if created_str:
                try:
                    created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

        # Convert packages
        packages = []
        spdx_packages = data.get("packages", [])
        for spdx_package in spdx_packages:
            package = self._convert_spdx_package(spdx_package)
            packages.append(package)

        # Extract relationships
        relationships = []
        spdx_relationships = data.get("relationships", [])
        for rel in spdx_relationships:
            rel_data = {
                "spdx_element_id": rel.get("spdxElementId"),
                "related_spdx_element_id": rel.get("relatedSpdxElementId"),
                "relationship_type": rel.get("relationshipType"),
            }
            relationships.append(rel_data)

        return SBOMData(
            format=SBOMFormat.SPDX,
            version=data.get("spdxVersion", "SPDX-2.3"),
            document_name=document_name,
            document_namespace=data.get("documentNamespace"),
            created=created,
            creator=creator,
            packages=packages,
            relationships=relationships,
            metadata={
                "spdx_version": data.get("spdxVersion"),
                "data_license": data.get("dataLicense"),
            },
        )

    def _convert_spdx_package(self, spdx_package: Dict[str, Any]) -> Package:
        """
        Convert SPDX package to internal Package model.

        Args:
            spdx_package: SPDX package data

        Returns:
            Converted Package object
        """
        # Extract licenses
        licenses = []
        license_declared = spdx_package.get("licenseDeclared")
        if license_declared:
            licenses.append(License(identifier=license_declared, name=license_declared))

        license_concluded = spdx_package.get("licenseConcluded")
        if license_concluded:
            licenses.append(
                License(identifier=license_concluded, name=license_concluded)
            )

        # Extract dependencies (from relationships)
        dependencies = []
        # Note: Dependencies would need to be extracted from relationships
        # This is a simplified implementation

        # Extract vulnerabilities
        vulnerabilities = []
        # Note: Vulnerability information would need to be extracted from annotations
        # This is a simplified implementation

        # Extract external references (PURL)
        purl = None
        external_refs = spdx_package.get("externalRefs", [])
        for ref in external_refs:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break

        return Package(
            id=spdx_package.get("SPDXID", spdx_package.get("name")),
            name=spdx_package.get("name", "Unknown"),
            version=spdx_package.get("versionInfo"),
            description=spdx_package.get("description"),
            licenses=licenses,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            purl=purl,
            supplier=spdx_package.get("supplier"),
            homepage=spdx_package.get("homepage"),
            source_info=spdx_package.get("sourceInfo"),
            checksums={},
        )
