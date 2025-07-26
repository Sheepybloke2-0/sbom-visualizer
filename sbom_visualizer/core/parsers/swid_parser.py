"""
SWID format parser.

Handles parsing of SWID (Software Identification Tags) format files.
"""

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from ...models.sbom_models import SBOMData, SBOMFormat, Package, License, Dependency


logger = logging.getLogger(__name__)


class SWIDParser:
    """Parser for SWID format SBOM files."""

    def parse(self, file_path: Path) -> SBOMData:
        """
        Parse a SWID file.

        Args:
            file_path: Path to the SWID file

        Returns:
            Parsed SBOM data

        Raises:
            ValueError: If file cannot be parsed as SWID
        """
        logger.info(f"Parsing SWID file: {file_path}")

        try:
            # Try to parse as XML first (most common SWID format)
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                return self._parse_swid_xml(root)
            except ET.ParseError:
                # Try as JSON
                content = file_path.read_text(encoding="utf-8")
                data = json.loads(content)
                return self._parse_swid_json(data)

        except Exception as e:
            logger.error(f"Failed to parse SWID file {file_path}: {e}")
            raise ValueError(f"Failed to parse SWID file: {e}")

    def _parse_swid_xml(self, root: ET.Element) -> SBOMData:
        """
        Parse SWID XML format.

        Args:
            root: XML root element

        Returns:
            Parsed SBOM data
        """
        # Extract basic information
        tag_id = root.get("tagId", "")
        name = root.get("name", "")
        version = root.get("version", "")

        # Extract creation info
        created = datetime.now()
        if root.get("versionScheme"):
            # Try to parse version scheme for creation info
            pass

        # Convert to package
        package = Package(
            id=tag_id,
            name=name,
            version=version,
            description=root.get("description", ""),
            licenses=[],  # SWID doesn't typically include license info
            dependencies=[],
            vulnerabilities=[],
            purl=None,
            supplier=root.get("regid", ""),
            homepage=None,
            source_info=None,
            checksums={},
        )

        return SBOMData(
            format=SBOMFormat.SWID,
            version="1.0",  # SWID version
            document_name=name,
            document_namespace=None,
            created=created,
            creator="SWID Generator",
            packages=[package],
            relationships=[],
            metadata={
                "tagId": tag_id,
                "regid": root.get("regid"),
                "versionScheme": root.get("versionScheme"),
            },
        )

    def _parse_swid_json(self, data: Dict[str, Any]) -> SBOMData:
        """
        Parse SWID JSON format.

        Args:
            data: SWID JSON data

        Returns:
            Parsed SBOM data
        """
        # Extract software identity
        software_identity = data.get("softwareIdentity", {})

        tag_id = software_identity.get("tagId", "")
        name = software_identity.get("name", "")
        version = software_identity.get("version", "")

        # Extract creation info
        created = datetime.now()
        if "versionScheme" in software_identity:
            # Try to parse version scheme for creation info
            pass

        # Convert to package
        package = Package(
            id=tag_id,
            name=name,
            version=version,
            description=software_identity.get("description", ""),
            licenses=[],  # SWID doesn't typically include license info
            dependencies=[],
            vulnerabilities=[],
            purl=None,
            supplier=software_identity.get("regid", ""),
            homepage=None,
            source_info=None,
            checksums={},
        )

        return SBOMData(
            format=SBOMFormat.SWID,
            version="1.0",  # SWID version
            document_name=name,
            document_namespace=None,
            created=created,
            creator="SWID Generator",
            packages=[package],
            relationships=[],
            metadata={
                "tagId": tag_id,
                "regid": software_identity.get("regid"),
                "versionScheme": software_identity.get("versionScheme"),
            },
        )
