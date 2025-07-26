"""
SBOM Parser for multiple formats.

Supports parsing SPDX, CycloneDX, and SWID formats with automatic format detection.
"""

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, Optional
import xmltodict

from ..models.sbom_models import SBOMData, SBOMFormat, Package, License, Dependency
from .parsers.spdx_parser import SPDXParser
from .parsers.cyclonedx_parser import CycloneDXParser
from .parsers.swid_parser import SWIDParser


logger = logging.getLogger(__name__)


class SBOMParser:
    """Main SBOM parser with format detection and delegation."""

    def __init__(self) -> None:
        """Initialize the SBOM parser with format-specific parsers."""
        self.spdx_parser = SPDXParser()
        self.cyclonedx_parser = CycloneDXParser()
        self.swid_parser = SWIDParser()

    def parse_file(self, file_path: Path) -> SBOMData:
        """
        Parse an SBOM file with automatic format detection.

        Args:
            file_path: Path to the SBOM file

        Returns:
            Parsed SBOM data

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format cannot be detected or parsed
        """
        logger.info(f"Parsing SBOM file: {file_path}")

        # Check if file exists
        if not file_path.exists():
            raise FileNotFoundError(f"SBOM file not found: {file_path}")

        # Check if file is readable
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        # Detect format
        format_type = self._detect_format(file_path)
        logger.info(f"Detected format: {format_type}")

        # Parse based on format
        try:
            if format_type == SBOMFormat.SPDX:
                return self.spdx_parser.parse(file_path)
            elif format_type == SBOMFormat.CYCLONEDX:
                return self.cyclonedx_parser.parse(file_path)
            elif format_type == SBOMFormat.SWID:
                return self.swid_parser.parse(file_path)
            else:
                raise ValueError(f"Unsupported SBOM format: {format_type}")
        except Exception as e:
            logger.error(f"Failed to parse SBOM file {file_path}: {e}")
            raise ValueError(f"Failed to parse SBOM file: {e}")

    def _detect_format(self, file_path: Path) -> SBOMFormat:
        """
        Detect the SBOM format based on file content and extension.

        Args:
            file_path: Path to the SBOM file

        Returns:
            Detected SBOM format
        """
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"File is not a valid text file: {file_path}")

        # Try to parse as JSON first
        try:
            data = json.loads(content)

            # Check for SPDX format
            if "spdxVersion" in data:
                return SBOMFormat.SPDX

            # Check for CycloneDX format
            if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
                return SBOMFormat.CYCLONEDX

            # Check for SWID format (SWID can be JSON)
            if "tagId" in data and "softwareIdentity" in data:
                return SBOMFormat.SWID

        except json.JSONDecodeError:
            pass

        # Try to parse as XML
        try:
            root = ET.fromstring(content)

            # Check for SPDX XML format
            if root.tag.endswith("SpdxDocument") or "spdx" in root.tag.lower():
                return SBOMFormat.SPDX

            # Check for CycloneDX XML format
            if root.tag.endswith("bom") or "cyclonedx" in root.tag.lower():
                return SBOMFormat.CYCLONEDX

            # Check for SWID XML format
            if root.tag.endswith("SoftwareIdentity") or "swid" in root.tag.lower():
                return SBOMFormat.SWID

        except ET.ParseError:
            pass

        # Check file extension as fallback
        extension = file_path.suffix.lower()
        if extension in [".spdx", ".spdx.json", ".spdx.xml"]:
            return SBOMFormat.SPDX
        elif extension in [".cdx", ".cyclonedx", ".bom"]:
            return SBOMFormat.CYCLONEDX
        elif extension in [".swid", ".swidtag"]:
            return SBOMFormat.SWID

        # Default to SPDX if we can't determine
        logger.warning(
            f"Could not detect SBOM format for {file_path}, defaulting to SPDX"
        )
        return SBOMFormat.SPDX
