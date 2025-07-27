"""
SBOM Parser for SBOM Visualizer.

Provides functionality to parse SBOM files in various formats.
"""

import json
import logging
from pathlib import Path
from typing import Union

from ..core.parsers.cyclonedx_parser import CycloneDXParser
from ..core.parsers.spdx_parser import SPDXParser
from ..core.parsers.swid_parser import SWIDParser
from ..exceptions import SBOMFileError, SBOMFormatError, SBOMParseError
from ..models.sbom_models import SBOMData, SBOMFormat

logger = logging.getLogger(__name__)


class SBOMParser:
    """Main parser for SBOM files in various formats."""

    def __init__(self):
        """Initialize the SBOM parser."""
        self.spdx_parser = SPDXParser()
        self.cyclonedx_parser = CycloneDXParser()
        self.swid_parser = SWIDParser()

    def parse_file(self, file_path: Union[str, Path]) -> SBOMData:
        """
        Parse an SBOM file and return structured data.

        Args:
            file_path: Path to the SBOM file

        Returns:
            Parsed SBOM data

        Raises:
            SBOMFileError: If file cannot be read
            SBOMParseError: If file cannot be parsed
            SBOMFormatError: If format is not supported
        """
        file_path = Path(file_path)

        # Check if file exists and is readable
        if not file_path.exists():
            raise SBOMFileError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise SBOMFileError(f"Path is not a file: {file_path}")

        try:
            # Read file content
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise SBOMFileError(f"Cannot read file as text: {file_path}")
        except Exception as e:
            raise SBOMFileError(f"Error reading file {file_path}: {e}")

        # Detect format and parse
        try:
            format_type = self._detect_format(file_path, content)
            return self._parse_by_format(format_type, content, file_path)
        except Exception as e:
            raise SBOMParseError(f"Error parsing SBOM file {file_path}: {e}")

    def _detect_format(self, file_path: Path, content: str) -> SBOMFormat:
        """
        Detect the format of the SBOM file.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Detected SBOM format

        Raises:
            SBOMFormatError: If format cannot be detected
        """
        # Check file extension first
        extension = file_path.suffix.lower()
        if extension in [".spdx", ".spdx.json"]:
            return SBOMFormat.SPDX
        elif extension in [".cdx", ".cyclonedx", ".cyclonedx.json"]:
            return SBOMFormat.CYCLONEDX
        elif extension in [".swid", ".swid.xml"]:
            return SBOMFormat.SWID

        # Try to detect from content
        if content:
            try:
                data = json.loads(content)
                if "spdxVersion" in data:
                    return SBOMFormat.SPDX
                elif "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
                    return SBOMFormat.CYCLONEDX
                elif "softwareIdentity" in data:
                    return SBOMFormat.SWID
            except json.JSONDecodeError:
                # Not JSON, check for XML
                if "<?xml" in content and "softwareIdentity" in content:
                    return SBOMFormat.SWID

        raise SBOMFormatError(f"Cannot detect SBOM format for file: {file_path}")

    def _parse_by_format(
        self, format_type: SBOMFormat, content: str, file_path: Path
    ) -> SBOMData:
        """
        Parse content based on detected format.

        Args:
            format_type: Detected SBOM format
            content: File content
            file_path: Original file path

        Returns:
            Parsed SBOM data

        Raises:
            SBOMParseError: If parsing fails
        """
        try:
            if format_type == SBOMFormat.SPDX:
                return self.spdx_parser.parse(content, file_path)
            elif format_type == SBOMFormat.CYCLONEDX:
                return self.cyclonedx_parser.parse(content, file_path)
            elif format_type == SBOMFormat.SWID:
                return self.swid_parser.parse(content, file_path)
            else:
                raise SBOMParseError(f"Unsupported format: {format_type}")
        except Exception as e:
            raise SBOMParseError(f"Error parsing {format_type} format: {e}")
