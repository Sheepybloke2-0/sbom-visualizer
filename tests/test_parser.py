"""
Tests for SBOM parser functionality.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from sbom_visualizer.core.parser import SBOMParser
from sbom_visualizer.models.sbom_models import SBOMFormat, SBOMData, Package, License


class TestSBOMParser:
    """Test cases for SBOMParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = SBOMParser()
        self.sample_spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentName": "Test SPDX Document",
            "documentNamespace": "https://example.com/spdx/test",
            "creationInfo": {
                "creators": ["Tool: Test"],
                "created": "2024-01-15T10:00:00Z",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-test",
                    "name": "test-package",
                    "versionInfo": "1.0.0",
                    "description": "Test package",
                    "licenseDeclared": "MIT",
                    "licenseConcluded": "MIT",
                }
            ],
            "relationships": [],
        }

    def test_parse_file_success(self):
        """Test successful parsing of an SPDX file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_spdx_data, f)
            file_path = Path(f.name)

        try:
            result = self.parser.parse_file(file_path)

            assert isinstance(result, SBOMData)
            assert result.format == SBOMFormat.SPDX
            assert result.document_name == "Test SPDX Document"
            assert len(result.packages) == 1
            assert result.packages[0].name == "test-package"
        finally:
            file_path.unlink()

    def test_parse_file_not_found(self):
        """Test parsing a non-existent file."""
        with pytest.raises(FileNotFoundError):
            self.parser.parse_file(Path("nonexistent.json"))

    def test_parse_file_not_a_file(self):
        """Test parsing a path that is not a file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            with pytest.raises(ValueError, match="Path is not a file"):
                self.parser.parse_file(dir_path)

    def test_parse_file_invalid_json(self):
        """Test parsing an invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content")
            file_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Failed to parse SPDX JSON"):
                self.parser.parse_file(file_path)
        finally:
            file_path.unlink()

    def test_parse_file_not_spdx(self):
        """Test parsing a JSON file that is not SPDX."""
        invalid_data = {"not": "spdx", "data": "here"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(invalid_data, f)
            file_path = Path(f.name)

        try:
            # Should default to SPDX format but fail during parsing
            with pytest.raises(ValueError):
                self.parser.parse_file(file_path)
        finally:
            file_path.unlink()

    def test_detect_format_spdx_json(self):
        """Test SPDX format detection from JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_spdx_data, f)
            file_path = Path(f.name)

        try:
            format_type = self.parser._detect_format(file_path)
            assert format_type == SBOMFormat.SPDX
        finally:
            file_path.unlink()

    def test_detect_format_cyclonedx_json(self):
        """Test CycloneDX format detection from JSON."""
        cyclonedx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cyclonedx_data, f)
            file_path = Path(f.name)

        try:
            format_type = self.parser._detect_format(file_path)
            assert format_type == SBOMFormat.CYCLONEDX
        finally:
            file_path.unlink()

    def test_detect_format_swid_json(self):
        """Test SWID format detection from JSON."""
        swid_data = {
            "tagId": "test-swid",
            "softwareIdentity": {"name": "test-software"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(swid_data, f)
            file_path = Path(f.name)

        try:
            format_type = self.parser._detect_format(file_path)
            assert format_type == SBOMFormat.SWID
        finally:
            file_path.unlink()

    def test_detect_format_by_extension(self):
        """Test format detection by file extension."""
        # Test SPDX extension
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            file_path = Path(f.name)

        try:
            format_type = self.parser._detect_format(file_path)
            assert format_type == SBOMFormat.SPDX
        finally:
            file_path.unlink()

        # Test CycloneDX extension
        with tempfile.NamedTemporaryFile(suffix=".cdx", delete=False) as f:
            file_path = Path(f.name)

        try:
            format_type = self.parser._detect_format(file_path)
            assert format_type == SBOMFormat.CYCLONEDX
        finally:
            file_path.unlink()

    def test_detect_format_unicode_error(self):
        """Test format detection with unicode decode error."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\xff\xfe\x00\x00")  # Invalid UTF-8
            file_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="File is not a valid text file"):
                self.parser._detect_format(file_path)
        finally:
            file_path.unlink()

    @patch("sbom_visualizer.core.parsers.spdx_parser.SPDXParser.parse")
    def test_parse_file_spdx_delegation(self, mock_spdx_parse):
        """Test that SPDX parsing is delegated correctly."""
        mock_result = MagicMock(spec=SBOMData)
        mock_spdx_parse.return_value = mock_result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_spdx_data, f)
            file_path = Path(f.name)

        try:
            result = self.parser.parse_file(file_path)
            assert result == mock_result
            mock_spdx_parse.assert_called_once_with(file_path)
        finally:
            file_path.unlink()

    @patch("sbom_visualizer.core.parsers.spdx_parser.SPDXParser.parse")
    def test_parse_file_exception_handling(self, mock_spdx_parse):
        """Test exception handling during parsing."""
        mock_spdx_parse.side_effect = Exception("Test error")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_spdx_data, f)
            file_path = Path(f.name)

        try:
            with pytest.raises(
                ValueError, match="Failed to parse SBOM file: Test error"
            ):
                self.parser.parse_file(file_path)
        finally:
            file_path.unlink()
