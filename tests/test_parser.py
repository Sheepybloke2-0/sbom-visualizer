"""
Tests for SBOM Parser.

Tests the parsing functionality for various SBOM formats.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from sbom_visualizer.core.parser import SBOMParser
from sbom_visualizer.exceptions import SBOMFileError, SBOMFormatError, SBOMParseError
from sbom_visualizer.models.sbom_models import SBOMData, SBOMFormat


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
            assert result.document_name == "Test SPDX Document"
        finally:
            file_path.unlink()

    def test_parse_file_not_found(self):
        """Test parsing a non-existent file."""
        with pytest.raises(SBOMFileError, match="File not found"):
            self.parser.parse_file(Path("nonexistent.json"))

    def test_parse_file_not_a_file(self):
        """Test parsing a path that is not a file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            with pytest.raises(SBOMFileError, match="Path is not a file"):
                self.parser.parse_file(dir_path)

    def test_parse_file_invalid_json(self):
        """Test parsing an invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content")
            file_path = Path(f.name)

        try:
            with pytest.raises(SBOMParseError, match="Error parsing SBOM file"):
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
            # Should fail during format detection
            with pytest.raises(SBOMParseError, match="Error parsing SBOM file"):
                self.parser.parse_file(file_path)
        finally:
            file_path.unlink()

    def test_detect_format_spdx_json(self):
        """Test SPDX format detection from JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_spdx_data, f)
            file_path = Path(f.name)

        try:
            content = file_path.read_text(encoding="utf-8")
            format_type = self.parser._detect_format(file_path, content)
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
            content = file_path.read_text(encoding="utf-8")
            format_type = self.parser._detect_format(file_path, content)
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
            content = file_path.read_text(encoding="utf-8")
            format_type = self.parser._detect_format(file_path, content)
            assert format_type == SBOMFormat.SWID
        finally:
            file_path.unlink()

    def test_detect_format_by_extension(self):
        """Test format detection by file extension."""
        # Test SPDX extension
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            file_path = Path(f.name)

        try:
            content = '{"spdxVersion": "SPDX-2.3"}'
            format_type = self.parser._detect_format(file_path, content)
            assert format_type == SBOMFormat.SPDX
        finally:
            file_path.unlink()

        # Test CycloneDX extension
        with tempfile.NamedTemporaryFile(suffix=".cdx", delete=False) as f:
            file_path = Path(f.name)

        try:
            content = '{"bomFormat": "CycloneDX"}'
            format_type = self.parser._detect_format(file_path, content)
            assert format_type == SBOMFormat.CYCLONEDX
        finally:
            file_path.unlink()

    def test_detect_format_unicode_error(self):
        """Test format detection with unicode decode error."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\xff\xfe\x00\x00")  # Invalid UTF-8
            file_path = Path(f.name)

        try:
            content = ""
            # This should work since we're not reading the file in _detect_format
            # but it will fail format detection since no content and no extension
            with pytest.raises(SBOMFormatError, match="Cannot detect SBOM format"):
                self.parser._detect_format(file_path, content)
        finally:
            file_path.unlink()

    @patch("sbom_visualizer.core.parsers.spdx_parser.SPDXParser.parse")
    def test_parse_file_spdx_delegation(self, mock_spdx_parse):
        """Test that SPDX parsing is delegated correctly."""
        mock_result = Mock(spec=SBOMData)
        mock_spdx_parse.return_value = mock_result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.sample_spdx_data, f)
            file_path = Path(f.name)

        try:
            result = self.parser.parse_file(file_path)
            assert result == mock_result
            # The mock should be called with content and file_path
            mock_spdx_parse.assert_called_once()
            call_args = mock_spdx_parse.call_args
            assert len(call_args[0]) == 2  # content and file_path
            assert call_args[0][1] == file_path  # file_path is second argument
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
            with pytest.raises(SBOMParseError, match="Error parsing SBOM file"):
                self.parser.parse_file(file_path)
        finally:
            file_path.unlink()

    def test_parse_spdx_with_dependencies(self, tmp_path):
        """Test parsing SPDX file with dependency relationships."""
        file_path = tmp_path / "test.spdx.json"
        content = {
            "spdxVersion": "SPDX-2.3",
            "documentName": "Test SBOM",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "creators": ["Tool: Test"],
                "created": "2024-01-01T00:00:00Z",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-flask",
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "description": "Web framework",
                    "licenseDeclared": "BSD-3-Clause",
                },
                {
                    "SPDXID": "SPDXRef-Package-requests",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "description": "HTTP library",
                    "licenseDeclared": "Apache-2.0",
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-Package-flask",
                    "relatedSpdxElementId": "SPDXRef-Package-requests",
                    "relationshipType": "DEPENDS_ON",
                }
            ],
        }
        file_path.write_text(json.dumps(content))

        result = self.parser.parse_file(file_path)

        assert result.format == SBOMFormat.SPDX
        assert len(result.packages) == 2

        # Check that dependencies were parsed
        flask_package = next(p for p in result.packages if p.name == "flask")
        assert len(flask_package.dependencies) == 1
        assert flask_package.dependencies[0].package_name == "requests"

    def test_parse_spdx_without_dependencies(self, tmp_path):
        """Test parsing SPDX file without dependency relationships."""
        file_path = tmp_path / "test.spdx.json"
        content = {
            "spdxVersion": "SPDX-2.3",
            "documentName": "Test SBOM",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "creators": ["Tool: Test"],
                "created": "2024-01-01T00:00:00Z",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-flask",
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "description": "Web framework",
                    "licenseDeclared": "BSD-3-Clause",
                }
            ],
            "relationships": [],
        }
        file_path.write_text(json.dumps(content))

        result = self.parser.parse_file(file_path)

        assert result.format == SBOMFormat.SPDX
        assert len(result.packages) == 1

        # Check that no dependencies were parsed
        flask_package = result.packages[0]
        assert len(flask_package.dependencies) == 0

    def test_parse_spdx_invalid_relationships(self, tmp_path):
        """Test parsing SPDX file with invalid relationship references."""
        file_path = tmp_path / "test.spdx.json"
        content = {
            "spdxVersion": "SPDX-2.3",
            "documentName": "Test SBOM",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "creators": ["Tool: Test"],
                "created": "2024-01-01T00:00:00Z",
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-flask",
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "description": "Web framework",
                    "licenseDeclared": "BSD-3-Clause",
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-Package-flask",
                    "relatedSpdxElementId": "SPDXRef-Package-nonexistent",
                    "relationshipType": "DEPENDS_ON",
                }
            ],
        }
        file_path.write_text(json.dumps(content))

        result = self.parser.parse_file(file_path)

        assert result.format == SBOMFormat.SPDX
        assert len(result.packages) == 1

        # Check that invalid dependency reference doesn't cause errors
        flask_package = result.packages[0]
        assert len(flask_package.dependencies) == 0

    def test_parse_cyclonedx_with_dependencies(self, tmp_path):
        """Test parsing CycloneDX file with dependencies."""
        file_path = tmp_path / "test.cyclonedx.json"
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": "flask",
                    "version": "3.0.0",
                    "description": "Web framework",
                    "licenses": [
                        {
                            "license": {
                                "id": "BSD-3-Clause",
                                "name": "BSD 3-Clause License",
                            }
                        }
                    ],
                    "purl": "pkg:pypi/flask@3.0.0",
                },
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.31.0",
                    "description": "HTTP library",
                    "licenses": [
                        {"license": {"id": "Apache-2.0", "name": "Apache License 2.0"}}
                    ],
                    "purl": "pkg:pypi/requests@2.31.0",
                },
            ],
            "dependencies": [
                {
                    "ref": "pkg:pypi/flask@3.0.0",
                    "dependsOn": ["pkg:pypi/requests@2.31.0"],
                }
            ],
        }
        file_path.write_text(json.dumps(content))

        result = self.parser.parse_file(file_path)

        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.packages) == 2

        # Check that dependencies were parsed
        flask_package = next(p for p in result.packages if p.name == "flask")
        assert len(flask_package.dependencies) == 1
        assert flask_package.dependencies[0].package_name == "requests"

    def test_parse_cyclonedx_without_dependencies(self, tmp_path):
        """Test parsing CycloneDX file without dependencies."""
        file_path = tmp_path / "test.cyclonedx.json"
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": "flask",
                    "version": "3.0.0",
                    "description": "Web framework",
                    "licenses": [
                        {
                            "license": {
                                "id": "BSD-3-Clause",
                                "name": "BSD 3-Clause License",
                            }
                        }
                    ],
                    "purl": "pkg:pypi/flask@3.0.0",
                }
            ],
            "dependencies": [],
        }
        file_path.write_text(json.dumps(content))

        result = self.parser.parse_file(file_path)

        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.packages) == 1

        # Check that no dependencies were parsed
        flask_package = result.packages[0]
        assert len(flask_package.dependencies) == 0

    def test_parse_cyclonedx_without_purls(self, tmp_path):
        """Test parsing CycloneDX file without PURLs."""
        file_path = tmp_path / "test.cyclonedx.json"
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": "flask",
                    "version": "3.0.0",
                    "description": "Web framework",
                    "licenses": [
                        {
                            "license": {
                                "id": "BSD-3-Clause",
                                "name": "BSD 3-Clause License",
                            }
                        }
                    ],
                }
            ],
            "dependencies": [],
        }
        file_path.write_text(json.dumps(content))

        result = self.parser.parse_file(file_path)

        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.packages) == 1

        flask_package = result.packages[0]
        assert flask_package.id == "pkg:flask@3.0.0"  # Generated from name and version

    def test_parse_cyclonedx_invalid_dependencies(self, tmp_path):
        """Test parsing CycloneDX file with invalid dependency references."""
        file_path = tmp_path / "test.cyclonedx.json"
        content = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": "flask",
                    "version": "3.0.0",
                    "description": "Web framework",
                    "licenses": [
                        {
                            "license": {
                                "id": "BSD-3-Clause",
                                "name": "BSD 3-Clause License",
                            }
                        }
                    ],
                    "purl": "pkg:pypi/flask@3.0.0",
                }
            ],
            "dependencies": [
                {
                    "ref": "pkg:pypi/flask@3.0.0",
                    "dependsOn": ["pkg:pypi/nonexistent@1.0.0"],
                }
            ],
        }
        file_path.write_text(json.dumps(content))

        result = self.parser.parse_file(file_path)

        assert result.format == SBOMFormat.CYCLONEDX
        assert len(result.packages) == 1

        # Check that invalid dependency reference doesn't cause errors
        flask_package = result.packages[0]
        assert (
            len(flask_package.dependencies) == 1
        )  # Should still create the dependency object
