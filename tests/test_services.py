"""
Tests for Service Layer.

Tests the service layer functionality including dependency tree generation.
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from sbom_visualizer.core.dependency_viewer import DependencyViewer
from sbom_visualizer.core.parser import SBOMParser
from sbom_visualizer.exceptions import SBOMAnalysisError
from sbom_visualizer.models.sbom_models import (
    Dependency,
    DependencyTree,
    License,
    Package,
    SBOMData,
    SBOMFormat,
)
from sbom_visualizer.services.sbom_service import SBOMService


class TestSBOMService:
    """Test cases for SBOMService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = SBOMService()

        # Create sample SBOM data with dependencies
        self.sample_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Test SBOM",
            document_namespace="https://example.com/test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="flask",
                    version="3.0.0",
                    description="Web framework",
                    licenses=[License(identifier="BSD-3-Clause")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg2",
                            package_name="requests",
                            relationship_type="DEPENDS_ON",
                        )
                    ],
                ),
                Package(
                    id="pkg2",
                    name="requests",
                    version="2.31.0",
                    description="HTTP library",
                    licenses=[License(identifier="Apache-2.0")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
            ],
            relationships=[],
            metadata={},
        )

    def test_get_dependency_tree_success(self):
        """Test successful dependency tree generation."""
        result = self.service.get_dependency_tree(self.sample_sbom)

        assert isinstance(result, DependencyTree)
        assert "flask" in result.tree_structure
        assert "requests" in result.tree_structure
        assert result.tree_structure["flask"] == ["requests"]
        assert result.tree_structure["requests"] == []
        assert "requests" in result.root_packages
        assert result.total_dependencies == 1
        assert result.max_depth == 1

    def test_get_dependency_tree_empty_sbom(self):
        """Test dependency tree generation with empty SBOM."""
        empty_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Empty SBOM",
            document_namespace="https://example.com/empty",
            created=datetime.now(),
            creator="Test Creator",
            packages=[],
            relationships=[],
            metadata={},
        )

        result = self.service.get_dependency_tree(empty_sbom)

        assert isinstance(result, DependencyTree)
        assert result.tree_structure == {}
        assert result.root_packages == []
        assert result.total_dependencies == 0
        assert result.max_depth == 0

    def test_get_dependency_tree_error(self):
        """Test dependency tree generation with error."""
        # Mock the dependency viewer to raise an exception
        mock_viewer = Mock()
        mock_viewer.build_dependency_tree.side_effect = Exception("Test error")

        service = SBOMService(dependency_viewer=mock_viewer)

        with pytest.raises(
            SBOMAnalysisError, match="Failed to generate dependency tree"
        ):
            service.get_dependency_tree(self.sample_sbom)

    def test_parse_sbom_success(self, tmp_path):
        """Test successful SBOM parsing."""
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
        file_path.write_text(str(content).replace("'", '"'))

        result = self.service.parse_sbom(file_path)

        assert isinstance(result, SBOMData)
        assert result.format == SBOMFormat.SPDX
        assert len(result.packages) == 1
        assert result.packages[0].name == "flask"

    def test_parse_sbom_file_not_found(self):
        """Test SBOM parsing with non-existent file."""
        non_existent_path = Path("/non/existent/file.json")

        with pytest.raises(Exception, match="File not found"):
            self.service.parse_sbom(non_existent_path)

    def test_analyze_sbom_success(self):
        """Test successful SBOM analysis."""
        result = self.service.analyze_sbom(self.sample_sbom)

        assert result.total_packages == 2
        assert len(result.unique_licenses) == 2
        assert "BSD-3-Clause" in result.unique_licenses
        assert "Apache-2.0" in result.unique_licenses
        assert result.completeness_score > 0

    def test_verify_sbom_success(self):
        """Test successful SBOM verification."""
        result = self.service.verify_sbom(self.sample_sbom)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)
        assert result.format_detected == SBOMFormat.SPDX
        assert result.version_detected == "2.3"

    def test_get_package_info_success(self):
        """Test successful package info retrieval."""
        result = self.service.get_package_info(self.sample_sbom, "flask")

        assert result is not None
        assert result.name == "flask"
        assert result.version == "3.0.0"
        assert result.license == "BSD-3-Clause"
        assert len(result.dependencies) == 1
        assert result.dependencies[0] == "requests"

    def test_get_package_info_not_found(self):
        """Test package info retrieval for non-existent package."""
        result = self.service.get_package_info(self.sample_sbom, "nonexistent")

        assert result is None

    def test_analyze_and_verify_success(self, tmp_path):
        """Test successful analyze and verify operation."""
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
        file_path.write_text(str(content).replace("'", '"'))

        analysis_result, verification_result = self.service.analyze_and_verify(
            file_path
        )

        assert analysis_result.total_packages == 1
        assert verification_result.format_detected == SBOMFormat.SPDX
