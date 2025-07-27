"""
Tests for Dependency Viewer.

Tests the dependency tree generation and analysis functionality.
"""

from datetime import datetime

import pytest

from sbom_visualizer.core.dependency_viewer import DependencyViewer
from sbom_visualizer.models.sbom_models import (
    Dependency,
    DependencyTree,
    License,
    Package,
    SBOMData,
    SBOMFormat,
)


class TestDependencyViewer:
    """Test cases for DependencyViewer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.viewer = DependencyViewer()

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
                    dependencies=[
                        Dependency(
                            package_id="pkg3",
                            package_name="urllib3",
                            relationship_type="DEPENDS_ON",
                        )
                    ],
                ),
                Package(
                    id="pkg3",
                    name="urllib3",
                    version="2.0.7",
                    description="HTTP library",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
            ],
            relationships=[],
            metadata={},
        )

        # Create SBOM with circular dependencies
        self.circular_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Circular Test SBOM",
            document_namespace="https://example.com/circular",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="package-a",
                    version="1.0.0",
                    description="Package A",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg2",
                            package_name="package-b",
                            relationship_type="DEPENDS_ON",
                        )
                    ],
                ),
                Package(
                    id="pkg2",
                    name="package-b",
                    version="1.0.0",
                    description="Package B",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg1",
                            package_name="package-a",
                            relationship_type="DEPENDS_ON",
                        )
                    ],
                ),
            ],
            relationships=[],
            metadata={},
        )

    def test_build_dependency_tree_empty_sbom(self):
        """Test building dependency tree with empty SBOM."""
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

        result = self.viewer.build_dependency_tree(empty_sbom)

        assert isinstance(result, DependencyTree)
        assert result.tree_structure == {}
        assert result.root_packages == []
        assert result.depth_analysis == {}
        assert result.circular_dependencies == []
        assert result.total_dependencies == 0
        assert result.max_depth == 0

    def test_build_dependency_tree_single_package(self):
        """Test building dependency tree with single package."""
        single_package_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Single Package SBOM",
            document_namespace="https://example.com/single",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="single-package",
                    version="1.0.0",
                    description="Single package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.viewer.build_dependency_tree(single_package_sbom)

        assert isinstance(result, DependencyTree)
        assert "single-package" in result.tree_structure
        assert result.tree_structure["single-package"] == []
        assert "single-package" in result.root_packages
        assert result.total_dependencies == 0
        assert result.max_depth == 0

    def test_build_dependency_tree_with_dependencies(self):
        """Test building dependency tree with dependencies."""
        result = self.viewer.build_dependency_tree(self.sample_sbom)

        assert isinstance(result, DependencyTree)
        assert "flask" in result.tree_structure
        assert "requests" in result.tree_structure
        assert "urllib3" in result.tree_structure

        # Check dependencies
        assert result.tree_structure["flask"] == ["requests"]
        assert result.tree_structure["requests"] == ["urllib3"]
        assert result.tree_structure["urllib3"] == []

        # Check root packages (packages with no dependencies)
        assert "urllib3" in result.root_packages
        assert "flask" not in result.root_packages
        assert "requests" not in result.root_packages

        # Check depth analysis
        assert result.depth_analysis["flask"] == 2
        assert result.depth_analysis["requests"] == 1
        assert result.depth_analysis["urllib3"] == 0

        # Check statistics
        assert result.total_dependencies == 2
        assert result.max_depth == 2

    def test_build_dependency_tree_with_circular_dependencies(self):
        """Test building dependency tree with circular dependencies."""
        result = self.viewer.build_dependency_tree(self.circular_sbom)

        assert isinstance(result, DependencyTree)
        assert "package-a" in result.tree_structure
        assert "package-b" in result.tree_structure

        # Check circular dependencies
        assert len(result.circular_dependencies) > 0
        assert any("package-a" in cycle for cycle in result.circular_dependencies)
        assert any("package-b" in cycle for cycle in result.circular_dependencies)

    def test_calculate_package_depth(self):
        """Test calculating package depth."""
        dependency_graph = {
            "flask": ["requests"],
            "requests": ["urllib3"],
            "urllib3": [],
        }

        depth = self.viewer._calculate_package_depth("flask", dependency_graph)
        assert depth == 2

        depth = self.viewer._calculate_package_depth("requests", dependency_graph)
        assert depth == 1

        depth = self.viewer._calculate_package_depth("urllib3", dependency_graph)
        assert depth == 0

    def test_detect_circular_dependencies(self):
        """Test detecting circular dependencies."""
        dependency_graph = {"package-a": ["package-b"], "package-b": ["package-a"]}

        circular_deps = self.viewer._detect_circular_dependencies(dependency_graph)
        assert len(circular_deps) > 0
        assert any("package-a" in cycle for cycle in circular_deps)
        assert any("package-b" in cycle for cycle in circular_deps)

    def test_detect_circular_dependencies_no_circular(self):
        """Test detecting circular dependencies when none exist."""
        dependency_graph = {
            "flask": ["requests"],
            "requests": ["urllib3"],
            "urllib3": [],
        }

        circular_deps = self.viewer._detect_circular_dependencies(dependency_graph)
        assert len(circular_deps) == 0

    def test_find_root_packages(self):
        """Test finding root packages."""
        root_packages = self.viewer.find_root_packages(self.sample_sbom)
        assert "urllib3" in root_packages
        assert "flask" not in root_packages
        assert "requests" not in root_packages

    def test_find_root_packages_empty(self):
        """Test finding root packages in empty SBOM."""
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

        root_packages = self.viewer.find_root_packages(empty_sbom)
        assert root_packages == []

    def test_calculate_max_depth(self):
        """Test calculating maximum depth."""
        max_depth = self.viewer.calculate_max_depth(self.sample_sbom)
        assert max_depth == 2

    def test_calculate_max_depth_empty(self):
        """Test calculating maximum depth for empty SBOM."""
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

        max_depth = self.viewer.calculate_max_depth(empty_sbom)
        assert max_depth == 0

    def test_format_tree_for_cli(self):
        """Test formatting tree for CLI output."""
        tree = self.viewer.build_dependency_tree(self.sample_sbom)
        result = self.viewer.format_tree_for_cli(tree)

        assert isinstance(result, str)
        assert "Dependency Tree:" in result
        assert "flask" in result
        assert "requests" in result
        assert "urllib3" in result

    def test_format_tree_for_cli_empty(self):
        """Test formatting empty tree for CLI output."""
        empty_tree = DependencyTree(
            tree_structure={},
            root_packages=[],
            depth_analysis={},
            circular_dependencies=[],
            total_dependencies=0,
            max_depth=0,
        )

        result = self.viewer.format_tree_for_cli(empty_tree)
        assert result == "No dependencies found."
