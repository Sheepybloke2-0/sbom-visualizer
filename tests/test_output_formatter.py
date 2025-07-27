"""
Tests for Output Formatter.

Tests the output formatting functionality.
"""

import json
import pytest
from unittest.mock import Mock

from sbom_visualizer.utils.output_formatter import OutputFormatter
from sbom_visualizer.models.sbom_models import (
    AnalysisResult,
    DependencyTree,
    PackageInfo,
)


class TestOutputFormatter:
    """Test cases for OutputFormatter."""

    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = OutputFormatter()

        # Create sample analysis result
        self.sample_analysis = AnalysisResult(
            total_packages=3,
            unique_licenses=["MIT", "Apache-2.0"],
            license_distribution={"MIT": 2, "Apache-2.0": 1},
            dependency_depth={},
            vulnerability_summary={"HIGH": 1, "MEDIUM": 0, "LOW": 0},
            completeness_score=85.5,
            recommendations=[
                "Add dependency information for packages",
                "Consider updating vulnerable packages",
            ],
        )

        # Create sample dependency tree
        self.sample_tree = DependencyTree(
            root_packages=["requests", "flask"],
            tree_structure={
                "requests": ["urllib3", "certifi"],
                "flask": ["requests", "jinja2"],
                "urllib3": [],
                "certifi": [],
                "jinja2": [],
            },
            depth_analysis={
                "requests": 0,
                "flask": 0,
                "urllib3": 1,
                "certifi": 1,
                "jinja2": 1,
            },
            circular_dependencies=[],
            total_dependencies=5,
            max_depth=2,
        )

        # Create sample package info
        self.sample_package_info = PackageInfo(
            name="requests",
            version="2.31.0",
            description="HTTP library for Python",
            license="Apache-2.0",
            dependencies=["urllib3", "certifi"],
            vulnerabilities=[],
            purl="pkg:pypi/requests@2.31.0",
            supplier="Python Software Foundation",
            homepage="https://requests.readthedocs.io/",
        )

    def test_format_analysis_text(self):
        """Test formatting analysis result as text."""
        result = self.formatter.format(self.sample_analysis, "text")

        assert isinstance(result, str)
        assert "SBOM Analysis Report" in result
        assert "Total Packages: 3" in result
        assert "Unique Licenses" in result
        assert "Completeness Score: 85.5%" in result

    def test_format_analysis_json(self):
        """Test JSON formatting of analysis results."""
        analysis_result = AnalysisResult(
            total_packages=3,
            unique_licenses=["MIT", "Apache-2.0", "GPL-3.0"],
            dependency_depth={"package1": 0, "package2": 1, "package3": 2},
            vulnerability_summary={"high": 1, "medium": 2, "low": 0},
            completeness_score=75.0,
            recommendations=["Add license information", "Review vulnerabilities"],
        )

        result = self.formatter.format(analysis_result, "json")
        data = json.loads(result)

        assert data["total_packages"] == 3
        assert len(data["unique_licenses"]) == 3
        assert "MIT" in data["unique_licenses"]

    def test_format_analysis_markdown(self):
        """Test markdown formatting of analysis results."""
        result = self.formatter.format(self.sample_analysis, "markdown")

        assert isinstance(result, str)
        assert "# SBOM Analysis Report" in result
        assert "## Summary" in result
        assert "## License Distribution" in result

    def test_format_analysis_html(self):
        """Test HTML formatting of analysis results."""
        analysis_result = AnalysisResult(
            total_packages=2,
            unique_licenses=["MIT"],
            license_distribution={"MIT": 2},
            dependency_depth={},
            vulnerability_summary={"high": 0, "medium": 0, "low": 0},
            completeness_score=90.0,
            recommendations=["All good!"],
        )

        result = self.formatter.format(analysis_result, "html")

        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result
        assert "<html" in result
        assert "<head>" in result
        assert "<body>" in result
        assert "SBOM Analysis Results" in result

    def test_format_tree_text(self):
        """Test text formatting of dependency tree."""
        result = self.formatter.format(self.sample_tree, "text")

        assert isinstance(result, str)
        assert "Dependency Tree" in result
        assert "requests" in result
        assert "flask" in result

    def test_format_tree_json(self):
        """Test JSON formatting of dependency tree."""
        tree_data = DependencyTree(
            root_packages=["root"],
            tree_structure={"root": ["child1", "child2"]},
            depth_analysis={"root": 0, "child1": 1, "child2": 1},
            circular_dependencies=[],
            total_dependencies=2,
            max_depth=1,
        )

        result = self.formatter.format(tree_data, "json")
        data = json.loads(result)

        assert data["root_packages"] == ["root"]
        assert "root" in data["tree_structure"]
        assert data["total_dependencies"] == 2

    def test_format_tree_markdown(self):
        """Test markdown formatting of dependency tree."""
        result = self.formatter.format(self.sample_tree, "markdown")

        assert isinstance(result, str)
        assert "# Dependency Tree" in result
        assert "## Root Packages" in result

    def test_format_tree_html(self):
        """Test HTML formatting of dependency tree."""
        tree_data = DependencyTree(
            root_packages=["app"],
            tree_structure={"app": ["lib1"], "lib1": []},
            depth_analysis={"app": 0, "lib1": 1},
            circular_dependencies=[],
            total_dependencies=1,
            max_depth=1,
        )

        result = self.formatter.format(tree_data, "html")

        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result
        assert "SBOM Analysis Results" in result

    def test_format_package_info_text(self):
        """Test text formatting of package info."""
        result = self.formatter.format(self.sample_package_info, "text")

        assert isinstance(result, str)
        assert "Package: requests" in result
        assert "Version: 2.31.0" in result

    def test_format_package_info_json(self):
        """Test JSON formatting of package info."""
        package_info = PackageInfo(
            name="test-package",
            version="1.0.0",
            description="Test package",
            license="MIT",
            dependencies=["dep1", "dep2"],
            vulnerabilities=["CVE-2023-1234"],
            supplier="Test Supplier",
            homepage="https://example.com",
        )

        result = self.formatter.format(package_info, "json")
        data = json.loads(result)

        assert data["name"] == "test-package"
        assert data["version"] == "1.0.0"
        assert "dep1" in data["dependencies"]

    def test_format_package_info_markdown(self):
        """Test markdown formatting of package info."""
        package_info = PackageInfo(
            name="markdown-test",
            version="2.0.0",
            description="Markdown test package",
            license="Apache-2.0",
            dependencies=[],
            vulnerabilities=[],
        )

        result = self.formatter.format(package_info, "markdown")

        assert isinstance(result, str)
        assert "# Package: markdown-test" in result

    def test_format_package_info_html(self):
        """Test HTML formatting of package info."""
        package_info = PackageInfo(
            name="html-test",
            version="3.0.0",
            description="HTML test package",
            license="GPL-3.0",
            dependencies=["dep1"],
            vulnerabilities=[],
        )

        result = self.formatter.format(package_info, "html")

        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result
        assert "SBOM Analysis Results" in result

    def test_format_unsupported_type(self):
        """Test formatting with unsupported output type."""
        with pytest.raises(ValueError, match="Unsupported output type"):
            self.formatter.format(self.sample_analysis, "unsupported")

    def test_format_none_input(self):
        """Test formatting with None input."""
        # The formatter should handle None gracefully
        result = self.formatter.format(None, "text")
        assert isinstance(result, str)

    def test_format_unknown_object(self):
        """Test formatting with unknown object type."""
        unknown_obj = Mock()
        # The formatter should handle unknown objects gracefully
        result = self.formatter.format(unknown_obj, "text")
        assert isinstance(result, str)

    def test_format_analysis_with_empty_data(self):
        """Test formatting analysis with empty data."""
        empty_analysis = AnalysisResult(
            total_packages=0,
            unique_licenses=[],
            license_distribution={},
            dependency_depth={},
            vulnerability_summary={},
            completeness_score=0.0,
            recommendations=[],
        )

        result = self.formatter.format(empty_analysis, "text")

        assert isinstance(result, str)
        assert "Total Packages: 0" in result
        assert "Total Packages: 0" in result

    def test_format_tree_with_empty_dependencies(self):
        """Test formatting tree with empty dependencies."""
        empty_tree = DependencyTree(
            root_packages=[],
            tree_structure={},
            depth_analysis={},
            circular_dependencies=[],
            total_dependencies=0,
            max_depth=0,
        )

        result = self.formatter.format(empty_tree, "text")

        assert isinstance(result, str)
        assert "Total dependencies: 0" in result

    def test_format_package_info_with_missing_data(self):
        """Test formatting package info with missing data."""
        incomplete_package = PackageInfo(
            name="incomplete-package",
            version=None,
            description=None,
            license=None,
            dependencies=[],
            vulnerabilities=[],
            purl=None,
            supplier=None,
            homepage=None,
        )

        result = self.formatter.format(incomplete_package, "text")

        assert isinstance(result, str)
        assert "Package: incomplete-package" in result
        assert "incomplete-package" in result

    def test_html_styling(self):
        """Test that HTML output includes proper styling."""
        result = self.formatter.format(self.sample_analysis, "html")

        # Check for CSS styling
        assert "background" in result
        assert "color" in result
        assert "font-family" in result
        assert "border-radius" in result
        assert "box-shadow" in result

    def test_markdown_structure(self):
        """Test that markdown output has proper structure."""
        result = self.formatter.format(self.sample_analysis, "markdown")

        # Check for proper markdown headers
        assert "# " in result
        assert "## " in result
        assert "## " in result
        assert "**" in result  # Bold text
        assert "- " in result  # List items

    def test_json_structure(self):
        """Test that JSON output has correct structure."""
        analysis_result = AnalysisResult(
            total_packages=1,
            unique_licenses=["MIT"],
            dependency_depth={"package1": 0},
            vulnerability_summary={"high": 0, "medium": 0, "low": 0},
            completeness_score=85.0,
            recommendations=[],
        )

        result = self.formatter.format(analysis_result, "json")
        data = json.loads(result)

        assert "total_packages" in data
        assert "unique_licenses" in data
        assert "dependency_depth" in data
        assert "vulnerability_summary" in data
        assert "completeness_score" in data
        assert "recommendations" in data

        assert data["total_packages"] == 1
        assert len(data["unique_licenses"]) == 1
        assert "MIT" in data["unique_licenses"]

    def test_text_formatting_with_emojis(self):
        """Test that text output includes emojis for better UX."""
        result = self.formatter.format(self.sample_analysis, "text")

        # Check for emojis
        assert "📊" in result  # Chart emoji
        assert "📦" in result  # Package emoji
        assert "📋" in result  # Clipboard emoji
        assert "💡" in result  # Lightbulb emoji
