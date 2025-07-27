"""
Tests for output formatter functionality.
"""

import json
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from sbom_visualizer.models.sbom_models import (
    AnalysisResult,
    DependencyTree,
    License,
    Package,
    PackageInfo,
    SBOMData,
    SBOMFormat,
)
from sbom_visualizer.utils.output_formatter import OutputFormatter


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
        """Test formatting analysis result as JSON."""
        result = self.formatter.format(self.sample_analysis, "json")

        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed["total_packages"] == 3
        assert len(parsed["unique_licenses"]) == 2
        assert parsed["completeness_score"] == 85.5

    def test_format_analysis_markdown(self):
        """Test formatting analysis result as markdown."""
        result = self.formatter.format(self.sample_analysis, "markdown")

        assert isinstance(result, str)
        assert "# SBOM Analysis Report" in result
        assert "## Summary" in result
        assert "## License Distribution" in result
        assert "## Recommendations" in result

    def test_format_analysis_html(self):
        """Test formatting analysis result as HTML."""
        result = self.formatter.format(self.sample_analysis, "html")

        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result
        assert "html" in result
        assert "<head>" in result
        assert "<body>" in result
        assert "SBOM Analysis Report" in result

    def test_format_tree_text(self):
        """Test formatting dependency tree as text."""
        result = self.formatter.format(self.sample_tree, "text")

        assert isinstance(result, str)
        assert "Dependency Tree" in result
        assert "Root Packages:" in result
        assert "requests" in result
        assert "flask" in result

    def test_format_tree_json(self):
        """Test formatting dependency tree as JSON."""
        result = self.formatter.format(self.sample_tree, "json")

        parsed = json.loads(result)
        assert parsed["root_packages"] == ["requests", "flask"]
        assert parsed["max_depth"] == 2
        assert parsed["total_dependencies"] == 5

    def test_format_tree_markdown(self):
        """Test formatting dependency tree as markdown."""
        result = self.formatter.format(self.sample_tree, "markdown")

        assert isinstance(result, str)
        assert "# Dependency Tree" in result
        assert "## Root Packages" in result
        assert "## Statistics" in result

    def test_format_tree_html(self):
        """Test formatting dependency tree as HTML."""
        result = self.formatter.format(self.sample_tree, "html")

        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result
        assert "Dependency Tree" in result
        assert "Root Packages" in result

    def test_format_package_info_text(self):
        """Test formatting package info as text."""
        result = self.formatter.format(self.sample_package_info, "text")

        assert isinstance(result, str)
        assert "Package: requests" in result
        assert "Version: 2.31.0" in result
        assert "License: Apache-2.0" in result

    def test_format_package_info_json(self):
        """Test formatting package info as JSON."""
        result = self.formatter.format(self.sample_package_info, "json")

        parsed = json.loads(result)
        assert parsed["name"] == "requests"
        assert parsed["version"] == "2.31.0"
        assert parsed["license"] == "Apache-2.0"

    def test_format_package_info_markdown(self):
        """Test formatting package info as markdown."""
        result = self.formatter.format(self.sample_package_info, "markdown")

        assert isinstance(result, str)
        assert "# Package:" in result
        assert "Package: requests" in result
        assert "**Version:** 2.31.0" in result

    def test_format_package_info_html(self):
        """Test formatting package info as HTML."""
        result = self.formatter.format(self.sample_package_info, "html")

        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result
        assert "Package:" in result
        assert "requests" in result

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
        unknown_obj = MagicMock()
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
        """Test that JSON output has proper structure."""
        result = self.formatter.format(self.sample_analysis, "json")

        parsed = json.loads(result)

        # Check for required fields
        assert "total_packages" in parsed
        assert "unique_licenses" in parsed
        assert "completeness_score" in parsed
        assert "license_distribution" in parsed
        assert "recommendations" in parsed

    def test_text_formatting_with_emojis(self):
        """Test that text output includes emojis for better UX."""
        result = self.formatter.format(self.sample_analysis, "text")

        # Check for emojis
        assert "📊" in result  # Chart emoji
        assert "📦" in result  # Package emoji
        assert "📋" in result  # Clipboard emoji
        assert "💡" in result  # Lightbulb emoji
