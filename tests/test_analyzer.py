"""
Tests for SBOM analyzer functionality.
"""

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from sbom_visualizer.core.analyzer import SBOMAnalyzer
from sbom_visualizer.models.sbom_models import (
    Dependency,
    License,
    Package,
    SBOMData,
    SBOMFormat,
    Vulnerability,
)


class TestSBOMAnalyzer:
    """Test cases for SBOMAnalyzer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = SBOMAnalyzer()

        # Create sample SBOM data
        self.sample_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="SPDX-2.3",
            document_name="Test SBOM",
            document_namespace="https://example.com/test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="requests",
                    version="2.31.0",
                    description="HTTP library",
                    licenses=[
                        License(identifier="Apache-2.0", name="Apache License 2.0")
                    ],
                    dependencies=[],
                    vulnerabilities=[],
                    purl="pkg:pypi/requests@2.31.0",
                ),
                Package(
                    id="pkg2",
                    name="flask",
                    version="3.0.0",
                    description="Web framework",
                    licenses=[License(identifier="BSD-3-Clause", name="BSD 3-Clause")],
                    dependencies=[
                        Dependency(
                            package_id="pkg1",
                            package_name="requests",
                            relationship_type="DEPENDS_ON",
                        )
                    ],
                    vulnerabilities=[],
                    purl="pkg:pypi/flask@3.0.0",
                ),
                Package(
                    id="pkg3",
                    name="sqlalchemy",
                    version="2.0.23",
                    description="Database library",
                    licenses=[License(identifier="MIT", name="MIT License")],
                    dependencies=[],
                    vulnerabilities=[
                        Vulnerability(
                            cve_id="CVE-2023-1234",
                            severity="HIGH",
                            description="Test vulnerability",
                        )
                    ],
                    purl="pkg:pypi/sqlalchemy@2.0.23",
                ),
            ],
            relationships=[],
            metadata={},
        )

    def test_analyze_basic(self):
        """Test basic SBOM analysis."""
        result = self.analyzer.analyze(self.sample_sbom)

        assert result.total_packages == 3
        assert len(result.unique_licenses) == 3
        assert result.completeness_score > 0
        assert len(result.recommendations) > 0
        assert result.vulnerability_summary.get("HIGH", 0) == 1

    def test_analyze_empty_sbom(self):
        """Test analysis of empty SBOM."""
        empty_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="SPDX-2.3",
            document_name="Empty SBOM",
            document_namespace="https://example.com/empty",
            created=datetime.now(),
            creator="Test Creator",
            packages=[],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(empty_sbom)

        assert result.total_packages == 0
        assert len(result.unique_licenses) == 0
        assert result.completeness_score == 0
        assert "SBOM completeness is low" in result.recommendations[0]

    def test_analyze_license_distribution(self):
        """Test license distribution analysis."""
        result = self.analyzer.analyze(self.sample_sbom)

        # Check that license distribution is calculated
        assert hasattr(result, "license_distribution")
        assert len(result.license_distribution) == 3

    def test_analyze_dependency_depth(self):
        """Test dependency depth analysis."""
        result = self.analyzer.analyze(self.sample_sbom)

        assert hasattr(result, "dependency_depth")
        assert isinstance(result.dependency_depth, dict)

    def test_analyze_vulnerability_summary(self):
        """Test vulnerability summary analysis."""
        result = self.analyzer.analyze(self.sample_sbom)

        assert sum(result.vulnerability_summary.values()) == 1
        assert result.high_severity_count == 1
        assert result.medium_severity_count == 0
        assert result.low_severity_count == 0

    def test_analyze_completeness_score(self):
        """Test completeness score calculation."""
        result = self.analyzer.analyze(self.sample_sbom)

        assert 0 <= result.completeness_score <= 100
        assert isinstance(result.completeness_score, float)

    def test_analyze_recommendations(self):
        """Test recommendation generation."""
        result = self.analyzer.analyze(self.sample_sbom)

        assert len(result.recommendations) > 0
        assert all(isinstance(rec, str) for rec in result.recommendations)

    def test_analyze_with_missing_licenses(self):
        """Test analysis with packages missing license information."""
        sbom_without_licenses = SBOMData(
            format=SBOMFormat.SPDX,
            version="SPDX-2.3",
            document_name="No Licenses SBOM",
            document_namespace="https://example.com/nolicenses",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="requests",
                    version="2.31.0",
                    description="HTTP library",
                    licenses=[],
                    dependencies=[],
                    vulnerabilities=[],
                    purl="pkg:pypi/requests@2.31.0",
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_without_licenses)

        assert result.total_packages == 1
        assert len(result.unique_licenses) == 0
        # The analyzer doesn't currently check for missing licenses specifically
        assert len(result.recommendations) > 0

    def test_analyze_with_complex_dependencies(self):
        """Test analysis with complex dependency relationships."""
        # Create SBOM with nested dependencies
        pkg1 = Package(
            id="pkg1",
            name="base-package",
            version="1.0.0",
            description="Base package",
            licenses=[License(identifier="MIT", name="MIT License")],
            dependencies=[],
            vulnerabilities=[],
            purl="pkg:pypi/base-package@1.0.0",
        )

        pkg2 = Package(
            id="pkg2",
            name="depends-on-base",
            version="2.0.0",
            description="Depends on base",
            licenses=[License(identifier="MIT", name="MIT License")],
            dependencies=[
                Dependency(
                    package_id="pkg1",
                    package_name="base-package",
                    relationship_type="DEPENDS_ON",
                )
            ],
            vulnerabilities=[],
            purl="pkg:pypi/depends-on-base@2.0.0",
        )

        pkg3 = Package(
            id="pkg3",
            name="depends-on-depends",
            version="3.0.0",
            description="Depends on depends",
            licenses=[License(identifier="MIT", name="MIT License")],
            dependencies=[
                Dependency(
                    package_id="pkg2",
                    package_name="depends-on-base",
                    relationship_type="DEPENDS_ON",
                )
            ],
            vulnerabilities=[],
            purl="pkg:pypi/depends-on-depends@3.0.0",
        )

        complex_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="SPDX-2.3",
            document_name="Complex Dependencies SBOM",
            document_namespace="https://example.com/complex",
            created=datetime.now(),
            creator="Test Creator",
            packages=[pkg1, pkg2, pkg3],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(complex_sbom)

        assert result.total_packages == 3
        # Check that dependency depth analysis is performed
        assert isinstance(result.dependency_depth, dict)

    def test_analyze_with_multiple_vulnerabilities(self):
        """Test analysis with multiple vulnerabilities."""
        vulnerable_package = Package(
            id="vuln-pkg",
            name="vulnerable-package",
            version="1.0.0",
            description="Vulnerable package",
            licenses=[License(identifier="MIT", name="MIT License")],
            dependencies=[],
            vulnerabilities=[
                Vulnerability(
                    cve_id="CVE-2023-1234", severity="HIGH", description="High vuln"
                ),
                Vulnerability(
                    cve_id="CVE-2023-5678", severity="MEDIUM", description="Medium vuln"
                ),
                Vulnerability(
                    cve_id="CVE-2023-9012", severity="LOW", description="Low vuln"
                ),
            ],
            purl="pkg:pypi/vulnerable-package@1.0.0",
        )

        vuln_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="SPDX-2.3",
            document_name="Vulnerable SBOM",
            document_namespace="https://example.com/vuln",
            created=datetime.now(),
            creator="Test Creator",
            packages=[vulnerable_package],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(vuln_sbom)

        assert result.vulnerability_summary.get("HIGH", 0) == 1
        assert result.vulnerability_summary.get("MEDIUM", 0) == 1
        assert result.vulnerability_summary.get("LOW", 0) == 1

    def test_analyze_with_duplicate_licenses(self):
        """Test analysis with duplicate licenses."""
        duplicate_license = License(identifier="MIT", name="MIT License")

        pkg1 = Package(
            id="pkg1",
            name="package1",
            version="1.0.0",
            description="Package 1",
            licenses=[duplicate_license],
            dependencies=[],
            vulnerabilities=[],
            purl="pkg:pypi/package1@1.0.0",
        )

        pkg2 = Package(
            id="pkg2",
            name="package2",
            version="2.0.0",
            description="Package 2",
            licenses=[duplicate_license],
            dependencies=[],
            vulnerabilities=[],
            purl="pkg:pypi/package2@2.0.0",
        )

        duplicate_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="SPDX-2.3",
            document_name="Duplicate Licenses SBOM",
            document_namespace="https://example.com/duplicate",
            created=datetime.now(),
            creator="Test Creator",
            packages=[pkg1, pkg2],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(duplicate_sbom)

        assert result.total_packages == 2
        assert len(result.unique_licenses) == 1  # Should count unique licenses only
