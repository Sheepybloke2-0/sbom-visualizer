"""
Tests for SBOM Analyzer.

Tests the analysis functionality for SBOM data.
"""

from datetime import datetime
from unittest.mock import Mock

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
        # Create test SBOM data
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Test SBOM",
            document_namespace="https://example.com/test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="test-package",
                    version="1.0.0",
                    description="Test package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 1
        assert "MIT" in result.unique_licenses
        assert result.completeness_score > 0

    def test_analyze_empty_sbom(self):
        """Test analysis of empty SBOM."""
        sbom_data = SBOMData(
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

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 0
        assert len(result.unique_licenses) == 0
        assert result.completeness_score == 0.0

    def test_analyze_license_distribution(self):
        """Test license distribution analysis."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="License Distribution Test",
            document_namespace="https://example.com/license-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="package1",
                    version="1.0.0",
                    description="Package 1",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
                Package(
                    id="pkg2",
                    name="package2",
                    version="2.0.0",
                    description="Package 2",
                    licenses=[License(identifier="Apache-2.0")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
                Package(
                    id="pkg3",
                    name="package3",
                    version="3.0.0",
                    description="Package 3",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 3
        assert len(result.unique_licenses) == 2
        assert "MIT" in result.unique_licenses
        assert "Apache-2.0" in result.unique_licenses
        assert result.license_distribution["MIT"] == 2
        assert result.license_distribution["Apache-2.0"] == 1

    def test_analyze_dependency_depth(self):
        """Test dependency depth analysis."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Dependency Depth Test",
            document_namespace="https://example.com/depth-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="root-package",
                    version="1.0.0",
                    description="Root package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg2",
                            package_name="dep1",
                            relationship_type="DEPENDS_ON",
                        ),
                    ],
                ),
                Package(
                    id="pkg2",
                    name="dep1",
                    version="1.0.0",
                    description="Dependency 1",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg3",
                            package_name="dep2",
                            relationship_type="DEPENDS_ON",
                        ),
                    ],
                ),
                Package(
                    id="pkg3",
                    name="dep2",
                    version="1.0.0",
                    description="Dependency 2",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 3
        assert len(result.dependency_depth) > 0

    def test_analyze_vulnerability_summary(self):
        """Test vulnerability summary analysis."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Vulnerability Test",
            document_namespace="https://example.com/vuln-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="vulnerable-package",
                    version="1.0.0",
                    description="Vulnerable package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[
                        Vulnerability(
                            cve_id="CVE-2023-1234",
                            severity="HIGH",
                            description="Test vulnerability",
                        )
                    ],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 1
        assert "high" in result.vulnerability_summary
        assert result.vulnerability_summary["high"] == 1

    def test_analyze_completeness_score(self):
        """Test completeness score calculation."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Completeness Test",
            document_namespace="https://example.com/completeness-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="complete-package",
                    version="1.0.0",
                    description="Complete package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                    purl="pkg:pypi/complete-package@1.0.0",
                    supplier="Test Supplier",
                    homepage="https://example.com",
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 1
        assert 0 <= result.completeness_score <= 100

    def test_analyze_recommendations(self):
        """Test recommendation generation."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Recommendations Test",
            document_namespace="https://example.com/recommendations-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="test-package",
                    version="1.0.0",
                    description="Test package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 1
        assert isinstance(result.recommendations, list)

    def test_analyze_with_missing_licenses(self):
        """Test analysis with packages missing licenses."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Missing Licenses Test",
            document_namespace="https://example.com/missing-licenses-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="no-license-package",
                    version="1.0.0",
                    description="Package without license",
                    licenses=[],
                    vulnerabilities=[],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 1
        assert len(result.unique_licenses) == 0

    def test_analyze_with_complex_dependencies(self):
        """Test analysis with complex dependency relationships."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Complex Dependencies Test",
            document_namespace="https://example.com/complex-deps-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="root-package",
                    version="1.0.0",
                    description="Root package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg2",
                            package_name="dep1",
                            relationship_type="DEPENDS_ON",
                        ),
                    ],
                ),
                Package(
                    id="pkg2",
                    name="dep1",
                    version="1.0.0",
                    description="Dependency 1",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg3",
                            package_name="dep2",
                            relationship_type="DEPENDS_ON",
                        ),
                    ],
                ),
                Package(
                    id="pkg3",
                    name="dep2",
                    version="1.0.0",
                    description="Dependency 2",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 3
        assert len(result.dependency_depth) > 0

    def test_analyze_with_multiple_vulnerabilities(self):
        """Test analysis with multiple vulnerabilities."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Multiple Vulnerabilities Test",
            document_namespace="https://example.com/multiple-vulns-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="vulnerable-package",
                    version="1.0.0",
                    description="Vulnerable package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[
                        Vulnerability(
                            cve_id="CVE-2023-1234",
                            severity="HIGH",
                            description="High severity vulnerability",
                        ),
                        Vulnerability(
                            cve_id="CVE-2023-5678",
                            severity="MEDIUM",
                            description="Medium severity vulnerability",
                        ),
                    ],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 1
        assert result.vulnerability_summary["high"] == 1
        assert result.vulnerability_summary["medium"] == 1

    def test_analyze_with_duplicate_licenses(self):
        """Test analysis with duplicate licenses."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Duplicate Licenses Test",
            document_namespace="https://example.com/duplicate-licenses-test",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="package1",
                    version="1.0.0",
                    description="Package 1",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
                Package(
                    id="pkg2",
                    name="package2",
                    version="2.0.0",
                    description="Package 2",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                ),
            ],
            relationships=[],
            metadata={},
        )

        result = self.analyzer.analyze(sbom_data)

        assert result.total_packages == 2
        assert len(result.unique_licenses) == 1
        assert "MIT" in result.unique_licenses
        assert result.license_distribution["MIT"] == 2
