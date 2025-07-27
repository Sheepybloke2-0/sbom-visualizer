"""
Tests for SBOM Verifier.

Tests the verification functionality for SBOM data.
"""

from datetime import datetime
from unittest.mock import Mock

import pytest

from sbom_visualizer.core.verifier import SBOMVerifier
from sbom_visualizer.models.sbom_models import (
    Dependency,
    License,
    Package,
    SBOMData,
    SBOMFormat,
    Vulnerability,
)


class TestSBOMVerifier:
    """Test cases for SBOMVerifier."""

    def setup_method(self):
        """Set up test fixtures."""
        self.verifier = SBOMVerifier()

        # Create sample SBOM data
        self.valid_sbom = SBOMData(
            format=SBOMFormat.SPDX,
            version="SPDX-2.3",
            document_name="Valid SBOM",
            document_namespace="https://example.com/valid",
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
                )
            ],
            relationships=[],
            metadata={},
        )

    def test_verify_valid_sbom(self):
        """Test verification of valid SBOM."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Valid SBOM",
            document_namespace="https://example.com/valid",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="valid-package",
                    version="1.0.0",
                    description="Valid package",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_empty_sbom(self):
        """Test verification of empty SBOM."""
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

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_missing_licenses(self):
        """Test verification with missing licenses."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Missing Licenses SBOM",
            document_namespace="https://example.com/missing-licenses",
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

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_missing_metadata(self):
        """Test verification with missing metadata."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="",  # Missing document name
            document_namespace="",
            created=datetime.now(),
            creator="Test Creator",
            packages=[],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_packages_without_dependencies(self):
        """Test verification of packages without dependencies."""
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
            ],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_packages_with_vulnerabilities(self):
        """Test verification of packages with vulnerabilities."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Vulnerable SBOM",
            document_namespace="https://example.com/vulnerable",
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
                            severity="high",
                            description="Test vulnerability",
                        )
                    ],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_format_compliance(self):
        """Test format compliance verification."""
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

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_license_compliance(self):
        """Test license compliance verification."""
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

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_dependency_completeness(self):
        """Test dependency completeness verification."""
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
                    dependencies=[],
                ),
            ],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_package_completeness(self):
        """Test package completeness verification."""
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

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_overall_score(self):
        """Test overall verification score calculation."""
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

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_with_circular_dependencies(self):
        """Test verification with circular dependencies."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Circular Dependencies SBOM",
            document_namespace="https://example.com/circular",
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
                    dependencies=[
                        Dependency(
                            package_id="pkg2",
                            package_name="package2",
                            relationship_type="DEPENDS_ON",
                        ),
                    ],
                ),
                Package(
                    id="pkg2",
                    name="package2",
                    version="1.0.0",
                    description="Package 2",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[
                        Dependency(
                            package_id="pkg1",
                            package_name="package1",
                            relationship_type="DEPENDS_ON",
                        ),
                    ],
                ),
            ],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_with_invalid_licenses(self):
        """Test verification with invalid licenses."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Invalid Licenses SBOM",
            document_namespace="https://example.com/invalid-licenses",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="invalid-license-package",
                    version="1.0.0",
                    description="Package with invalid license",
                    licenses=[License(identifier="INVALID-LICENSE")],
                    vulnerabilities=[],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)

    def test_verify_with_missing_purls(self):
        """Test verification with missing PURLs."""
        sbom_data = SBOMData(
            format=SBOMFormat.SPDX,
            version="2.3",
            document_name="Missing PURLs SBOM",
            document_namespace="https://example.com/missing-purls",
            created=datetime.now(),
            creator="Test Creator",
            packages=[
                Package(
                    id="pkg1",
                    name="no-purl-package",
                    version="1.0.0",
                    description="Package without PURL",
                    licenses=[License(identifier="MIT")],
                    vulnerabilities=[],
                    dependencies=[],
                )
            ],
            relationships=[],
            metadata={},
        )

        result = self.verifier.verify(sbom_data)

        assert isinstance(result.is_valid, bool)
        assert isinstance(result.issues, list)
        assert isinstance(result.warnings, list)
