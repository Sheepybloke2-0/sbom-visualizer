"""
SBOM Verifier for format validation and completeness checking.
"""

import logging
from typing import List

from ..models.sbom_models import SBOMData, VerificationResult, SBOMFormat


logger = logging.getLogger(__name__)


class SBOMVerifier:
    """Verifies SBOM format compliance and completeness."""

    def verify(self, sbom_data: SBOMData) -> VerificationResult:
        """
        Verify an SBOM for format compliance and completeness.

        Args:
            sbom_data: Parsed SBOM data to verify

        Returns:
            Verification result with issues and warnings
        """
        logger.info(f"Verifying SBOM: {sbom_data.document_name}")

        issues = []
        warnings = []

        # Basic format validation
        format_issues = self._verify_format(sbom_data)
        issues.extend(format_issues)

        # License validation
        license_issues = self._verify_licenses(sbom_data)
        issues.extend(license_issues)

        # Dependency completeness
        dependency_issues = self._verify_dependencies(sbom_data)
        issues.extend(dependency_issues)

        # Package completeness
        package_issues = self._verify_packages(sbom_data)
        issues.extend(package_issues)

        # Metadata validation
        metadata_issues = self._verify_metadata(sbom_data)
        issues.extend(metadata_issues)

        is_valid = len(issues) == 0

        return VerificationResult(
            is_valid=is_valid,
            issues=issues,
            warnings=warnings,
            format_detected=sbom_data.format,
            version_detected=sbom_data.version,
        )

    def _verify_format(self, sbom_data: SBOMData) -> List[str]:
        """Verify basic format requirements."""
        issues = []

        # Check required fields
        if not sbom_data.document_name:
            issues.append("Missing document name")

        if not sbom_data.creator:
            issues.append("Missing creator information")

        if not sbom_data.created:
            issues.append("Missing creation timestamp")

        # Format-specific checks
        if sbom_data.format == SBOMFormat.SPDX:
            if not sbom_data.version.startswith("SPDX-"):
                issues.append("Invalid SPDX version format")

        elif sbom_data.format == SBOMFormat.CYCLONEDX:
            if not sbom_data.version.startswith("1."):
                issues.append("Invalid CycloneDX version format")

        return issues

    def _verify_licenses(self, sbom_data: SBOMData) -> List[str]:
        """Verify license information."""
        issues = []

        packages_without_licenses = []
        invalid_licenses = []

        for package in sbom_data.packages:
            if not package.licenses:
                packages_without_licenses.append(package.name)
            else:
                for license_info in package.licenses:
                    if not license_info.identifier:
                        invalid_licenses.append(
                            f"{package.name}: missing license identifier"
                        )

        if packages_without_licenses:
            issues.append(
                f"Packages without license information: {', '.join(packages_without_licenses)}"
            )

        if invalid_licenses:
            issues.extend(invalid_licenses)

        return issues

    def _verify_dependencies(self, sbom_data: SBOMData) -> List[str]:
        """Verify dependency information."""
        issues = []

        # Check for circular dependencies
        circular_deps = self._find_circular_dependencies(sbom_data)
        if circular_deps:
            issues.append(f"Circular dependencies detected: {circular_deps}")

        # Check for missing dependency information
        packages_without_deps = []
        for package in sbom_data.packages:
            if not package.dependencies and len(sbom_data.packages) > 1:
                # Only flag if there are other packages but no dependencies listed
                packages_without_deps.append(package.name)

        if packages_without_deps:
            issues.append(
                f"Packages without dependency information: {', '.join(packages_without_deps)}"
            )

        return issues

    def _verify_packages(self, sbom_data: SBOMData) -> List[str]:
        """Verify package information completeness."""
        issues = []

        packages_without_version = []
        packages_without_description = []

        for package in sbom_data.packages:
            if not package.version:
                packages_without_version.append(package.name)

            if not package.description:
                packages_without_description.append(package.name)

        if packages_without_version:
            issues.append(
                f"Packages without version information: {', '.join(packages_without_version)}"
            )

        if packages_without_description:
            issues.append(
                f"Packages without description: {', '.join(packages_without_description)}"
            )

        return issues

    def _verify_metadata(self, sbom_data: SBOMData) -> List[str]:
        """Verify metadata completeness."""
        issues = []

        if not sbom_data.metadata:
            issues.append("Missing metadata information")

        return issues

    def _find_circular_dependencies(self, sbom_data: SBOMData) -> List[str]:
        """Find circular dependencies in the SBOM."""
        # This is a simplified implementation
        # In a real implementation, you would build a dependency graph and detect cycles
        return []
