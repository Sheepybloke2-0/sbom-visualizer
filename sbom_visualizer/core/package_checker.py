"""
Package Checker for detailed package information and fuzzy matching.
"""

import logging
from difflib import get_close_matches
from typing import List, Optional

from ..models.sbom_models import Package, PackageInfo, SBOMData

logger = logging.getLogger(__name__)


class PackageChecker:
    """Provides detailed information about packages with fuzzy matching."""

    def get_package_info(
        self, sbom_data: SBOMData, package_name: str
    ) -> Optional[PackageInfo]:
        """
        Get detailed information about a package with fuzzy matching.

        Args:
            sbom_data: Parsed SBOM data
            package_name: Name of the package to find

        Returns:
            Package information if found, None otherwise
        """
        logger.info(f"Looking for package: {package_name}")

        # Try exact match first
        package = self._find_exact_match(sbom_data, package_name)

        if not package:
            # Try fuzzy matching
            package = self._find_fuzzy_match(sbom_data, package_name)

        if package:
            return self._create_package_info(package, sbom_data)

        return None

    def _find_exact_match(
        self, sbom_data: SBOMData, package_name: str
    ) -> Optional[Package]:
        """Find package by exact name match."""
        for package in sbom_data.packages:
            if package.name.lower() == package_name.lower():
                return package
        return None

    def _find_fuzzy_match(
        self, sbom_data: SBOMData, package_name: str
    ) -> Optional[Package]:
        """Find package using fuzzy matching."""
        package_names = [p.name for p in sbom_data.packages]

        # Get close matches
        matches = get_close_matches(
            package_name.lower(),
            [name.lower() for name in package_names],
            n=1,
            cutoff=0.6,
        )

        if matches:
            matched_name = matches[0]
            # Find the original package with the matched name
            for package in sbom_data.packages:
                if package.name.lower() == matched_name:
                    logger.info(
                        f"Found fuzzy match: {package.name} for '{package_name}'"
                    )
                    return package

        return None

    def _create_package_info(
        self, package: Package, sbom_data: SBOMData
    ) -> PackageInfo:
        """Create PackageInfo from Package model."""
        # Get primary license
        primary_license = None
        if package.licenses:
            primary_license = package.licenses[0].identifier

        # Get direct dependencies
        dependencies = []
        for dep in package.dependencies:
            dependencies.append(dep.package_name)

        # Get vulnerabilities
        vulnerabilities = []
        for vuln in package.vulnerabilities:
            vuln_info = f"{vuln.cve_id or 'Unknown'}"
            if vuln.severity:
                vuln_info += f" ({vuln.severity})"
            vulnerabilities.append(vuln_info)

        return PackageInfo(
            name=package.name,
            version=package.version,
            license=primary_license,
            description=package.description,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            supplier=package.supplier,
            homepage=package.homepage,
        )

    def list_all_packages(self, sbom_data: SBOMData) -> List[str]:
        """List all package names in the SBOM."""
        return [package.name for package in sbom_data.packages]

    def search_packages(
        self, sbom_data: SBOMData, search_term: str
    ) -> List[PackageInfo]:
        """
        Search for packages containing the search term.

        Args:
            sbom_data: Parsed SBOM data
            search_term: Term to search for

        Returns:
            List of matching packages
        """
        matching_packages = []
        search_term_lower = search_term.lower()

        for package in sbom_data.packages:
            if search_term_lower in package.name.lower() or (
                package.description and search_term_lower in package.description.lower()
            ):
                package_info = self._create_package_info(package, sbom_data)
                matching_packages.append(package_info)

        return matching_packages

    def get_package_statistics(self, sbom_data: SBOMData) -> dict:
        """
        Get statistics about packages in the SBOM.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Dictionary with package statistics
        """
        total_packages = len(sbom_data.packages)
        packages_with_version = sum(1 for p in sbom_data.packages if p.version)
        packages_with_description = sum(1 for p in sbom_data.packages if p.description)
        packages_with_licenses = sum(1 for p in sbom_data.packages if p.licenses)
        packages_with_dependencies = sum(
            1 for p in sbom_data.packages if p.dependencies
        )
        packages_with_vulnerabilities = sum(
            1 for p in sbom_data.packages if p.vulnerabilities
        )

        return {
            "total_packages": total_packages,
            "packages_with_version": packages_with_version,
            "packages_with_description": packages_with_description,
            "packages_with_licenses": packages_with_licenses,
            "packages_with_dependencies": packages_with_dependencies,
            "packages_with_vulnerabilities": packages_with_vulnerabilities,
            "completeness_percentage": {
                "version": (
                    (packages_with_version / total_packages * 100)
                    if total_packages > 0
                    else 0
                ),
                "description": (
                    (packages_with_description / total_packages * 100)
                    if total_packages > 0
                    else 0
                ),
                "licenses": (
                    (packages_with_licenses / total_packages * 100)
                    if total_packages > 0
                    else 0
                ),
                "dependencies": (
                    (packages_with_dependencies / total_packages * 100)
                    if total_packages > 0
                    else 0
                ),
            },
        }
