"""
SBOM Analyzer for SBOM Visualizer.

Provides functionality to analyze SBOM data and generate insights.
"""

import logging
from collections import Counter
from typing import Dict, List, Tuple

from ..models.sbom_models import AnalysisResult, Package, SBOMData

logger = logging.getLogger(__name__)


class SBOMAnalyzer:
    """Analyzes SBOM data for insights and recommendations."""

    def analyze(self, sbom_data: SBOMData) -> AnalysisResult:
        """
        Analyze SBOM data for comprehensive insights.

        Args:
            sbom_data: Parsed SBOM data to analyze

        Returns:
            Analysis result with statistics and recommendations
        """
        logger.info(f"Analyzing SBOM: {sbom_data.document_name}")

        # Basic statistics
        total_packages = len(sbom_data.packages)

        # License analysis
        unique_licenses, license_distribution = self._analyze_licenses(sbom_data)

        # Calculate dependency depth analysis
        dependency_depth = {}
        for package in sbom_data.packages:
            depth = self._calculate_dependency_depth(package, sbom_data.packages)
            dependency_depth[package.name] = depth

        # Calculate vulnerability summary
        vulnerability_summary = self._calculate_vulnerability_summary(
            sbom_data.packages
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            total_packages, unique_licenses, dependency_depth, vulnerability_summary
        )

        return AnalysisResult(
            total_packages=total_packages,
            unique_licenses=unique_licenses,
            license_distribution=license_distribution,
            dependency_depth=dependency_depth,
            vulnerability_summary=vulnerability_summary,
            completeness_score=self._calculate_completeness(sbom_data),
            recommendations=recommendations,
        )

    def _analyze_licenses(
        self, sbom_data: SBOMData
    ) -> tuple[List[str], Dict[str, int]]:
        """Analyze license usage and distribution."""
        license_counter = Counter()
        unique_licenses = set()

        for package in sbom_data.packages:
            for license_info in package.licenses:
                if license_info.identifier:
                    license_counter[license_info.identifier] += 1
                    unique_licenses.add(license_info.identifier)

        return list(unique_licenses), dict(license_counter)

    def _calculate_dependency_depth(
        self, package: Package, all_packages: list[Package]
    ) -> int:
        """Calculate the maximum depth of dependencies for a package."""
        if not package.dependencies:
            return 0

        max_depth = 0
        for dep in package.dependencies:
            # Find the dependent package
            dep_package = next(
                (p for p in all_packages if p.name == dep.package_name), None
            )
            if dep_package:
                depth = self._calculate_dependency_depth(dep_package, all_packages)
                max_depth = max(max_depth, depth + 1)

        return max_depth

    def _calculate_vulnerability_summary(
        self, packages: list[Package]
    ) -> dict[str, int]:
        """Calculate vulnerability summary by severity."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for package in packages:
            for vulnerability in package.vulnerabilities:
                severity = vulnerability.severity.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        return severity_counts

    def _calculate_completeness(self, sbom_data: SBOMData) -> float:
        """Calculate SBOM completeness score (0-100)."""
        if not sbom_data.packages:
            return 0.0

        total_score = 0
        max_score = len(sbom_data.packages) * 100  # 100 points per package

        for package in sbom_data.packages:
            package_score = 0

            # Basic information (40 points)
            if package.name:
                package_score += 20
            if package.version:
                package_score += 20

            # Description (20 points)
            if package.description:
                package_score += 20

            # License information (20 points)
            if package.licenses:
                package_score += 20

            # Dependencies (10 points)
            if package.dependencies:
                package_score += 10

            # Additional metadata (10 points)
            if package.supplier or package.homepage or package.purl:
                package_score += 10

            total_score += package_score

        return (total_score / max_score) * 100

    def _generate_recommendations(
        self,
        total_packages: int,
        unique_licenses: list[str],
        dependency_depth: dict[str, int],
        vulnerability_summary: dict[str, int],
    ) -> list[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []

        if total_packages == 0:
            recommendations.append(
                "SBOM completeness is low. Consider adding missing package information."
            )
            return recommendations

        # License recommendations
        if len(unique_licenses) == 0:
            recommendations.append(
                "No license information found. Consider adding license details."
            )
        elif len(unique_licenses) > 10:
            recommendations.append(
                "High license diversity detected. Consider license compliance review."
            )

        # Dependency depth recommendations
        max_depth = max(dependency_depth.values()) if dependency_depth else 0
        if max_depth > 5:
            recommendations.append(
                "Deep dependency tree detected. Consider dependency optimization."
            )

        # Vulnerability recommendations
        total_vulnerabilities = sum(vulnerability_summary.values())
        if total_vulnerabilities > 0:
            if vulnerability_summary.get("critical", 0) > 0:
                recommendations.append(
                    "Critical vulnerabilities detected. Immediate action required."
                )
            elif vulnerability_summary.get("high", 0) > 5:
                recommendations.append(
                    "Multiple high-severity vulnerabilities. Review security posture."
                )

        return recommendations
