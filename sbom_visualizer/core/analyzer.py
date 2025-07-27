"""
SBOM Analyzer for comprehensive analysis of SBOM data.
"""

import logging
from collections import Counter, defaultdict
from typing import Dict, List

from ..models.sbom_models import AnalysisResult, SBOMData

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

        # Dependency analysis
        dependency_depth = self._analyze_dependencies(sbom_data)

        # Vulnerability analysis
        vulnerability_summary = self._analyze_vulnerabilities(sbom_data)

        # Completeness analysis
        completeness_score = self._calculate_completeness(sbom_data)

        # Generate recommendations
        recommendations = self._generate_recommendations(sbom_data, completeness_score)

        return AnalysisResult(
            total_packages=total_packages,
            unique_licenses=unique_licenses,
            license_distribution=license_distribution,
            dependency_depth=dependency_depth,
            vulnerability_summary=vulnerability_summary,
            completeness_score=completeness_score,
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

    def _analyze_dependencies(self, sbom_data: SBOMData) -> Dict[str, int]:
        """Analyze dependency depth for each package."""
        dependency_depth = {}

        # Build dependency graph
        dependency_graph = defaultdict(list)
        for package in sbom_data.packages:
            for dep in package.dependencies:
                dependency_graph[package.id].append(dep.package_id)

        # Calculate depth for each package
        for package in sbom_data.packages:
            depth = self._calculate_package_depth(package.id, dependency_graph)
            dependency_depth[package.name] = depth

        return dependency_depth

    def _calculate_package_depth(
        self, package_id: str, dependency_graph: Dict[str, List[str]]
    ) -> int:
        """Calculate the maximum depth of a package in the dependency tree."""
        visited = set()

        def dfs(node: str, depth: int) -> int:
            if node in visited:
                return depth
            visited.add(node)

            max_depth = depth
            for dep in dependency_graph.get(node, []):
                max_depth = max(max_depth, dfs(dep, depth + 1))

            return max_depth

        return dfs(package_id, 0)

    def _analyze_vulnerabilities(self, sbom_data: SBOMData) -> Dict[str, int]:
        """Analyze vulnerability distribution by severity."""
        vulnerability_counter = Counter()

        for package in sbom_data.packages:
            for vuln in package.vulnerabilities:
                severity = vuln.severity or "unknown"
                vulnerability_counter[severity] += 1

        return dict(vulnerability_counter)

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
        self, sbom_data: SBOMData, completeness_score: float
    ) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        # Completeness recommendations
        if completeness_score < 50:
            recommendations.append(
                "SBOM completeness is low. Consider adding missing package information."
            )
        elif completeness_score < 80:
            recommendations.append(
                "SBOM completeness is moderate. Consider adding more detailed package information."
            )

        # License recommendations
        packages_without_licenses = [
            p.name for p in sbom_data.packages if not p.licenses
        ]
        if packages_without_licenses:
            recommendations.append(
                f"Add license information for packages: {', '.join(packages_without_licenses[:5])}"
            )

        # Dependency recommendations
        packages_without_deps = [
            p.name
            for p in sbom_data.packages
            if not p.dependencies and len(sbom_data.packages) > 1
        ]
        if packages_without_deps:
            recommendations.append(
                f"Add dependency information for packages: {', '.join(packages_without_deps[:5])}"
            )

        # Version recommendations
        packages_without_version = [p.name for p in sbom_data.packages if not p.version]
        if packages_without_version:
            recommendations.append(
                f"Add version information for packages: {', '.join(packages_without_version[:5])}"
            )

        # Vulnerability recommendations
        total_vulnerabilities = sum(len(p.vulnerabilities) for p in sbom_data.packages)
        if total_vulnerabilities > 0:
            recommendations.append(
                f"Review {total_vulnerabilities} vulnerabilities found in the SBOM."
            )

        return recommendations
