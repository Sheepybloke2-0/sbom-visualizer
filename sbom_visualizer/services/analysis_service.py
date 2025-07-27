"""
Analysis service for SBOM data analysis.

Provides specialized analysis operations and insights.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any

from ..core.analyzer import SBOMAnalyzer
from ..core.dependency_viewer import DependencyViewer
from ..models.sbom_models import SBOMData, AnalysisResult, DependencyTree
from ..exceptions import SBOMAnalysisError


logger = logging.getLogger(__name__)


class AnalysisService:
    """Service for SBOM analysis operations."""

    def __init__(
        self, analyzer: SBOMAnalyzer = None, dependency_viewer: DependencyViewer = None
    ):
        """Initialize the analysis service."""
        self.analyzer = analyzer or SBOMAnalyzer()
        self.dependency_viewer = dependency_viewer or DependencyViewer()

    def analyze_sbom(self, sbom_data: SBOMData) -> AnalysisResult:
        """
        Perform comprehensive SBOM analysis.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Analysis result with statistics and recommendations
        """
        try:
            logger.info(f"Starting analysis of SBOM: {sbom_data.document_name}")
            result = self.analyzer.analyze(sbom_data)
            logger.info(
                f"Analysis completed: {result.total_packages} packages, "
                f"{len(result.unique_licenses)} licenses"
            )
            return result

        except Exception as e:
            raise SBOMAnalysisError(f"Analysis failed: {e}")

    def get_dependency_tree(self, sbom_data: SBOMData) -> DependencyTree:
        """
        Generate dependency tree analysis.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Dependency tree structure
        """
        try:
            logger.info(f"Generating dependency tree for: {sbom_data.document_name}")
            tree = self.dependency_viewer.generate_tree(sbom_data)
            logger.info(
                f"Dependency tree generated: {tree.total_dependencies} dependencies, "
                f"max depth: {tree.max_depth}"
            )
            return tree

        except Exception as e:
            raise SBOMAnalysisError(f"Dependency tree generation failed: {e}")

    def get_analysis_summary(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """
        Get a summary of SBOM analysis.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Summary dictionary with key metrics
        """
        try:
            analysis = self.analyze_sbom(sbom_data)
            tree = self.get_dependency_tree(sbom_data)

            summary = {
                "total_packages": analysis.total_packages,
                "unique_licenses": len(analysis.unique_licenses),
                "completeness_score": analysis.completeness_score,
                "total_dependencies": tree.total_dependencies,
                "max_depth": tree.max_depth,
                "circular_dependencies": len(tree.circular_dependencies),
                "vulnerability_count": sum(analysis.vulnerability_summary.values()),
                "recommendations_count": len(analysis.recommendations),
            }

            logger.info(f"Analysis summary generated for: {sbom_data.document_name}")
            return summary

        except Exception as e:
            raise SBOMAnalysisError(f"Failed to generate analysis summary: {e}")

    def get_license_analysis(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """
        Get detailed license analysis.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            License analysis dictionary
        """
        try:
            analysis = self.analyze_sbom(sbom_data)

            license_analysis = {
                "total_licenses": len(analysis.unique_licenses),
                "license_distribution": analysis.license_distribution,
                "packages_without_licenses": [],
                "license_recommendations": [],
            }

            # Find packages without licenses
            for package in sbom_data.packages:
                if not package.licenses:
                    license_analysis["packages_without_licenses"].append(package.name)

            # Generate license-specific recommendations
            if license_analysis["packages_without_licenses"]:
                license_analysis["license_recommendations"].append(
                    f"Add license information for {len(license_analysis['packages_without_licenses'])} packages"
                )

            logger.info(
                f"License analysis completed: {license_analysis['total_licenses']} unique licenses"
            )
            return license_analysis

        except Exception as e:
            raise SBOMAnalysisError(f"License analysis failed: {e}")

    def get_vulnerability_analysis(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """
        Get detailed vulnerability analysis.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Vulnerability analysis dictionary
        """
        try:
            analysis = self.analyze_sbom(sbom_data)

            vulnerability_analysis = {
                "total_vulnerabilities": sum(analysis.vulnerability_summary.values()),
                "vulnerability_summary": analysis.vulnerability_summary,
                "high_risk_count": analysis.vulnerability_summary.get("HIGH", 0),
                "medium_risk_count": analysis.vulnerability_summary.get("MEDIUM", 0),
                "low_risk_count": analysis.vulnerability_summary.get("LOW", 0),
                "vulnerability_recommendations": [],
            }

            # Generate vulnerability-specific recommendations
            total_vulns = vulnerability_analysis["total_vulnerabilities"]
            if total_vulns > 0:
                vulnerability_analysis["vulnerability_recommendations"].append(
                    f"Review {total_vulns} vulnerabilities found in the SBOM"
                )

                if vulnerability_analysis["high_risk_count"] > 0:
                    vulnerability_analysis["vulnerability_recommendations"].append(
                        f"Prioritize fixing {vulnerability_analysis['high_risk_count']} high-risk vulnerabilities"
                    )

            logger.info(
                f"Vulnerability analysis completed: {total_vulns} vulnerabilities found"
            )
            return vulnerability_analysis

        except Exception as e:
            raise SBOMAnalysisError(f"Vulnerability analysis failed: {e}")
