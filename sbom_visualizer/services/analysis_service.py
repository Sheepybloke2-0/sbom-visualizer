"""
Analysis service for SBOM data analysis.

Provides specialized analysis operations and insights.
"""

import logging
from typing import Any, Dict

from ..core.analyzer import SBOMAnalyzer
from ..core.dependency_viewer import DependencyViewer
from ..exceptions import SBOMAnalysisError
from ..models.sbom_models import AnalysisResult, DependencyTree, SBOMData

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
        """Analyze SBOM data and return analysis results."""
        try:
            return self.analyzer.analyze(sbom_data)
        except Exception as e:
            logger.error(f"Error analyzing SBOM: {e}")
            raise SBOMAnalysisError(f"Failed to analyze SBOM: {e}")

    def get_dependency_tree(self, sbom_data: SBOMData) -> DependencyTree:
        """Get dependency tree for SBOM data."""
        try:
            return self.dependency_viewer.build_dependency_tree(sbom_data)
        except Exception as e:
            logger.error(f"Error building dependency tree: {e}")
            raise SBOMAnalysisError(f"Failed to build dependency tree: {e}")

    def get_analysis_summary(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """Get a summary of SBOM analysis."""
        try:
            analysis_result = self.analyzer.analyze(sbom_data)
            dependency_tree = self.dependency_viewer.build_dependency_tree(sbom_data)

            return {
                "total_packages": analysis_result.total_packages,
                "unique_licenses": len(analysis_result.unique_licenses),
                "max_dependency_depth": (
                    max(dependency_tree.depth_analysis.values())
                    if dependency_tree.depth_analysis
                    else 0
                ),
                "root_packages": len(dependency_tree.root_packages),
                "circular_dependencies": len(dependency_tree.circular_dependencies),
                "vulnerabilities": sum(analysis_result.vulnerability_summary.values()),
                "recommendations": len(analysis_result.recommendations),
            }
        except Exception as e:
            logger.error(f"Error generating analysis summary: {e}")
            raise SBOMAnalysisError(f"Failed to generate analysis summary: {e}")

    def get_license_analysis(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """Get detailed license analysis."""
        try:
            analysis_result = self.analyzer.analyze(sbom_data)

            # Count licenses
            license_counts = {}
            for license_name in analysis_result.unique_licenses:
                license_counts[license_name] = sum(
                    1 for pkg in sbom_data.packages if license_name in pkg.licenses
                )

            return {
                "total_licenses": len(analysis_result.unique_licenses),
                "license_distribution": license_counts,
                "packages_without_licenses": sum(
                    1 for pkg in sbom_data.packages if not pkg.licenses
                ),
            }
        except Exception as e:
            logger.error(f"Error generating license analysis: {e}")
            raise SBOMAnalysisError(f"Failed to generate license analysis: {e}")

    def get_vulnerability_analysis(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """Get detailed vulnerability analysis."""
        try:
            analysis_result = self.analyzer.analyze(sbom_data)

            total_vulnerabilities = sum(analysis_result.vulnerability_summary.values())
            critical_vulns = analysis_result.vulnerability_summary.get("critical", 0)
            high_vulns = analysis_result.vulnerability_summary.get("high", 0)

            return {
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "vulnerability_summary": analysis_result.vulnerability_summary,
                "packages_with_vulnerabilities": sum(
                    1 for pkg in sbom_data.packages if pkg.vulnerabilities
                ),
            }
        except Exception as e:
            logger.error(f"Error generating vulnerability analysis: {e}")
            raise SBOMAnalysisError(f"Failed to generate vulnerability analysis: {e}")
